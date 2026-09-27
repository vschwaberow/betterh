// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! LDAP/LDAPS Simple Bind (RFC 4511) over Tokio with lightweight ASN.1 BER.

use std::time::Duration;

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use super::tls::{TransportStream, wrap_tls};
use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_ENUMERATED: u8 = 0x0A;
const TAG_BIND_REQUEST: u8 = 0x60; // APPLICATION 0
const TAG_BIND_RESPONSE: u8 = 0x61; // APPLICATION 1
const TAG_SIMPLE_AUTH: u8 = 0x80; // CONTEXT 0

const RESULT_SUCCESS: u32 = 0;
const RESULT_BUSY: u32 = 51;
const RESULT_UNWILLING: u32 = 53;
const RESULT_INVALID_CREDENTIALS: u32 = 49;

struct Disconnected;
struct Connected;

struct LdapClient<State> {
    stream: Option<TransportStream>,
    _state: State,
}

impl LdapClient<Disconnected> {
    const fn new() -> Self {
        Self {
            stream: None,
            _state: Disconnected,
        }
    }

    async fn connect(
        self,
        target: &Target,
        proxy: Option<&str>,
        insecure: bool,
    ) -> Result<LdapClient<Connected>, ProtocolError> {
        let tcp = super::io::dial(target, proxy).await?;

        // Implicit LDAPS: wrap before BindRequest.
        let transport = if target.ssl || target.port == 636 {
            wrap_tls(tcp, &target.host, insecure).await?
        } else {
            TransportStream::plain(tcp)
        };

        Ok(LdapClient {
            stream: Some(transport),
            _state: Connected,
        })
    }
}

impl LdapClient<Connected> {
    async fn bind(
        mut self,
        dn: &str,
        password: &str,
    ) -> Result<(AuthResult, LdapClient<Connected>), ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("LDAP stream missing before bind".into()))?;

        let request = encode_bind_request(1, dn, password);
        stream
            .write_all(&request)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

        let response = read_ldap_message(stream).await?;
        let result_code = parse_bind_response_code(&response)?;
        Ok((map_ldap_result(result_code), self))
    }

    async fn unbind(mut self) {
        if let Some(mut stream) = self.stream.take() {
            // UnbindRequest ::= [APPLICATION 2] NULL  → tag 0x42, length 0
            // LDAPMessage SEQUENCE { messageID INTEGER 2, unbind }
            let message_id = ber_tlv(TAG_INTEGER, &[0x02]);
            let unbind = ber_tlv(0x42, &[]);
            let mut body = Vec::new();
            body.extend_from_slice(&message_id);
            body.extend_from_slice(&unbind);
            let packet = ber_tlv(TAG_SEQUENCE, &body);
            let _ = stream.write_all(&packet).await;
            let _ = stream.flush().await;
        }
    }
}

fn ber_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![u8::try_from(len).unwrap_or(0)]
    } else if len < 0x100 {
        vec![0x81, u8::try_from(len).unwrap_or(0)]
    } else {
        vec![
            0x82,
            u8::try_from((len >> 8) & 0xff).unwrap_or(0),
            u8::try_from(len & 0xff).unwrap_or(0),
        ]
    }
}

fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len());
    out.push(tag);
    out.extend_from_slice(&ber_length(value.len()));
    out.extend_from_slice(value);
    out
}

fn encode_integer(value: u32) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    // Strip leading zeros, keep at least one byte; ensure high bit clear for positive.
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    ber_tlv(TAG_INTEGER, &bytes)
}

#[cfg(test)]
fn encode_enumerated(value: u32) -> Vec<u8> {
    let mut bytes = encode_integer(value);
    bytes[0] = TAG_ENUMERATED;
    bytes
}

fn encode_bind_request(message_id: u32, dn: &str, password: &str) -> Vec<u8> {
    let version = encode_integer(3);
    let name = ber_tlv(TAG_OCTET_STRING, dn.as_bytes());
    let auth = ber_tlv(TAG_SIMPLE_AUTH, password.as_bytes());

    let mut bind_body = Vec::new();
    bind_body.extend_from_slice(&version);
    bind_body.extend_from_slice(&name);
    bind_body.extend_from_slice(&auth);
    let bind_request = ber_tlv(TAG_BIND_REQUEST, &bind_body);

    let mut message_body = Vec::new();
    message_body.extend_from_slice(&encode_integer(message_id));
    message_body.extend_from_slice(&bind_request);
    ber_tlv(TAG_SEQUENCE, &message_body)
}

#[cfg(test)]
fn encode_bind_response(message_id: u32, result_code: u32) -> Vec<u8> {
    let mut result_body = Vec::new();
    result_body.extend_from_slice(&encode_enumerated(result_code));
    result_body.extend_from_slice(&ber_tlv(TAG_OCTET_STRING, b"")); // matchedDN
    result_body.extend_from_slice(&ber_tlv(TAG_OCTET_STRING, b"")); // diagnosticMessage
    let bind_response = ber_tlv(TAG_BIND_RESPONSE, &result_body);

    let mut message_body = Vec::new();
    message_body.extend_from_slice(&encode_integer(message_id));
    message_body.extend_from_slice(&bind_response);
    ber_tlv(TAG_SEQUENCE, &message_body)
}

async fn read_ldap_message(stream: &mut TransportStream) -> Result<Vec<u8>, ProtocolError> {
    let mut tag = [0u8; 1];
    stream
        .read_exact(&mut tag)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    if tag[0] != TAG_SEQUENCE {
        return Err(ProtocolError::HandshakeFailed(format!(
            "Expected LDAP SEQUENCE tag 0x30, got 0x{:02x}",
            tag[0]
        )));
    }

    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

    let (content_len, len_prefix) = if first[0] & 0x80 == 0 {
        (usize::from(first[0]), vec![first[0]])
    } else {
        let nbytes = usize::from(first[0] & 0x7f);
        if nbytes == 0 || nbytes > 4 {
            return Err(ProtocolError::HandshakeFailed(
                "Unsupported LDAP BER length encoding".into(),
            ));
        }
        let mut raw = vec![0u8; nbytes];
        stream
            .read_exact(&mut raw)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        let mut len = 0usize;
        for byte in &raw {
            len = (len << 8) | usize::from(*byte);
        }
        let mut prefix = vec![first[0]];
        prefix.extend_from_slice(&raw);
        (len, prefix)
    };

    let mut content = vec![0u8; content_len];
    if content_len > 0 {
        stream
            .read_exact(&mut content)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    }

    let mut full = Vec::with_capacity(1 + len_prefix.len() + content.len());
    full.push(tag[0]);
    full.extend_from_slice(&len_prefix);
    full.extend_from_slice(&content);
    Ok(full)
}

fn parse_ber_length(bytes: &[u8]) -> Result<(usize, usize), ProtocolError> {
    // returns (value_length, header_size including the length byte(s) after tag)
    if bytes.is_empty() {
        return Err(ProtocolError::HandshakeFailed(
            "Truncated BER length".into(),
        ));
    }
    if bytes[0] & 0x80 == 0 {
        return Ok((usize::from(bytes[0]), 1));
    }
    let nbytes = usize::from(bytes[0] & 0x7f);
    if nbytes == 0 || nbytes > 4 || bytes.len() < 1 + nbytes {
        return Err(ProtocolError::HandshakeFailed("Invalid BER length".into()));
    }
    let mut len = 0usize;
    for byte in &bytes[1..=nbytes] {
        len = (len << 8) | usize::from(*byte);
    }
    if len > 16 * 1024 {
        return Err(ProtocolError::HandshakeFailed(
            "BER length exceeds maximum".into(),
        ));
    }
    Ok((len, 1 + nbytes))
}

fn parse_tlv(bytes: &[u8]) -> Result<(u8, &[u8], usize), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::HandshakeFailed("Truncated BER TLV".into()));
    }
    let tag = bytes[0];
    let (len, len_size) = parse_ber_length(&bytes[1..])?;
    let header = 1 + len_size;
    let end = header + len;
    if bytes.len() < end {
        return Err(ProtocolError::HandshakeFailed("Truncated BER value".into()));
    }
    Ok((tag, &bytes[header..end], end))
}

fn parse_integer(value: &[u8]) -> Result<u32, ProtocolError> {
    if value.is_empty() || value.len() > 5 {
        return Err(ProtocolError::HandshakeFailed(
            "Invalid BER INTEGER width".into(),
        ));
    }
    let mut acc = 0u32;
    for byte in value {
        acc = (acc << 8) | u32::from(*byte);
    }
    Ok(acc)
}

fn parse_bind_response_code(message: &[u8]) -> Result<u32, ProtocolError> {
    let (tag, seq_body, _) = parse_tlv(message)?;
    if tag != TAG_SEQUENCE {
        return Err(ProtocolError::HandshakeFailed(
            "LDAPMessage is not a SEQUENCE".into(),
        ));
    }

    // messageID
    let (id_tag, id_value, offset) = parse_tlv(seq_body)?;
    if id_tag != TAG_INTEGER {
        return Err(ProtocolError::HandshakeFailed(
            "LDAPMessage missing messageID".into(),
        ));
    }
    let _message_id = parse_integer(id_value)?;

    let (op_tag, op_body, _) = parse_tlv(&seq_body[offset..])?;
    if op_tag != TAG_BIND_RESPONSE {
        return Err(ProtocolError::HandshakeFailed(format!(
            "Expected BindResponse (0x61), got 0x{op_tag:02x}"
        )));
    }

    let (code_tag, code_value, _) = parse_tlv(op_body)?;
    if code_tag != TAG_ENUMERATED && code_tag != TAG_INTEGER {
        return Err(ProtocolError::HandshakeFailed(
            "BindResponse missing resultCode".into(),
        ));
    }
    parse_integer(code_value)
}

fn map_ldap_result(code: u32) -> AuthResult {
    match code {
        RESULT_SUCCESS => AuthResult::Success,
        RESULT_INVALID_CREDENTIALS => AuthResult::Failure,
        RESULT_UNWILLING => AuthResult::LockedOut,
        RESULT_BUSY => AuthResult::RateLimited(Duration::from_secs(5)),
        other => AuthResult::Error(format!("LDAP resultCode {other}")),
    }
}

/// LDAP/LDAPS Simple Bind authentication module.
#[derive(Debug, Default, Clone)]
pub struct LdapModule {
    proxy: Option<String>,
    insecure: bool,
}

impl LdapModule {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            proxy: None,
            insecure: false,
        }
    }

    #[must_use]
    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = proxy;
        self
    }

    #[must_use]
    pub const fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }
}

#[async_trait]
impl ProtocolModule for LdapModule {
    fn name(&self) -> &'static str {
        "ldap"
    }

    fn default_port(&self) -> u16 {
        389
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_budget: Duration,
    ) -> Result<AuthResult, ProtocolError> {
        if timeout_budget.is_zero() {
            return Err(ProtocolError::Timeout);
        }
        let dn = credential.username.as_str();
        let password = credential.password.as_deref().unwrap_or("");

        let result = timeout(timeout_budget, async {
            let connected = LdapClient::new()
                .connect(target, self.proxy.as_deref(), self.insecure)
                .await?;
            let (outcome, client) = connected.bind(dn, password).await?;
            client.unbind().await;
            Ok::<AuthResult, ProtocolError>(outcome)
        })
        .await
        .map_err(|_| ProtocolError::Timeout)??;

        Ok(result)
    }
}

/// Fuzz entry: walk BER TLVs without panicking on adversarial lengths.
///
/// # Errors
///
/// Returns [`ProtocolError`] when a TLV is malformed or the walk stalls.
pub fn fuzz_walk_ber(mut bytes: &[u8]) -> Result<(), ProtocolError> {
    let mut steps = 0usize;
    while !bytes.is_empty() && steps < 256 {
        let (_tag, _value, consumed) = parse_tlv(bytes)?;
        if consumed == 0 || consumed > bytes.len() {
            return Err(ProtocolError::HandshakeFailed("BER walk stalled".into()));
        }
        bytes = &bytes[consumed..];
        steps += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    fn target(port: u16) -> Target {
        Target {
            host: "127.0.0.1".into(),
            port,
            ssl: false,
            path: None,
            ip: Some("127.0.0.1".parse().unwrap()),
        }
    }

    fn target_ssl(port: u16) -> Target {
        let mut t = target(port);
        t.ssl = true;
        t
    }

    fn test_server_config() -> Arc<ServerConfig> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .expect("generate self-signed cert");
        let cert_der = CertificateDer::from(certified.cert);
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config");
        Arc::new(config)
    }

    async fn read_client_message(socket: &mut (impl AsyncReadExt + Unpin)) -> Vec<u8> {
        // Reuse the same framing reader against a raw stream by temporarily
        // reading via TransportStream::plain through a helper on TcpStream.
        let mut tag = [0u8; 1];
        socket.read_exact(&mut tag).await.unwrap();
        assert_eq!(tag[0], TAG_SEQUENCE);
        let mut first = [0u8; 1];
        socket.read_exact(&mut first).await.unwrap();
        let (content_len, mut full) = if first[0] & 0x80 == 0 {
            (usize::from(first[0]), vec![tag[0], first[0]])
        } else {
            let nbytes = usize::from(first[0] & 0x7f);
            let mut raw = vec![0u8; nbytes];
            socket.read_exact(&mut raw).await.unwrap();
            let mut len = 0usize;
            for byte in &raw {
                len = (len << 8) | usize::from(*byte);
            }
            let mut prefix = vec![tag[0], first[0]];
            prefix.extend_from_slice(&raw);
            (len, prefix)
        };
        let mut content = vec![0u8; content_len];
        socket.read_exact(&mut content).await.unwrap();
        full.extend_from_slice(&content);
        full
    }

    fn assert_bind_request_contains(message: &[u8], dn: &str, password: &str) {
        let hay: &[u8] = message;
        assert!(hay.windows(dn.len()).any(|w| w == dn.as_bytes()));
        assert!(
            hay.windows(password.len())
                .any(|w| w == password.as_bytes())
        );
        assert!(hay.contains(&TAG_BIND_REQUEST));
        assert!(hay.contains(&TAG_SIMPLE_AUTH));
    }

    #[test]
    fn bind_response_result_codes_roundtrip() {
        for code in [0u32, 49, 51, 53] {
            let packet = encode_bind_response(1, code);
            assert_eq!(parse_bind_response_code(&packet).unwrap(), code);
        }
        assert_eq!(map_ldap_result(0), AuthResult::Success);
        assert_eq!(map_ldap_result(49), AuthResult::Failure);
        assert_eq!(map_ldap_result(53), AuthResult::LockedOut);
        assert_eq!(
            map_ldap_result(51),
            AuthResult::RateLimited(Duration::from_secs(5))
        );
    }

    #[tokio::test]
    async fn authenticates_simple_bind_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_client_message(&mut socket).await;
            assert_bind_request_contains(&request, "cn=alice,dc=example,dc=com", "secret");
            let response = encode_bind_response(1, RESULT_SUCCESS);
            socket.write_all(&response).await.unwrap();
            let _ = read_client_message(&mut socket).await; // unbind
        });

        let module = LdapModule::new();
        let credential = Credential {
            username: "cn=alice,dc=example,dc=com".into(),
            password: Some("secret".into()),
        };
        let result = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn authenticates_ldaps_simple_bind_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(test_server_config());

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(tcp).await.unwrap();
            let request = read_client_message(&mut socket).await;
            assert_bind_request_contains(&request, "alice@corp.local", "secret");
            socket
                .write_all(&encode_bind_response(1, RESULT_SUCCESS))
                .await
                .unwrap();
            let _ = read_client_message(&mut socket).await;
        });

        let module = LdapModule::new().with_insecure(true);
        let credential = Credential {
            username: "alice@corp.local".into(),
            password: Some("secret".into()),
        };
        let result = module
            .authenticate(&target_ssl(port), &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handles_invalid_credentials_49() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = read_client_message(&mut socket).await;
            socket
                .write_all(&encode_bind_response(1, RESULT_INVALID_CREDENTIALS))
                .await
                .unwrap();
            let _ = read_client_message(&mut socket).await;
        });

        let module = LdapModule::new();
        let credential = Credential {
            username: "cn=alice,dc=example,dc=com".into(),
            password: Some("wrong".into()),
        };
        let result = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Failure);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handles_busy_51_as_rate_limited() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = read_client_message(&mut socket).await;
            socket
                .write_all(&encode_bind_response(1, RESULT_BUSY))
                .await
                .unwrap();
            let _ = read_client_message(&mut socket).await;
        });

        let module = LdapModule::new();
        let credential = Credential {
            username: "cn=alice,dc=example,dc=com".into(),
            password: Some("secret".into()),
        };
        let result = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::RateLimited(Duration::from_secs(5)));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handles_unwilling_53_as_locked_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = read_client_message(&mut socket).await;
            socket
                .write_all(&encode_bind_response(1, RESULT_UNWILLING))
                .await
                .unwrap();
            let _ = read_client_message(&mut socket).await;
        });

        let module = LdapModule::new();
        let credential = Credential {
            username: "cn=alice,dc=example,dc=com".into(),
            password: Some("secret".into()),
        };
        let result = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::LockedOut);
        server.await.unwrap();
    }
}
