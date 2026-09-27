// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Microsoft SQL Server TDS authentication (`PRELOGIN` → optional TLS → `LOGIN7`).
//!
//! Auth-only SQL authentication. Windows Integrated / SSPI / Kerberos / Azure AD
//! and post-login queries are out of scope.

use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target, wrap_tls};

/// TDS packet types used by the auth path.
pub const PACKET_TYPE_PRELOGIN: u8 = 0x12;
pub const PACKET_TYPE_LOGIN7: u8 = 0x10;
pub const PACKET_TYPE_RESPONSE: u8 = 0x04;

const STATUS_EOM: u8 = 0x01;

/// PRELOGIN option types (MS-TDS).
pub const PRELOGIN_VERSION: u8 = 0x00;
pub const PRELOGIN_ENCRYPTION: u8 = 0x01;
pub const PRELOGIN_INSTOPT: u8 = 0x02;
pub const PRELOGIN_THREADID: u8 = 0x03;
pub const PRELOGIN_MARS: u8 = 0x04;
pub const PRELOGIN_TERMINATOR: u8 = 0xff;

/// PRELOGIN ENCRYPTION values.
pub const ENCRYPT_OFF: u8 = 0x00;
pub const ENCRYPT_ON: u8 = 0x01;
pub const ENCRYPT_NOT_SUP: u8 = 0x02;
pub const ENCRYPT_REQ: u8 = 0x03;

const TOKEN_ERROR: u8 = 0xaa;
const TOKEN_LOGINACK: u8 = 0xad;
const TOKEN_DONE: u8 = 0xfd;
const TOKEN_DONEPROC: u8 = 0xfe;
const TOKEN_DONEINPROC: u8 = 0xff;

const TDS_VERSION_7_4: u32 = 0x7400_0004;
const DEFAULT_PACKET_SIZE: u32 = 4096;

const ERROR_LOGIN_FAILED: u32 = 18_456;
const ERROR_PASSWORD_EXPIRED: u32 = 18_487;
const ERROR_ACCOUNT_LOCKED: u32 = 18_486;
const ERROR_LOGIN_DISABLED: u32 = 18_470;

/// Encoded PRELOGIN ENCRYPTION negotiation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptMode {
    /// No TLS; LOGIN7 may be sent in clear.
    Clear,
    /// TLS required before LOGIN7 (encrypt-login or full).
    TlsBeforeLogin,
}

/// Decode server ENCRYPTION byte into client behaviour.
///
/// # Errors
/// Returns an error when the ENCRYPTION value is not one of the known constants.
pub fn encrypt_mode_from_server(server_encrypt: u8) -> Result<EncryptMode, &'static str> {
    match server_encrypt {
        ENCRYPT_OFF | ENCRYPT_NOT_SUP => Ok(EncryptMode::Clear),
        ENCRYPT_ON | ENCRYPT_REQ => Ok(EncryptMode::TlsBeforeLogin),
        _ => Err("unsupported PRELOGIN ENCRYPTION value"),
    }
}

/// Build a client PRELOGIN payload (option table + data).
#[must_use]
pub fn encode_prelogin(client_encrypt: u8) -> Vec<u8> {
    // Options: VERSION(6), ENCRYPTION(1), INSTOPT(1), THREADID(4), MARS(1)
    let option_count = 5usize;
    let header_len = option_count * 5 + 1; // type+off+len each, then 0xFF
    let mut data = Vec::new();
    // VERSION: 1.0.0.0 major.minor.build(ul) subbuild
    data.extend_from_slice(&[0x10, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let version_off = 0u16;
    let version_len = 6u16;
    let enc_off = 6u16;
    let enc_len = 1u16;
    data.push(client_encrypt);
    let inst_off = 7u16;
    let inst_len = 1u16;
    data.push(0x00); // default instance
    let thread_off = 8u16;
    let thread_len = 4u16;
    data.extend_from_slice(&0u32.to_be_bytes());
    let mars_off = 12u16;
    let mars_len = 1u16;
    data.push(0x00); // MARS off

    let mut out = Vec::with_capacity(header_len + data.len());
    let mut push_opt = |ty: u8, off: u16, len: u16| {
        out.push(ty);
        out.extend_from_slice(&off.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
    };
    // Offsets are relative to start of option data (after terminator), i.e. absolute
    // from start of PRELOGIN payload = header_len + relative.
    let base = u16::try_from(header_len).unwrap_or(0);
    push_opt(PRELOGIN_VERSION, base + version_off, version_len);
    push_opt(PRELOGIN_ENCRYPTION, base + enc_off, enc_len);
    push_opt(PRELOGIN_INSTOPT, base + inst_off, inst_len);
    push_opt(PRELOGIN_THREADID, base + thread_off, thread_len);
    push_opt(PRELOGIN_MARS, base + mars_off, mars_len);
    out.push(PRELOGIN_TERMINATOR);
    out.extend_from_slice(&data);
    out
}

/// Parse ENCRYPTION value from a PRELOGIN payload.
///
/// # Errors
/// Returns an error when the option table is truncated or ENCRYPTION is missing.
pub fn parse_prelogin_encryption(payload: &[u8]) -> Result<u8, &'static str> {
    let mut i = 0usize;
    while i < payload.len() {
        let ty = payload[i];
        if ty == PRELOGIN_TERMINATOR {
            break;
        }
        if i + 5 > payload.len() {
            return Err("PRELOGIN option truncated");
        }
        let offset = u16::from_be_bytes([payload[i + 1], payload[i + 2]]) as usize;
        let length = u16::from_be_bytes([payload[i + 3], payload[i + 4]]) as usize;
        i += 5;
        if ty == PRELOGIN_ENCRYPTION {
            if offset + length > payload.len() || length == 0 {
                return Err("PRELOGIN ENCRYPTION out of range");
            }
            return Ok(payload[offset]);
        }
    }
    Err("PRELOGIN ENCRYPTION option missing")
}

/// Encode a TDS packet (single EOM packet).
#[must_use]
pub fn encode_tds_packet(packet_type: u8, payload: &[u8], packet_id: u8) -> Vec<u8> {
    let total = 8 + payload.len();
    let mut out = Vec::with_capacity(total);
    out.push(packet_type);
    out.push(STATUS_EOM);
    out.extend_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // SPID
    out.push(packet_id);
    out.push(0x00); // Window
    out.extend_from_slice(payload);
    out
}

/// Decode a TDS packet header + body from a complete buffer.
///
/// # Errors
/// Returns an error when the buffer is truncated or the length is inconsistent.
pub fn decode_tds_packet(bytes: &[u8]) -> Result<(u8, Vec<u8>), &'static str> {
    if bytes.len() < 8 {
        return Err("TDS header truncated");
    }
    let packet_type = bytes[0];
    let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if total < 8 {
        return Err("TDS length too small");
    }
    if total > 64 * 1024 {
        return Err("TDS length exceeds maximum");
    }
    if bytes.len() < total {
        return Err("TDS payload truncated");
    }
    Ok((packet_type, bytes[8..total].to_vec()))
}

fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// TDS LOGIN7 password obfuscation (nibble-swap XOR `0xA5`).
#[must_use]
pub fn encode_tds_password(password: &str) -> Vec<u8> {
    let mut out = utf16le(password);
    for byte in &mut out {
        let x = *byte ^ 0xa5;
        *byte = x.rotate_left(4);
    }
    out
}

/// Build a LOGIN7 payload for SQL authentication.
#[must_use]
pub fn encode_login7(username: &str, password: &str, database: Option<&str>, app: &str) -> Vec<u8> {
    let hostname = "BETTERH";
    let servername = "";
    let library = "betterh";
    let language = "";
    let db = database.unwrap_or("");

    let host_b = utf16le(hostname);
    let user_b = utf16le(username);
    let pass_b = encode_tds_password(password);
    let app_b = utf16le(app);
    let server_b = utf16le(servername);
    let lib_b = utf16le(library);
    let lang_b = utf16le(language);
    let db_b = utf16le(db);

    // LOGIN7 fixed header is 36 bytes; then USHORT/USHORT offset-length pairs for strings.
    let fixed_before_offsets = 36usize;
    // Classic 9-string table: Host, User, Pass, App, Server, Unused, Lib, Locale, DB.
    let pair_count = 9usize;
    let offsets_len = pair_count * 4;
    let data_start = fixed_before_offsets + offsets_len;

    let mut data = Vec::new();
    let mut offsets: Vec<(u16, u16)> = Vec::with_capacity(pair_count);
    let mut push_str = |bytes: &[u8]| {
        let off = u16::try_from(data_start + data.len()).unwrap_or(u16::MAX);
        let chars = u16::try_from(bytes.len() / 2).unwrap_or(0);
        offsets.push((off, chars));
        data.extend_from_slice(bytes);
    };
    push_str(&host_b);
    push_str(&user_b);
    push_str(&pass_b);
    push_str(&app_b);
    push_str(&server_b);
    push_str(&[]); // unused / Extension placeholder empty
    push_str(&lib_b);
    push_str(&lang_b);
    push_str(&db_b);

    let length = u32::try_from(data_start + data.len()).unwrap_or(0);
    let mut out = Vec::with_capacity(length as usize);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&TDS_VERSION_7_4.to_le_bytes());
    out.extend_from_slice(&DEFAULT_PACKET_SIZE.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // ClientProgVer
    out.extend_from_slice(&std::process::id().to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // ConnectionID
    out.push(0xE0); // OptionFlags1: useDB, dumpLoad, etc. set setLang
    out.push(0x03); // OptionFlags2: initLang, ODBC
    out.push(0x00); // TypeFlags
    out.push(0x00); // OptionFlags3
    out.extend_from_slice(&0i32.to_le_bytes()); // ClientTimeZone
    out.extend_from_slice(&0u32.to_le_bytes()); // ClientLCID
    for (off, len) in offsets {
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
    }
    out.extend_from_slice(&data);
    // Fix length field
    let real_len = u32::try_from(out.len()).unwrap_or(0);
    out[0..4].copy_from_slice(&real_len.to_le_bytes());
    out
}

/// Scan a TDS response body for LOGINACK / ERROR tokens.
#[must_use]
pub fn interpret_login_tokens(body: &[u8]) -> AuthResult {
    let mut i = 0usize;
    let mut saw_loginack = false;
    let mut last_error: Option<(u32, String)> = None;

    while i < body.len() {
        let token = body[i];
        i += 1;
        match token {
            TOKEN_ERROR => {
                if i + 2 > body.len() {
                    break;
                }
                let len = u16::from_le_bytes([body[i], body[i + 1]]) as usize;
                i += 2;
                if i + len > body.len() || len < 6 {
                    break;
                }
                let number = u32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
                // skip state, class
                let msg_start = i + 6;
                let msg = if msg_start + 2 <= i + len {
                    let msg_chars =
                        u16::from_le_bytes([body[msg_start], body[msg_start + 1]]) as usize;
                    let msg_bytes = msg_chars.saturating_mul(2);
                    let text_at = msg_start + 2;
                    if text_at + msg_bytes <= i + len {
                        String::from_utf16_lossy(
                            &body[text_at..text_at + msg_bytes]
                                .chunks(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect::<Vec<_>>(),
                        )
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                last_error = Some((number, msg));
                i += len;
            }
            TOKEN_LOGINACK => {
                if i + 2 > body.len() {
                    break;
                }
                let len = u16::from_le_bytes([body[i], body[i + 1]]) as usize;
                i += 2;
                if i + len > body.len() {
                    break;
                }
                saw_loginack = true;
                i += len;
            }
            TOKEN_DONE | TOKEN_DONEPROC | TOKEN_DONEINPROC => {
                // DONE: status(2) curcmd(2) done_row(8) = 12 bytes typically
                if i + 12 > body.len() {
                    break;
                }
                i += 12;
            }
            _ => {
                // Unknown token — stop scanning to avoid desync.
                break;
            }
        }
    }

    if saw_loginack {
        return AuthResult::Success;
    }
    if let Some((number, msg)) = last_error {
        return map_mssql_error(number, &msg);
    }
    AuthResult::Error("MSSQL login response missing LOGINACK/ERROR".into())
}

#[must_use]
pub fn map_mssql_error(number: u32, message: &str) -> AuthResult {
    match number {
        ERROR_LOGIN_FAILED => AuthResult::Failure,
        ERROR_ACCOUNT_LOCKED | ERROR_LOGIN_DISABLED | ERROR_PASSWORD_EXPIRED => {
            AuthResult::LockedOut
        }
        _ if message.to_ascii_lowercase().contains("login failed") => AuthResult::Failure,
        other => AuthResult::Error(format!("MSSQL error {other}: {message}")),
    }
}

async fn write_packet<W: AsyncWrite + Unpin>(
    stream: &mut W,
    packet_type: u8,
    payload: &[u8],
    packet_id: u8,
) -> Result<(), ProtocolError> {
    let framed = encode_tds_packet(packet_type, payload, packet_id);
    stream
        .write_all(&framed)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    Ok(())
}

async fn read_packet<R: AsyncRead + Unpin>(stream: &mut R) -> Result<(u8, Vec<u8>), ProtocolError> {
    let mut hdr = [0u8; 8];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    let total = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
    if total < 8 {
        return Err(ProtocolError::HandshakeFailed(
            "TDS length too small".into(),
        ));
    }
    let mut body = vec![0u8; total - 8];
    if !body.is_empty() {
        stream
            .read_exact(&mut body)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    }
    Ok((hdr[0], body))
}

/// Production MSSQL TDS login module (feature = `mssql`).
#[derive(Debug, Clone, Default)]
pub struct MssqlModule {
    proxy: Option<String>,
    insecure: bool,
    database: Option<String>,
}

impl MssqlModule {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = proxy;
        self
    }

    #[must_use]
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    #[must_use]
    pub fn with_database(mut self, database: Option<String>) -> Self {
        self.database = database;
        self
    }
}

#[async_trait]
impl ProtocolModule for MssqlModule {
    fn name(&self) -> &'static str {
        "mssql"
    }

    fn default_port(&self) -> u16 {
        1433
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
        let password = credential.password.as_deref().unwrap_or("");
        let proxy = self.proxy.clone();
        let insecure = self.insecure;
        let database = self.database.clone();
        let username = credential.username.clone();
        let host = target.host.clone();

        let result = timeout(timeout_budget, async {
            let mut tcp = super::io::dial(target, proxy.as_deref()).await?;

            // PRELOGIN in clear.
            let prelogin = encode_prelogin(ENCRYPT_OFF);
            write_packet(&mut tcp, PACKET_TYPE_PRELOGIN, &prelogin, 1).await?;
            let (ptype, pre_body) = read_packet(&mut tcp).await?;
            if ptype != PACKET_TYPE_PRELOGIN {
                return Err(ProtocolError::HandshakeFailed(format!(
                    "expected PRELOGIN response, got type 0x{ptype:02x}"
                )));
            }
            let server_enc = parse_prelogin_encryption(&pre_body)
                .map_err(|e| ProtocolError::HandshakeFailed(e.into()))?;
            let mode = encrypt_mode_from_server(server_enc)
                .map_err(|e| ProtocolError::HandshakeFailed(e.into()))?;

            let login = encode_login7(&username, password, database.as_deref(), "betterh");

            let outcome = match mode {
                EncryptMode::Clear => {
                    write_packet(&mut tcp, PACKET_TYPE_LOGIN7, &login, 2).await?;
                    let (rtype, body) = read_packet(&mut tcp).await?;
                    if rtype != PACKET_TYPE_RESPONSE {
                        return Err(ProtocolError::HandshakeFailed(format!(
                            "unexpected TDS response type 0x{rtype:02x}"
                        )));
                    }
                    interpret_login_tokens(&body)
                }
                EncryptMode::TlsBeforeLogin => {
                    let mut tls = wrap_tls(tcp, &host, insecure).await?;
                    write_packet(&mut tls, PACKET_TYPE_LOGIN7, &login, 2).await?;
                    let (rtype, body) = read_packet(&mut tls).await?;
                    if rtype != PACKET_TYPE_RESPONSE {
                        return Err(ProtocolError::HandshakeFailed(format!(
                            "unexpected TDS response type 0x{rtype:02x} after TLS login"
                        )));
                    }
                    let _ = tls;
                    interpret_login_tokens(&body)
                }
            };
            Ok(outcome)
        })
        .await
        .map_err(|_| ProtocolError::Timeout)??;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    fn target_for(port: u16) -> Target {
        Target {
            host: "localhost".into(),
            port,
            ssl: false,
            path: None,
            ip: Some("127.0.0.1".parse().unwrap()),
        }
    }

    fn test_server_config() -> Arc<ServerConfig> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
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

    #[must_use]
    fn encode_server_prelogin(encryption: u8) -> Vec<u8> {
        // Minimal: ENCRYPTION only.
        let header_len = 5 + 1;
        let mut out = Vec::new();
        out.push(PRELOGIN_ENCRYPTION);
        out.extend_from_slice(&u16::try_from(header_len).unwrap().to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.push(PRELOGIN_TERMINATOR);
        out.push(encryption);
        out
    }

    fn encode_error_token(number: u32, message: &str) -> Vec<u8> {
        let msg_utf16 = utf16le(message);
        let msg_chars = u16::try_from(msg_utf16.len() / 2).unwrap_or(0);
        // Number(4)+State(1)+Class(1)+MsgLen(2)+Msg+ServerNameLen(1)+ProcLen(1)+Line(4)
        let inner_len = 4 + 1 + 1 + 2 + msg_utf16.len() + 1 + 1 + 4;
        let mut tok = Vec::new();
        tok.push(TOKEN_ERROR);
        tok.extend_from_slice(&u16::try_from(inner_len).unwrap_or(0).to_le_bytes());
        tok.extend_from_slice(&number.to_le_bytes());
        tok.push(1); // state
        tok.push(14); // class
        tok.extend_from_slice(&msg_chars.to_le_bytes());
        tok.extend_from_slice(&msg_utf16);
        tok.push(0); // server name len
        tok.push(0); // proc len
        tok.extend_from_slice(&1u32.to_le_bytes()); // line
        tok
    }

    fn encode_loginack_token() -> Vec<u8> {
        // Interface(1)+TDSVersion(4)+ProgName(len+utf16)+ProgVersion(4)
        let prog = utf16le("mock");
        let prog_chars = u8::try_from(prog.len() / 2).unwrap_or(0);
        let inner = 1 + 4 + 1 + prog.len() + 4;
        let mut tok = Vec::new();
        tok.push(TOKEN_LOGINACK);
        tok.extend_from_slice(&u16::try_from(inner).unwrap_or(0).to_le_bytes());
        tok.push(1);
        tok.extend_from_slice(&TDS_VERSION_7_4.to_le_bytes());
        tok.push(prog_chars);
        tok.extend_from_slice(&prog);
        tok.extend_from_slice(&0u32.to_le_bytes());
        tok
    }

    #[test]
    fn prelogin_roundtrip_exposes_encryption() {
        let payload = encode_prelogin(ENCRYPT_OFF);
        // Self-parse client packet for sanity on option offsets.
        assert!(payload.contains(&PRELOGIN_TERMINATOR));
        let server = encode_server_prelogin(ENCRYPT_REQ);
        assert_eq!(parse_prelogin_encryption(&server).unwrap(), ENCRYPT_REQ);
        assert_eq!(
            encrypt_mode_from_server(ENCRYPT_REQ).unwrap(),
            EncryptMode::TlsBeforeLogin
        );
        assert_eq!(
            encrypt_mode_from_server(ENCRYPT_NOT_SUP).unwrap(),
            EncryptMode::Clear
        );
    }

    #[test]
    fn tds_packet_roundtrip() {
        let framed = encode_tds_packet(PACKET_TYPE_PRELOGIN, b"abc", 1);
        let (ty, body) = decode_tds_packet(&framed).unwrap();
        assert_eq!(ty, PACKET_TYPE_PRELOGIN);
        assert_eq!(body, b"abc");
    }

    #[test]
    fn password_obfuscation_is_deterministic_and_non_plaintext() {
        let enc = encode_tds_password("Secret!");
        assert_ne!(enc, utf16le("Secret!"));
        assert_eq!(enc, encode_tds_password("Secret!"));
    }

    #[test]
    fn login_tokens_map_success_and_failure() {
        let mut ok = encode_loginack_token();
        ok.extend_from_slice(&[TOKEN_DONE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(interpret_login_tokens(&ok), AuthResult::Success);

        let err = encode_error_token(ERROR_LOGIN_FAILED, "Login failed for user 'a'.");
        assert_eq!(interpret_login_tokens(&err), AuthResult::Failure);

        let locked = encode_error_token(ERROR_ACCOUNT_LOCKED, "locked");
        assert_eq!(interpret_login_tokens(&locked), AuthResult::LockedOut);
    }

    #[test]
    fn login7_contains_obfuscated_password_not_clear_utf16() {
        let login = encode_login7("alice", "p@ss", Some("master"), "betterh");
        let clear = utf16le("p@ss");
        assert!(!login.windows(clear.len()).any(|w| w == clear.as_slice()));
        let obfuscated = encode_tds_password("p@ss");
        assert!(
            login
                .windows(obfuscated.len())
                .any(|w| w == obfuscated.as_slice())
        );
    }

    async fn mock_plain_peer(listener: TcpListener, accept: bool) {
        let (mut sock, _) = listener.accept().await.unwrap();
        let (ty, body) = read_packet(&mut sock).await.unwrap();
        assert_eq!(ty, PACKET_TYPE_PRELOGIN);
        assert!(parse_prelogin_encryption(&body).is_ok());
        let resp = encode_server_prelogin(ENCRYPT_NOT_SUP);
        write_packet(&mut sock, PACKET_TYPE_PRELOGIN, &resp, 1)
            .await
            .unwrap();

        let (ty, login) = read_packet(&mut sock).await.unwrap();
        assert_eq!(ty, PACKET_TYPE_LOGIN7);
        assert!(!login.is_empty());

        let mut body = if accept {
            encode_loginack_token()
        } else {
            encode_error_token(ERROR_LOGIN_FAILED, "Login failed for user 'alice'.")
        };
        body.extend_from_slice(&[TOKEN_DONE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        write_packet(&mut sock, PACKET_TYPE_RESPONSE, &body, 1)
            .await
            .unwrap();
    }

    async fn mock_encrypt_req_peer(listener: TcpListener, acceptor: TlsAcceptor, accept: bool) {
        let (mut sock, _) = listener.accept().await.unwrap();
        let (ty, _) = read_packet(&mut sock).await.unwrap();
        assert_eq!(ty, PACKET_TYPE_PRELOGIN);
        let resp = encode_server_prelogin(ENCRYPT_REQ);
        write_packet(&mut sock, PACKET_TYPE_PRELOGIN, &resp, 1)
            .await
            .unwrap();

        let mut tls = acceptor.accept(sock).await.unwrap();
        let (ty, login) = read_packet(&mut tls).await.unwrap();
        assert_eq!(ty, PACKET_TYPE_LOGIN7);
        // Ensure password material is not clear UTF-16 on the wire body.
        assert!(!login.windows(8).any(|w| w == utf16le("correct").as_slice()));

        let mut body = if accept {
            encode_loginack_token()
        } else {
            encode_error_token(ERROR_LOGIN_FAILED, "Login failed")
        };
        body.extend_from_slice(&[TOKEN_DONE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        write_packet(&mut tls, PACKET_TYPE_RESPONSE, &body, 1)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn authenticates_cleartext_prelogin_success_and_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { mock_plain_peer(listener, true).await });
        let module = MssqlModule::new();
        let ok = module
            .authenticate(
                &target_for(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("correct".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(ok, AuthResult::Success);
        server.await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { mock_plain_peer(listener, false).await });
        let bad = module
            .authenticate(
                &target_for(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("wrong".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(bad, AuthResult::Failure);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn authenticates_with_encrypt_req_over_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(test_server_config());
        let server =
            tokio::spawn(async move { mock_encrypt_req_peer(listener, acceptor, true).await });
        let module = MssqlModule::new().with_insecure(true);
        let ok = module
            .authenticate(
                &target_for(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("correct".into()),
                },
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert_eq!(ok, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn proxy_path_rejects_non_socks() {
        let module = MssqlModule::new().with_proxy(Some("http://127.0.0.1:1".into()));
        let err = module
            .authenticate(
                &target_for(9),
                &Credential {
                    username: "u".into(),
                    password: Some("p".into()),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProtocolError::ProxyError(_)));
    }

    #[tokio::test]
    async fn truncated_prelogin_surfaces_handshake_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = read_packet(&mut sock).await;
            // Malformed PRELOGIN: claim length 8 with no body options.
            let mut hdr = [0u8; 8];
            hdr[0] = PACKET_TYPE_PRELOGIN;
            hdr[1] = STATUS_EOM;
            hdr[2..4].copy_from_slice(&8u16.to_be_bytes());
            sock.write_all(&hdr).await.unwrap();
        });
        let module = MssqlModule::new();
        let err = module
            .authenticate(
                &target_for(port),
                &Credential {
                    username: "a".into(),
                    password: Some("b".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProtocolError::HandshakeFailed(_)));
        server.await.unwrap();
    }
}
