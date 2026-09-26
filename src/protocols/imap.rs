// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! IMAP/IMAPS authentication (RFC 3501) over Tokio with optional STARTTLS.

use std::time::Duration;

use async_trait::async_trait;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

use super::tls::{TransportStream, wrap_tls};
use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

struct Disconnected;
struct Connected {
    host: String,
    insecure: bool,
    already_tls: bool,
}
struct Ready;

struct ImapClient<State> {
    stream: Option<BufReader<TransportStream>>,
    state: State,
}

impl ImapClient<Disconnected> {
    const fn new() -> Self {
        Self {
            stream: None,
            state: Disconnected,
        }
    }

    async fn connect(
        self,
        target: &Target,
        proxy: Option<&str>,
        insecure: bool,
    ) -> Result<ImapClient<Connected>, ProtocolError> {
        let addr = target.dial_addr();
        let tcp = match proxy {
            None => TcpStream::connect(&addr)
                .await
                .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?,
            Some(proxy) => super::socks::connect_socks5(proxy, &addr).await?,
        };

        // Implicit IMAPS: wrap before reading the greeting.
        let (transport, already_tls) = if target.ssl || target.port == 993 {
            (wrap_tls(tcp, &target.host, insecure).await?, true)
        } else {
            (TransportStream::plain(tcp), false)
        };

        Ok(ImapClient {
            stream: Some(BufReader::new(transport)),
            state: Connected {
                host: target.host.clone(),
                insecure,
                already_tls,
            },
        })
    }
}

impl ImapClient<Connected> {
    async fn greet_and_maybe_starttls(mut self) -> Result<ImapClient<Ready>, ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("IMAP stream missing after connect".into()))?;

        // 1. Greeting: expect `* OK` (or treat `* BYE` as rate-limit).
        let greeting = read_line(stream).await?;
        if map_bye(&greeting).is_some() {
            return Err(ProtocolError::HandshakeFailed(
                "IMAP greeting closed the session with BYE".into(),
            ));
        }
        if !is_untagged_ok(&greeting) {
            return Err(ProtocolError::HandshakeFailed(format!(
                "Unexpected IMAP greeting: {}",
                normalize(&greeting)
            )));
        }

        let offers_starttls = greeting.to_ascii_uppercase().contains("STARTTLS");
        let wants_starttls = !self.state.already_tls
            && (offers_starttls || {
                // CAPABILITY probe when greeting omits the list (hermetic plain mocks).
                write_line(stream, "C01 CAPABILITY").await?;
                let caps = read_until_tagged(stream, "C01").await?;
                match caps {
                    TaggedOutcome::Bye => {
                        return Err(ProtocolError::HandshakeFailed(
                            "IMAP CAPABILITY ended with BYE".into(),
                        ));
                    }
                    TaggedOutcome::Ok { untagged } => untagged
                        .iter()
                        .any(|line| line.to_ascii_uppercase().contains("STARTTLS")),
                    TaggedOutcome::No | TaggedOutcome::Bad => false,
                }
            });

        if wants_starttls {
            self.upgrade_starttls().await?;
        }

        Ok(ImapClient {
            stream: self.stream.take(),
            state: Ready,
        })
    }

    async fn upgrade_starttls(&mut self) -> Result<(), ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("IMAP stream missing before STARTTLS".into()))?;

        write_line(stream, "A001 STARTTLS").await?;
        match read_until_tagged(stream, "A001").await? {
            TaggedOutcome::Ok { .. } => {}
            TaggedOutcome::No | TaggedOutcome::Bad => {
                return Err(ProtocolError::HandshakeFailed(
                    "IMAP STARTTLS rejected".into(),
                ));
            }
            TaggedOutcome::Bye => {
                return Err(ProtocolError::HandshakeFailed(
                    "IMAP STARTTLS ended with BYE".into(),
                ));
            }
        }

        let buffered = self.stream.take().ok_or_else(|| {
            ProtocolError::Internal("IMAP stream missing during STARTTLS upgrade".into())
        })?;
        let inner = buffered.into_inner();
        let TransportStream::Plain(tcp) = inner else {
            return Err(ProtocolError::Internal(
                "STARTTLS requested on an already-TLS stream".into(),
            ));
        };
        let upgraded = wrap_tls(tcp, &self.state.host, self.state.insecure).await?;
        self.stream = Some(BufReader::new(upgraded));
        self.state.already_tls = true;
        Ok(())
    }
}

impl ImapClient<Ready> {
    async fn login(
        mut self,
        username: &str,
        password: &str,
    ) -> Result<(AuthResult, ImapClient<Ready>), ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("IMAP stream missing before LOGIN".into()))?;

        let command = format!(
            "A002 LOGIN {} {}",
            quote_imap(username),
            quote_imap(password)
        );
        write_line(stream, &command).await?;
        let outcome = read_until_tagged(stream, "A002").await?;
        let result = match outcome {
            TaggedOutcome::Ok { .. } => AuthResult::Success,
            TaggedOutcome::No => AuthResult::Failure,
            TaggedOutcome::Bad => AuthResult::Error("IMAP LOGIN returned BAD".into()),
            TaggedOutcome::Bye => AuthResult::RateLimited(Duration::from_secs(5)),
        };
        Ok((result, self))
    }

    async fn logout(mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = write_line(&mut stream, "A003 LOGOUT").await;
            // Drain until tagged LOGOUT or peer close; ignore errors on teardown.
            let _ = read_until_tagged(&mut stream, "A003").await;
        }
    }
}

#[derive(Debug)]
enum TaggedOutcome {
    Ok { untagged: Vec<String> },
    No,
    Bad,
    Bye,
}

fn normalize(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

fn is_untagged_ok(line: &str) -> bool {
    let n = normalize(line);
    n.starts_with("* OK") || n.starts_with("* ok")
}

fn map_bye(line: &str) -> Option<AuthResult> {
    let n = normalize(line);
    if n.to_ascii_uppercase().starts_with("* BYE") {
        Some(AuthResult::RateLimited(Duration::from_secs(5)))
    } else {
        None
    }
}

fn quote_imap(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        if ch == '\\' || ch == '"' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

async fn write_line(
    stream: &mut BufReader<TransportStream>,
    line: &str,
) -> Result<(), ProtocolError> {
    stream
        .write_all(line.as_bytes())
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    stream
        .write_all(b"\r\n")
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    Ok(())
}

async fn read_line(stream: &mut BufReader<TransportStream>) -> Result<String, ProtocolError> {
    let mut line = String::new();
    let n = stream
        .read_line(&mut line)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    if n == 0 {
        return Err(ProtocolError::ConnectionError(
            "IMAP peer closed the connection".into(),
        ));
    }
    Ok(line)
}

async fn read_until_tagged(
    stream: &mut BufReader<TransportStream>,
    tag: &str,
) -> Result<TaggedOutcome, ProtocolError> {
    let mut untagged = Vec::new();
    let ok_prefix = format!("{tag} OK");
    let no_prefix = format!("{tag} NO");
    let bad_prefix = format!("{tag} BAD");
    loop {
        let line = read_line(stream).await?;
        if map_bye(&line).is_some() {
            return Ok(TaggedOutcome::Bye);
        }
        let normalized = normalize(&line);
        if normalized.starts_with(&ok_prefix)
            || normalized
                .to_ascii_uppercase()
                .starts_with(&ok_prefix.to_ascii_uppercase())
        {
            return Ok(TaggedOutcome::Ok { untagged });
        }
        if normalized.starts_with(&no_prefix)
            || normalized
                .to_ascii_uppercase()
                .starts_with(&no_prefix.to_ascii_uppercase())
        {
            return Ok(TaggedOutcome::No);
        }
        if normalized.starts_with(&bad_prefix)
            || normalized
                .to_ascii_uppercase()
                .starts_with(&bad_prefix.to_ascii_uppercase())
        {
            return Ok(TaggedOutcome::Bad);
        }
        if normalized.starts_with('*') {
            untagged.push(normalized.to_owned());
            continue;
        }
        return Err(ProtocolError::HandshakeFailed(format!(
            "Unexpected IMAP response while waiting for {tag}: {normalized}"
        )));
    }
}

/// IMAP/IMAPS authentication module.
#[derive(Debug, Default, Clone)]
pub struct ImapModule {
    proxy: Option<String>,
    insecure: bool,
}

impl ImapModule {
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
impl ProtocolModule for ImapModule {
    fn name(&self) -> &'static str {
        "imap"
    }

    fn default_port(&self) -> u16 {
        143
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
        let username = credential.username.as_str();
        let password = credential.password.as_deref().unwrap_or("");

        let result = timeout(timeout_budget, async {
            let connected = ImapClient::new()
                .connect(target, self.proxy.as_deref(), self.insecure)
                .await?;
            let ready = connected.greet_and_maybe_starttls().await?;
            let (outcome, client) = ready.login(username, password).await?;
            client.logout().await;
            Ok::<AuthResult, ProtocolError>(outcome)
        })
        .await
        .map_err(|_| ProtocolError::Timeout)??;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    async fn expect_line(stream: &mut (impl AsyncReadExt + Unpin), expected: &str) {
        let mut buf = vec![0u8; expected.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(std::str::from_utf8(&buf).unwrap(), expected);
    }

    #[test]
    fn quote_imap_escapes_specials() {
        assert_eq!(quote_imap(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[tokio::test]
    async fn authenticates_plain_login_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"* OK IMAP4rev1 ready\r\n").await.unwrap();
            expect_line(&mut socket, "C01 CAPABILITY\r\n").await;
            socket
                .write_all(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\nC01 OK CAPABILITY completed\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "A002 LOGIN \"alice\" \"secret\"\r\n").await;
            socket
                .write_all(b"A002 OK LOGIN completed\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "A003 LOGOUT\r\n").await;
            socket
                .write_all(b"* BYE Logging out\r\nA003 OK LOGOUT completed\r\n")
                .await
                .unwrap();
        });

        let module = ImapModule::new();
        let credential = Credential {
            username: "alice".into(),
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
    async fn authenticates_starttls_then_login() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(test_server_config());

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(b"* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "A001 STARTTLS\r\n").await;
            socket.write_all(b"A001 OK begin TLS\r\n").await.unwrap();

            let mut socket = acceptor.accept(socket).await.unwrap();
            expect_line(&mut socket, "A002 LOGIN \"alice\" \"secret\"\r\n").await;
            socket
                .write_all(b"A002 OK LOGIN completed\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "A003 LOGOUT\r\n").await;
            socket
                .write_all(b"* BYE Logging out\r\nA003 OK LOGOUT completed\r\n")
                .await
                .unwrap();
        });

        let module = ImapModule::new().with_insecure(true);
        let credential = Credential {
            username: "alice".into(),
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
    async fn authenticates_implicit_imaps() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(test_server_config());

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(tcp).await.unwrap();
            socket.write_all(b"* OK IMAP4rev1 ready\r\n").await.unwrap();
            // Already TLS → skip STARTTLS negotiation and LOGIN directly.
            expect_line(&mut socket, "A002 LOGIN \"alice\" \"secret\"\r\n").await;
            socket
                .write_all(b"A002 OK LOGIN completed\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "A003 LOGOUT\r\n").await;
            socket
                .write_all(b"* BYE Logging out\r\nA003 OK LOGOUT completed\r\n")
                .await
                .unwrap();
        });

        let module = ImapModule::new().with_insecure(true);
        let credential = Credential {
            username: "alice".into(),
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
    async fn handles_login_no_as_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"* OK IMAP4rev1 ready\r\n").await.unwrap();
            expect_line(&mut socket, "C01 CAPABILITY\r\n").await;
            socket
                .write_all(b"* CAPABILITY IMAP4rev1\r\nC01 OK done\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "A002 LOGIN \"alice\" \"wrong\"\r\n").await;
            socket
                .write_all(b"A002 NO [AUTHENTICATIONFAILED] Invalid credentials\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "A003 LOGOUT\r\n").await;
            socket
                .write_all(b"* BYE Logging out\r\nA003 OK LOGOUT completed\r\n")
                .await
                .unwrap();
        });

        let module = ImapModule::new();
        let credential = Credential {
            username: "alice".into(),
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
    async fn handles_bye_during_login_as_rate_limited() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"* OK IMAP4rev1 ready\r\n").await.unwrap();
            expect_line(&mut socket, "C01 CAPABILITY\r\n").await;
            socket
                .write_all(b"* CAPABILITY IMAP4rev1\r\nC01 OK done\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "A002 LOGIN \"alice\" \"secret\"\r\n").await;
            socket
                .write_all(b"* BYE Autologout; idle for too long\r\n")
                .await
                .unwrap();
        });

        let module = ImapModule::new();
        let credential = Credential {
            username: "alice".into(),
            password: Some("secret".into()),
        };
        let result = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::RateLimited(Duration::from_secs(5)));
        server.await.unwrap();
    }
}
