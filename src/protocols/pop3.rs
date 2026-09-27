// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! POP3 / POP3S authentication (RFC 1939 / RFC 5034 / RFC 2595) — auth-only.
//!
//! Default auth path is `USER` / `PASS`. When `CAPA` advertises `SASL PLAIN` and
//! [`Pop3Module::with_prefer_auth_plain`] is set, the module uses `AUTH PLAIN`
//! instead. Unknown capa tokens are ignored. Always issues `QUIT` on teardown.
//!
//! TLS order: implicit TLS before the greeting when `target.ssl` or port `995`;
//! otherwise `CAPA` → `STLS` (when advertised) → upgrade via [`TransportStream`]
//! → auth. Plaintext `PASS` is never sent if `STLS` was required and failed.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::{
    io::{AsyncWriteExt, BufReader},
    time::timeout,
};

use super::io::{dial, read_crlf_line};
use super::tls::{TransportStream, wrap_tls};
use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

/// POP3 / POP3S authentication module (feature = `pop3`).
#[derive(Debug, Default, Clone)]
pub struct Pop3Module {
    proxy: Option<String>,
    insecure: bool,
    /// When true and `CAPA` lists `SASL PLAIN`, use `AUTH PLAIN` instead of `USER`/`PASS`.
    prefer_auth_plain: bool,
}

impl Pop3Module {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            proxy: None,
            insecure: false,
            prefer_auth_plain: false,
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

    /// Prefer `AUTH PLAIN` when the server advertises it via `CAPA` (default: `USER`/`PASS`).
    #[must_use]
    pub const fn with_prefer_auth_plain(mut self, prefer: bool) -> Self {
        self.prefer_auth_plain = prefer;
        self
    }
}

#[async_trait]
impl ProtocolModule for Pop3Module {
    fn name(&self) -> &'static str {
        "pop3"
    }

    fn default_port(&self) -> u16 {
        110
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
        let username = credential.username.clone();
        let password = credential.password.clone().unwrap_or_default();
        let host = target.host.clone();
        let insecure = self.insecure;
        let prefer_auth_plain = self.prefer_auth_plain;
        let proxy = self.proxy.clone();
        let ssl = target.ssl;
        let port = target.port;

        timeout(timeout_budget, async move {
            let tcp = dial(target, proxy.as_deref()).await?;
            let implicit_tls = ssl || port == 995;
            let transport = if implicit_tls {
                wrap_tls(tcp, &host, insecure).await?
            } else {
                TransportStream::plain(tcp)
            };
            let mut client = Pop3Client {
                stream: Some(BufReader::new(transport)),
                host,
                insecure,
                already_tls: implicit_tls,
            };
            client
                .run_session(&username, &password, prefer_auth_plain)
                .await
        })
        .await
        .map_err(|_| ProtocolError::Timeout)?
    }
}

struct Pop3Client {
    stream: Option<BufReader<TransportStream>>,
    host: String,
    insecure: bool,
    already_tls: bool,
}

impl Pop3Client {
    fn stream_mut(&mut self) -> Result<&mut BufReader<TransportStream>, ProtocolError> {
        self.stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("POP3 stream missing".into()))
    }

    async fn run_session(
        &mut self,
        username: &str,
        password: &str,
        prefer_auth_plain: bool,
    ) -> Result<AuthResult, ProtocolError> {
        {
            let stream = self.stream_mut()?;
            let greeting = read_crlf_line(stream).await?;
            match classify_status(&greeting) {
                Pop3Status::Ok => {}
                Pop3Status::Err => {
                    return Err(ProtocolError::HandshakeFailed(format!(
                        "POP3 greeting rejected: {greeting}"
                    )));
                }
                Pop3Status::Other => {
                    return Err(ProtocolError::HandshakeFailed(format!(
                        "Unexpected POP3 greeting: {greeting}"
                    )));
                }
            }
        }

        let mut capa = self.fetch_capa().await?;
        if !self.already_tls && capa.stls {
            self.upgrade_stls().await?;
            capa = self.fetch_capa().await?;
        }

        let use_plain = prefer_auth_plain && capa.sasl_plain;
        let result = if use_plain {
            self.auth_plain(username, password).await?
        } else {
            self.auth_user_pass(username, password).await?
        };

        let _ = self.quit().await;
        Ok(result)
    }

    async fn fetch_capa(&mut self) -> Result<Capa, ProtocolError> {
        let stream = self.stream_mut()?;
        write_line(stream, "CAPA").await?;
        let status = read_crlf_line(stream).await?;
        match classify_status(&status) {
            Pop3Status::Ok => {}
            Pop3Status::Err => return Ok(Capa::default()),
            Pop3Status::Other => {
                return Err(ProtocolError::HandshakeFailed(format!(
                    "Unexpected POP3 CAPA status: {status}"
                )));
            }
        }

        let mut lines = Vec::new();
        loop {
            let line = read_crlf_line(stream).await?;
            if line.trim() == "." {
                break;
            }
            lines.push(line);
        }
        Ok(parse_capa_lines(&lines))
    }

    async fn upgrade_stls(&mut self) -> Result<(), ProtocolError> {
        {
            let stream = self.stream_mut()?;
            write_line(stream, "STLS").await?;
            let resp = read_crlf_line(stream).await?;
            match classify_status(&resp) {
                Pop3Status::Ok => {}
                Pop3Status::Err => {
                    return Err(ProtocolError::HandshakeFailed(
                        "POP3 STLS rejected; refusing plaintext PASS".into(),
                    ));
                }
                Pop3Status::Other => {
                    return Err(ProtocolError::HandshakeFailed(format!(
                        "Unexpected POP3 STLS response: {resp}"
                    )));
                }
            }
        }

        let buffered = self.stream.take().ok_or_else(|| {
            ProtocolError::Internal("POP3 stream missing during STLS upgrade".into())
        })?;
        let inner = buffered.into_inner();
        let TransportStream::Plain(tcp) = inner else {
            return Err(ProtocolError::Internal(
                "STLS requested on an already-TLS stream".into(),
            ));
        };
        let upgraded = wrap_tls(tcp, &self.host, self.insecure).await?;
        self.stream = Some(BufReader::new(upgraded));
        self.already_tls = true;
        Ok(())
    }

    async fn auth_user_pass(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<AuthResult, ProtocolError> {
        let stream = self.stream_mut()?;
        write_line(stream, &format!("USER {username}")).await?;
        let user_resp = read_crlf_line(stream).await?;
        match classify_status(&user_resp) {
            Pop3Status::Ok => {}
            Pop3Status::Err => return Ok(AuthResult::Failure),
            Pop3Status::Other => {
                return Err(ProtocolError::HandshakeFailed(format!(
                    "Unexpected POP3 USER response: {user_resp}"
                )));
            }
        }

        write_line(stream, &format!("PASS {password}")).await?;
        let pass_resp = read_crlf_line(stream).await?;
        Ok(map_auth_response(&pass_resp))
    }

    async fn auth_plain(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<AuthResult, ProtocolError> {
        let stream = self.stream_mut()?;
        let mut material = Vec::with_capacity(username.len() + password.len() + 2);
        material.push(0);
        material.extend_from_slice(username.as_bytes());
        material.push(0);
        material.extend_from_slice(password.as_bytes());
        let encoded = B64.encode(material);
        write_line(stream, &format!("AUTH PLAIN {encoded}")).await?;
        let resp = read_crlf_line(stream).await?;
        Ok(map_auth_response(&resp))
    }

    async fn quit(&mut self) -> Result<(), ProtocolError> {
        let stream = self.stream_mut()?;
        write_line(stream, "QUIT").await?;
        let _ = read_crlf_line(stream).await;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pop3Status {
    Ok,
    Err,
    Other,
}

fn classify_status(line: &str) -> Pop3Status {
    let upper = line.trim().to_ascii_uppercase();
    if upper.starts_with("+OK") {
        Pop3Status::Ok
    } else if upper.starts_with("-ERR") {
        Pop3Status::Err
    } else {
        Pop3Status::Other
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Capa {
    sasl_plain: bool,
    stls: bool,
    user: bool,
}

/// Parse a `CAPA` listing; unknown tokens are ignored.
fn parse_capa_lines(lines: &[String]) -> Capa {
    let mut capa = Capa::default();
    for line in lines {
        let upper = line.trim().to_ascii_uppercase();
        if upper.is_empty() || upper == "." {
            continue;
        }
        if upper == "STLS" {
            capa.stls = true;
            continue;
        }
        if upper == "USER" {
            capa.user = true;
            continue;
        }
        if let Some(rest) = upper.strip_prefix("SASL") {
            let mechs = rest.trim();
            if mechs.split_whitespace().any(|m| m == "PLAIN") {
                capa.sasl_plain = true;
            }
        }
    }
    capa
}

fn map_auth_response(line: &str) -> AuthResult {
    let upper = line.trim().to_ascii_uppercase();
    if upper.starts_with("+OK") {
        AuthResult::Success
    } else if upper.starts_with("-ERR") {
        if upper.contains("LOCK") || upper.contains("BUSY") || upper.contains("TRY LATER") {
            AuthResult::RateLimited(Duration::from_secs(5))
        } else {
            AuthResult::Failure
        }
    } else {
        AuthResult::Error(format!("Unexpected POP3 auth response: {line}"))
    }
}

async fn write_line(
    stream: &mut BufReader<TransportStream>,
    line: &str,
) -> Result<(), ProtocolError> {
    let mut payload = String::with_capacity(line.len() + 2);
    payload.push_str(line);
    payload.push_str("\r\n");
    stream
        .get_mut()
        .write_all(payload.as_bytes())
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))
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

    async fn expect_line(socket: &mut (impl AsyncReadExt + Unpin), expected: &str) {
        let mut buf = vec![0u8; expected.len()];
        socket.read_exact(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&buf), expected);
    }

    #[test]
    fn parse_capa_ignores_unknown_and_detects_sasl_plain() {
        let lines = [
            "TOP".into(),
            "USER".into(),
            "PIPELINING".into(),
            "SASL PLAIN LOGIN".into(),
            "IMPLEMENTATION foo".into(),
        ];
        let capa = parse_capa_lines(&lines);
        assert!(capa.user);
        assert!(capa.sasl_plain);
        assert!(!capa.stls);
    }

    #[test]
    fn parse_capa_stls_without_sasl() {
        let capa = parse_capa_lines(&["STLS".into(), "USER".into()]);
        assert!(capa.stls);
        assert!(capa.user);
        assert!(!capa.sasl_plain);
    }

    #[tokio::test]
    async fn user_pass_success_and_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"+OK POP3 ready\r\n").await.unwrap();
            expect_line(&mut socket, "CAPA\r\n").await;
            socket
                .write_all(b"+OK Capability list follows\r\nUSER\r\nTOP\r\n.\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "USER alice\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
            expect_line(&mut socket, "PASS secret\r\n").await;
            socket.write_all(b"+OK maildrop locked\r\n").await.unwrap();
            expect_line(&mut socket, "QUIT\r\n").await;
            socket.write_all(b"+OK bye\r\n").await.unwrap();

            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"+OK POP3 ready\r\n").await.unwrap();
            expect_line(&mut socket, "CAPA\r\n").await;
            socket.write_all(b"+OK\r\nUSER\r\n.\r\n").await.unwrap();
            expect_line(&mut socket, "USER alice\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
            expect_line(&mut socket, "PASS wrong\r\n").await;
            socket.write_all(b"-ERR auth failed\r\n").await.unwrap();
            expect_line(&mut socket, "QUIT\r\n").await;
            let _ = socket.write_all(b"+OK bye\r\n").await;
        });

        let module = Pop3Module::new();
        let ok = module
            .authenticate(
                &target(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("secret".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(ok, AuthResult::Success);

        let fail = module
            .authenticate(
                &target(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("wrong".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(fail, AuthResult::Failure);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn auth_plain_when_preferred_and_advertised() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"+OK ready\r\n").await.unwrap();
            expect_line(&mut socket, "CAPA\r\n").await;
            socket
                .write_all(b"+OK\r\nUSER\r\nSASL PLAIN\r\n.\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
            expect_line(&mut socket, "QUIT\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
        });

        let module = Pop3Module::new().with_prefer_auth_plain(true);
        let result = module
            .authenticate(
                &target(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("secret".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn prefer_auth_plain_falls_back_to_user_pass_without_sasl() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"+OK ready\r\n").await.unwrap();
            expect_line(&mut socket, "CAPA\r\n").await;
            socket
                .write_all(b"+OK\r\nUSER\r\nUIDL\r\n.\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "USER bob\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
            expect_line(&mut socket, "PASS x\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
            expect_line(&mut socket, "QUIT\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
        });

        let module = Pop3Module::new().with_prefer_auth_plain(true);
        let result = module
            .authenticate(
                &target(port),
                &Credential {
                    username: "bob".into(),
                    password: Some("x".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn capa_error_still_allows_user_pass() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"+OK ready\r\n").await.unwrap();
            expect_line(&mut socket, "CAPA\r\n").await;
            socket.write_all(b"-ERR unknown\r\n").await.unwrap();
            expect_line(&mut socket, "USER u\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
            expect_line(&mut socket, "PASS p\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
            expect_line(&mut socket, "QUIT\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
        });

        let result = Pop3Module::new()
            .authenticate(
                &target(port),
                &Credential {
                    username: "u".into(),
                    password: Some("p".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn stls_then_user_pass_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(test_server_config());

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"+OK ready\r\n").await.unwrap();
            expect_line(&mut socket, "CAPA\r\n").await;
            socket
                .write_all(b"+OK\r\nUSER\r\nSTLS\r\n.\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "STLS\r\n").await;
            socket.write_all(b"+OK Begin TLS\r\n").await.unwrap();

            let mut socket = acceptor.accept(socket).await.unwrap();
            expect_line(&mut socket, "CAPA\r\n").await;
            socket.write_all(b"+OK\r\nUSER\r\n.\r\n").await.unwrap();
            expect_line(&mut socket, "USER alice\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
            expect_line(&mut socket, "PASS secret\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
            expect_line(&mut socket, "QUIT\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
        });

        let module = Pop3Module::new().with_insecure(true);
        let result = module
            .authenticate(
                &target(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("secret".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn implicit_pop3s_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(test_server_config());

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(tcp).await.unwrap();
            socket.write_all(b"+OK POP3S ready\r\n").await.unwrap();
            expect_line(&mut socket, "CAPA\r\n").await;
            socket.write_all(b"+OK\r\nUSER\r\n.\r\n").await.unwrap();
            expect_line(&mut socket, "USER alice\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
            expect_line(&mut socket, "PASS secret\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
            expect_line(&mut socket, "QUIT\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
        });

        let module = Pop3Module::new().with_insecure(true);
        let result = module
            .authenticate(
                &target_ssl(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("secret".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn stls_failure_refuses_plaintext_pass() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"+OK ready\r\n").await.unwrap();
            expect_line(&mut socket, "CAPA\r\n").await;
            socket
                .write_all(b"+OK\r\nSTLS\r\nUSER\r\n.\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "STLS\r\n").await;
            socket.write_all(b"-ERR TLS unavailable\r\n").await.unwrap();
            // Client must not send USER/PASS. Brief wait then close.
            let mut buf = [0u8; 8];
            let n = tokio::time::timeout(Duration::from_millis(200), socket.read(&mut buf))
                .await
                .unwrap_or(Ok(0))
                .unwrap_or(0);
            assert_eq!(
                n, 0,
                "must not send plaintext credentials after STLS failure"
            );
        });

        let err = Pop3Module::new()
            .authenticate(
                &target(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("secret".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProtocolError::HandshakeFailed(_)));
        server.await.unwrap();
    }

    #[test]
    fn map_auth_response_classifies_ok_err_and_rate_limit() {
        assert_eq!(map_auth_response("+OK welcome"), AuthResult::Success);
        assert_eq!(map_auth_response("-ERR auth failed"), AuthResult::Failure);
        assert_eq!(
            map_auth_response("-ERR [IN-USE] mailbox locked, try later"),
            AuthResult::RateLimited(Duration::from_secs(5))
        );
        assert_eq!(
            map_auth_response("-ERR server busy"),
            AuthResult::RateLimited(Duration::from_secs(5))
        );
        assert!(matches!(map_auth_response("WTF"), AuthResult::Error(_)));
    }

    #[test]
    fn with_proxy_stores_socks_url() {
        let module = Pop3Module::new().with_proxy(Some("socks5://127.0.0.1:1080".into()));
        assert_eq!(module.proxy.as_deref(), Some("socks5://127.0.0.1:1080"));
    }

    #[tokio::test]
    async fn zero_timeout_returns_timeout_error() {
        let err = Pop3Module::new()
            .authenticate(
                &target(9),
                &Credential {
                    username: "a".into(),
                    password: Some("b".into()),
                },
                Duration::ZERO,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProtocolError::Timeout));
    }

    #[tokio::test]
    async fn rate_limited_pass_still_sends_quit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"+OK ready\r\n").await.unwrap();
            expect_line(&mut socket, "CAPA\r\n").await;
            socket.write_all(b"+OK\r\nUSER\r\n.\r\n").await.unwrap();
            expect_line(&mut socket, "USER alice\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
            expect_line(&mut socket, "PASS secret\r\n").await;
            socket
                .write_all(b"-ERR [IN-USE] try later\r\n")
                .await
                .unwrap();
            expect_line(&mut socket, "QUIT\r\n").await;
            socket.write_all(b"+OK\r\n").await.unwrap();
        });

        let result = Pop3Module::new()
            .authenticate(
                &target(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("secret".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::RateLimited(Duration::from_secs(5)));
        server.await.unwrap();
    }
}
