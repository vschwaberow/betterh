// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! SMTP authentication over Tokio TCP with type-state connections,
//! RFC 5321 multiline reply parsing, STARTTLS, and implicit SMTPS.

use std::{marker::PhantomData, time::Duration};

use async_trait::async_trait;
use base64::prelude::*;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    time::timeout,
};

use super::tls::{TransportStream, wrap_tls};
use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

struct Disconnected;
struct Connected;
struct Greeted;

#[derive(Clone, Copy, Default)]
struct AuthCaps {
    plain: bool,
    login: bool,
}

struct SmtpClient<State> {
    stream: Option<BufReader<TransportStream>>,
    host: String,
    port: u16,
    insecure: bool,
    already_tls: bool,
    auth: AuthCaps,
    _state: PhantomData<State>,
}

impl SmtpClient<Disconnected> {
    fn new(host: String, port: u16, insecure: bool) -> Self {
        Self {
            stream: None,
            host,
            port,
            insecure,
            already_tls: false,
            auth: AuthCaps::default(),
            _state: PhantomData,
        }
    }

    async fn connect(
        self,
        target: &Target,
        proxy: Option<&str>,
    ) -> Result<SmtpClient<Connected>, ProtocolError> {
        let tcp = super::io::dial(target, proxy).await?;

        // Implicit TLS (SMTPS): wrap before reading the banner.
        let (transport, already_tls) = if target.ssl || target.port == 465 {
            (wrap_tls(tcp, &self.host, self.insecure).await?, true)
        } else {
            (TransportStream::plain(tcp), false)
        };

        Ok(SmtpClient {
            stream: Some(BufReader::new(transport)),
            host: self.host,
            port: self.port,
            insecure: self.insecure,
            already_tls,
            auth: AuthCaps::default(),
            _state: PhantomData,
        })
    }
}

impl SmtpClient<Connected> {
    async fn greet(mut self) -> Result<SmtpClient<Greeted>, ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("SMTP stream missing after connect".into()))?;

        // 1. Read initial banner (220 ...)
        let (banner_code, _) = read_reply(stream).await?;
        if !(200..300).contains(&banner_code) {
            return Err(ProtocolError::HandshakeFailed(format!(
                "unexpected SMTP banner code {banner_code}"
            )));
        }

        // 2. EHLO + optional STARTTLS upgrade on submission ports.
        let (auth_plain, auth_login) = self.ehlo_and_maybe_starttls().await?;

        Ok(SmtpClient {
            stream: self.stream.take(),
            host: self.host,
            port: self.port,
            insecure: self.insecure,
            already_tls: self.already_tls,
            auth: AuthCaps {
                plain: auth_plain,
                login: auth_login,
            },
            _state: PhantomData,
        })
    }

    async fn ehlo_and_maybe_starttls(&mut self) -> Result<(bool, bool), ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("SMTP stream missing before EHLO".into()))?;

        let (mut auth_plain, mut auth_login, starttls) = perform_ehlo(stream).await?;

        // Upgrade whenever the peer offers STARTTLS on a cleartext session
        // (typically ports 25 / 587; hermetic tests use ephemeral ports).
        let wants_starttls = starttls && !self.already_tls;
        if !wants_starttls {
            return Ok((auth_plain, auth_login));
        }

        write_line(stream, "STARTTLS").await?;
        let (code, body) = read_reply(stream).await?;
        if code != 220 {
            return Err(ProtocolError::HandshakeFailed(format!(
                "STARTTLS rejected with {code}: {body}"
            )));
        }

        let buffered = self.stream.take().ok_or_else(|| {
            ProtocolError::Internal("SMTP stream missing during STARTTLS upgrade".into())
        })?;
        let inner = buffered.into_inner();
        let TransportStream::Plain(tcp) = inner else {
            return Err(ProtocolError::Internal(
                "STARTTLS requested on an already-TLS stream".into(),
            ));
        };
        let upgraded = wrap_tls(tcp, &self.host, self.insecure).await?;
        let mut stream = BufReader::new(upgraded);
        self.already_tls = true;

        // Re-issue EHLO after TLS and refresh AUTH capabilities.
        let (plain, login, _) = perform_ehlo(&mut stream).await?;
        auth_plain = plain;
        auth_login = login;
        self.stream = Some(stream);
        Ok((auth_plain, auth_login))
    }
}

impl SmtpClient<Greeted> {
    async fn authenticate(
        mut self,
        username: &str,
        password: &str,
    ) -> Result<(AuthResult, SmtpClient<Greeted>), ProtocolError> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            ProtocolError::Internal("SMTP stream missing before authentication".into())
        })?;

        // Prefer AUTH PLAIN if supported
        if self.auth.plain {
            let mut plain_bytes = Vec::with_capacity(username.len() + password.len() + 2);
            plain_bytes.push(0);
            plain_bytes.extend_from_slice(username.as_bytes());
            plain_bytes.push(0);
            plain_bytes.extend_from_slice(password.as_bytes());
            let encoded = BASE64_STANDARD.encode(&plain_bytes);
            write_line(stream, &format!("AUTH PLAIN {encoded}")).await?;
            let (code, body) = read_reply(stream).await?;
            let result = map_smtp_code(code, &body);
            if matches!(result, AuthResult::Error(_)) && self.auth.login {
                return self.authenticate_login(username, password).await;
            }
            return Ok((result, self));
        }

        if self.auth.login {
            return self.authenticate_login(username, password).await;
        }

        Err(ProtocolError::HandshakeFailed(
            "No supported SMTP authentication mechanism (PLAIN/LOGIN)".into(),
        ))
    }

    async fn authenticate_login(
        mut self,
        username: &str,
        password: &str,
    ) -> Result<(AuthResult, SmtpClient<Greeted>), ProtocolError> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            ProtocolError::Internal("SMTP stream missing during AUTH LOGIN".into())
        })?;

        write_line(stream, "AUTH LOGIN").await?;
        let (code, body) = read_reply(stream).await?;
        if code != 334 {
            let result = map_smtp_code(code, &body);
            return Ok((result, self));
        }

        let user_b64 = BASE64_STANDARD.encode(username.as_bytes());
        write_line(stream, &user_b64).await?;
        let (code, body) = read_reply(stream).await?;
        if code != 334 {
            let result = map_smtp_code(code, &body);
            return Ok((result, self));
        }

        let pass_b64 = BASE64_STANDARD.encode(password.as_bytes());
        write_line(stream, &pass_b64).await?;
        let (code, body) = read_reply(stream).await?;
        let result = map_smtp_code(code, &body);
        Ok((result, self))
    }

    async fn quit(mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = write_line(&mut stream, "QUIT").await;
        }
    }
}

fn map_smtp_code(code: u16, body: &str) -> AuthResult {
    match code {
        235 => AuthResult::Success,
        535 | 534 => AuthResult::Failure,
        421 | 454 => AuthResult::RateLimited(Duration::from_secs(5)),
        550 => AuthResult::LockedOut,
        _ => AuthResult::Error(format!("unexpected SMTP reply {code}: {body}")),
    }
}

/// Native SMTP authentication module (`AUTH PLAIN` / `AUTH LOGIN`, STARTTLS / SMTPS).
#[derive(Debug, Default, Clone)]
pub struct SmtpModule {
    proxy: Option<String>,
    insecure: bool,
}

impl SmtpModule {
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
impl ProtocolModule for SmtpModule {
    fn name(&self) -> &'static str {
        "smtp"
    }

    fn default_port(&self) -> u16 {
        25
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
            let connected = SmtpClient::new(target.host.clone(), target.port, self.insecure)
                .connect(target, self.proxy.as_deref())
                .await?;
            let greeted = connected.greet().await?;
            let (outcome, client) = greeted.authenticate(username, password).await?;
            client.quit().await;
            Ok::<AuthResult, ProtocolError>(outcome)
        })
        .await
        .map_err(|_| ProtocolError::Timeout)??;

        Ok(result)
    }
}

async fn perform_ehlo(
    stream: &mut BufReader<TransportStream>,
) -> Result<(bool, bool, bool), ProtocolError> {
    write_line(stream, "EHLO betterh.local").await?;
    let (ehlo_code, ehlo_body) = read_reply(stream).await?;
    let mut auth_plain = false;
    let mut auth_login = false;
    let mut starttls = false;

    if (200..300).contains(&ehlo_code) {
        for line in ehlo_body.lines() {
            let upper = line.to_ascii_uppercase();
            if upper.contains("STARTTLS") {
                starttls = true;
            }
            if upper.contains("AUTH") {
                if upper.contains("PLAIN") {
                    auth_plain = true;
                }
                if upper.contains("LOGIN") {
                    auth_login = true;
                }
            }
        }
    } else {
        write_line(stream, "HELO betterh.local").await?;
        let (helo_code, _) = read_reply(stream).await?;
        if !(200..300).contains(&helo_code) {
            return Err(ProtocolError::HandshakeFailed(format!(
                "unexpected SMTP HELO reply {helo_code}"
            )));
        }
        auth_plain = true;
        auth_login = true;
    }

    if !auth_plain && !auth_login {
        auth_plain = true;
        auth_login = true;
    }

    Ok((auth_plain, auth_login, starttls))
}

async fn write_line(
    stream: &mut BufReader<TransportStream>,
    line: &str,
) -> Result<(), ProtocolError> {
    let mut payload = Vec::with_capacity(line.len() + 2);
    payload.extend_from_slice(line.as_bytes());
    payload.extend_from_slice(b"\r\n");
    let writer = stream.get_mut();
    writer
        .write_all(&payload)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    Ok(())
}

/// Read one SMTP reply, tolerating CRLF or bare LF and RFC 5321 multi-line continuations.
async fn read_reply(
    stream: &mut BufReader<TransportStream>,
) -> Result<(u16, String), ProtocolError> {
    let mut body = String::new();
    let mut expected_code: Option<u16> = None;

    loop {
        let mut line = String::new();
        let read = stream
            .read_line(&mut line)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        if read == 0 {
            return Err(ProtocolError::ConnectionError(
                "SMTP peer closed during reply".into(),
            ));
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if !body.is_empty() {
            body.push('\n');
        }
        body.push_str(trimmed);

        if let Some(expected) = expected_code {
            let expected_str = format!("{expected}");
            if trimmed.starts_with(&expected_str) {
                let char_after = trimmed.as_bytes().get(expected_str.len()).copied();
                if char_after == Some(b' ') || char_after.is_none() {
                    return Ok((expected, body));
                }
            }
            continue;
        }

        if trimmed.len() < 3 {
            return Err(ProtocolError::HandshakeFailed(
                "SMTP reply line too short".into(),
            ));
        }

        let code: u16 = trimmed[..3]
            .parse()
            .map_err(|_| ProtocolError::HandshakeFailed("SMTP reply missing status code".into()))?;

        if trimmed.as_bytes().get(3).copied() == Some(b'-') {
            expected_code = Some(code);
            continue;
        }

        return Ok((code, body));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::TlsAcceptor;

    use super::*;

    async fn spawn_script(script: Vec<&'static str>) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            for step in script {
                if let Some(reply) = step.strip_prefix(">>") {
                    socket.write_all(reply.as_bytes()).await.unwrap();
                } else if let Some(expected) = step.strip_prefix("<<") {
                    let mut buf = vec![0u8; expected.len()];
                    socket.read_exact(&mut buf).await.unwrap();
                    assert_eq!(String::from_utf8_lossy(&buf), expected);
                }
            }
        });
        (port, handle)
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

    async fn expect_exact(stream: &mut (impl AsyncReadExt + Unpin), expected: &str) {
        let mut buf = vec![0u8; expected.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&buf), expected);
    }

    fn target(port: u16) -> Target {
        Target {
            host: "localhost".into(),
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

    #[tokio::test]
    async fn authenticates_smtp_plain_success() {
        let (port, server) = spawn_script(vec![
            ">>220 mail.example.com ESMTP Postfix\r\n",
            "<<EHLO betterh.local\r\n",
            ">>250-mail.example.com\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n",
            "<<AUTH PLAIN AGFsaWNlAHNlY3JldDEyMw==\r\n",
            ">>235 2.7.0 Authentication successful\r\n",
            "<<QUIT\r\n",
        ])
        .await;

        let module = SmtpModule::new();
        let credential = Credential {
            username: "alice".into(),
            password: Some("secret123".into()),
        };
        let result = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handles_smtp_login_fallback_and_failure() {
        let (port, server) = spawn_script(vec![
            ">>220 mail.example.com ESMTP\r\n",
            "<<EHLO betterh.local\r\n",
            ">>250-mail.example.com\r\n250 AUTH LOGIN\r\n",
            "<<AUTH LOGIN\r\n",
            ">>334 VXNlcm5hbWU6\r\n",
            "<<Ym9i\r\n",
            ">>334 UGFzc3dvcmQ6\r\n",
            "<<d3JvbmdwYXNz\r\n",
            ">>535 5.7.8 Authentication credentials invalid\r\n",
            "<<QUIT\r\n",
        ])
        .await;

        let module = SmtpModule::new();
        let credential = Credential {
            username: "bob".into(),
            password: Some("wrongpass".into()),
        };
        let result = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Failure);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handles_multiline_banner_bare_lf_and_rate_limit() {
        let (port, server) = spawn_script(vec![
            ">>220-Welcome to legacy mail server\n220-Warning: monitored\n220 Ready\n",
            "<<EHLO betterh.local\r\n",
            ">>250-localhost\n250 AUTH PLAIN\n",
            "<<AUTH PLAIN AGNlY2lsZQBzZWNyZXQ=\r\n",
            ">>421 4.4.2 Connection limit exceeded\n",
            "<<QUIT\r\n",
        ])
        .await;

        let module = SmtpModule::new();
        let credential = Credential {
            username: "cecile".into(),
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
    async fn handles_account_lockout_550() {
        let (port, server) = spawn_script(vec![
            ">>220 mail.corp\r\n",
            "<<EHLO betterh.local\r\n",
            ">>250-mail.corp\r\n250 AUTH PLAIN\r\n",
            "<<AUTH PLAIN AGRhdmUAcGFzcw==\r\n",
            ">>550 5.2.1 User account disabled or locked\r\n",
            "<<QUIT\r\n",
        ])
        .await;

        let module = SmtpModule::new();
        let credential = Credential {
            username: "dave".into(),
            password: Some("pass".into()),
        };
        let result = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::LockedOut);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn starttls_upgrade_then_authenticates() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(test_server_config());

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(b"220 mail.example.com ESMTP\r\n")
                .await
                .unwrap();
            expect_exact(&mut socket, "EHLO betterh.local\r\n").await;
            socket
                .write_all(b"250-mail.example.com\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            expect_exact(&mut socket, "STARTTLS\r\n").await;
            socket
                .write_all(b"220 Ready to start TLS\r\n")
                .await
                .unwrap();

            let mut socket = acceptor.accept(socket).await.unwrap();
            expect_exact(&mut socket, "EHLO betterh.local\r\n").await;
            socket
                .write_all(b"250-mail.example.com\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            expect_exact(&mut socket, "AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n").await;
            socket
                .write_all(b"235 2.7.0 Authentication successful\r\n")
                .await
                .unwrap();
            expect_exact(&mut socket, "QUIT\r\n").await;
        });

        let module = SmtpModule::new().with_insecure(true);
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
    async fn starttls_rejection_returns_handshake_error() {
        let (port, server) = spawn_script(vec![
            ">>220 mail.example.com ESMTP\r\n",
            "<<EHLO betterh.local\r\n",
            ">>250-mail.example.com\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n",
            "<<STARTTLS\r\n",
            ">>454 TLS not available\r\n",
        ])
        .await;

        // Peer advertises STARTTLS; rejection must surface as HandshakeFailed.
        let module = SmtpModule::new();
        let credential = Credential {
            username: "alice".into(),
            password: Some("secret".into()),
        };
        let err = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, ProtocolError::HandshakeFailed(_)));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn implicit_smtps_wraps_before_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(test_server_config());

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(tcp).await.unwrap();
            socket
                .write_all(b"220 smtps.example.com ESMTP\r\n")
                .await
                .unwrap();
            expect_exact(&mut socket, "EHLO betterh.local\r\n").await;
            socket
                .write_all(b"250-smtps.example.com\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            expect_exact(&mut socket, "AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n").await;
            socket
                .write_all(b"235 2.7.0 Authentication successful\r\n")
                .await
                .unwrap();
            expect_exact(&mut socket, "QUIT\r\n").await;
        });

        let module = SmtpModule::new().with_insecure(true);
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
    async fn implicit_tls_on_port_465_without_ssl_flag() {
        // Port 465 implies SMTPS even without `target.ssl`. Skip if 465 is busy.
        let Ok(listener) = TcpListener::bind("127.0.0.1:465").await else {
            return;
        };
        let acceptor = TlsAcceptor::from(test_server_config());
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(tcp).await.unwrap();
            socket.write_all(b"220 smtps\r\n").await.unwrap();
            expect_exact(&mut socket, "EHLO betterh.local\r\n").await;
            socket
                .write_all(b"250-smtps\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            expect_exact(&mut socket, "AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n").await;
            socket.write_all(b"235 ok\r\n").await.unwrap();
            expect_exact(&mut socket, "QUIT\r\n").await;
        });

        let module = SmtpModule::new().with_insecure(true);
        let credential = Credential {
            username: "alice".into(),
            password: Some("secret".into()),
        };
        let mut tgt = target(465);
        tgt.ssl = false;
        let result = module
            .authenticate(&tgt, &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }
}
