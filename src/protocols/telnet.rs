// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Telnet login-prompt authentication (RFC 854) over Tokio TCP.
//!
//! Auth-only: classic banner → username prompt → password prompt dialogue.
//! Minimal IAC negotiation so real `login` daemons do not stall.

use std::time::Duration;

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout},
};

use super::io::dial;
use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

const OPT_ECHO: u8 = 1;
const OPT_SUPPRESS_GO_AHEAD: u8 = 3;

const MAX_TEXT_BUF: usize = 16 * 1024;
const RESPONSE_IDLE: Duration = Duration::from_millis(400);
const RESPONSE_DEADLINE: Duration = Duration::from_secs(3);

/// Telnet login authentication module (feature = `telnet`).
#[derive(Debug, Default, Clone)]
pub struct TelnetModule {
    proxy: Option<String>,
}

impl TelnetModule {
    #[must_use]
    pub const fn new() -> Self {
        Self { proxy: None }
    }

    #[must_use]
    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = proxy;
        self
    }
}

#[async_trait]
impl ProtocolModule for TelnetModule {
    fn name(&self) -> &'static str {
        "telnet"
    }

    fn default_port(&self) -> u16 {
        23
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
        let proxy = self.proxy.clone();

        timeout(timeout_budget, async move {
            let mut stream = dial(target, proxy.as_deref()).await?;
            run_telnet_login(&mut stream, &username, &password).await
        })
        .await
        .map_err(|_| ProtocolError::Timeout)?
    }
}

async fn run_telnet_login(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<AuthResult, ProtocolError> {
    let mut text = String::new();
    // Session-scoped: incomplete IAC sequences must survive prompt-phase boundaries.
    let mut pending = Vec::new();

    wait_for_prompt(stream, &mut pending, &mut text, PromptKind::Username).await?;
    write_line(stream, username).await?;

    text.clear();
    wait_for_prompt(stream, &mut pending, &mut text, PromptKind::Password).await?;
    write_line(stream, password).await?;

    text.clear();
    read_response_window(stream, &mut pending, &mut text).await?;
    Ok(classify_auth_result(&text))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptKind {
    Username,
    Password,
}

fn is_username_prompt(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("login:") || lower.contains("username:") || lower.contains("user name:")
}

fn is_password_prompt(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("password:") || lower.contains("passwd:")
}

fn prompt_matches(text: &str, kind: PromptKind) -> bool {
    match kind {
        PromptKind::Username => is_username_prompt(text),
        PromptKind::Password => is_password_prompt(text),
    }
}

fn prompt_label(kind: PromptKind) -> &'static str {
    match kind {
        PromptKind::Username => "username",
        PromptKind::Password => "password",
    }
}

/// Classify post-password server text into an auth result.
#[must_use]
pub fn classify_auth_result(text: &str) -> AuthResult {
    let lower = text.to_ascii_lowercase();
    let failure = [
        "login incorrect",
        "login failed",
        "authentication failed",
        "access denied",
        "incorrect",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    if failure {
        return AuthResult::Failure;
    }

    let success_phrase = lower.contains("last login");
    let shell_marker = text.chars().any(|c| matches!(c, '$' | '#' | '>' | '%'));
    if success_phrase || shell_marker {
        return AuthResult::Success;
    }

    // Safe default for auth auditing: treat ambiguous output as failure.
    AuthResult::Failure
}

fn response_is_decisive(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("login incorrect")
        || lower.contains("login failed")
        || lower.contains("authentication failed")
        || lower.contains("access denied")
        || lower.contains("last login")
        || text.chars().any(|c| matches!(c, '$' | '#' | '>' | '%'))
}

async fn write_line(stream: &mut TcpStream, line: &str) -> Result<(), ProtocolError> {
    let mut buf = Vec::with_capacity(line.len() + 2);
    buf.extend_from_slice(line.as_bytes());
    buf.extend_from_slice(b"\r\n");
    stream
        .write_all(&buf)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))
}

async fn write_iac_replies(stream: &mut TcpStream, replies: &[u8]) -> Result<(), ProtocolError> {
    if replies.is_empty() {
        return Ok(());
    }
    stream
        .write_all(replies)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))
}

async fn wait_for_prompt(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
    text: &mut String,
    kind: PromptKind,
) -> Result<(), ProtocolError> {
    let mut chunk = [0u8; 512];
    loop {
        if prompt_matches(text, kind) {
            return Ok(());
        }
        if text.len() > MAX_TEXT_BUF {
            return Err(ProtocolError::HandshakeFailed(format!(
                "Telnet banner exceeded {MAX_TEXT_BUF} bytes without a {} prompt",
                prompt_label(kind)
            )));
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        if n == 0 {
            return Err(ProtocolError::HandshakeFailed(format!(
                "Telnet peer closed before {} prompt",
                prompt_label(kind)
            )));
        }
        let replies = feed_iac(&chunk[..n], pending, text);
        write_iac_replies(stream, &replies).await?;
    }
}

async fn read_response_window(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
    text: &mut String,
) -> Result<(), ProtocolError> {
    let mut chunk = [0u8; 512];
    let deadline = Instant::now() + RESPONSE_DEADLINE;
    let mut saw_data = false;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let idle = if saw_data {
            RESPONSE_IDLE.min(remaining)
        } else {
            remaining
        };
        match timeout(idle, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                saw_data = true;
                let replies = feed_iac(&chunk[..n], pending, text);
                write_iac_replies(stream, &replies).await?;
                if text.len() > MAX_TEXT_BUF || response_is_decisive(text) {
                    break;
                }
            }
            Ok(Err(error)) => {
                return Err(ProtocolError::ConnectionError(error.to_string()));
            }
            Err(_) => {
                if saw_data {
                    break;
                }
                return Err(ProtocolError::Timeout);
            }
        }
    }
    Ok(())
}

/// Feed raw bytes through an IAC filter into `text`, returning reply bytes to send.
#[must_use]
pub fn feed_iac(input: &[u8], pending: &mut Vec<u8>, text: &mut String) -> Vec<u8> {
    pending.extend_from_slice(input);
    let mut replies = Vec::new();
    let mut i = 0;
    while i < pending.len() {
        if pending[i] != IAC {
            let start = i;
            while i < pending.len() && pending[i] != IAC {
                i += 1;
            }
            append_lossy_utf8(text, &pending[start..i]);
            continue;
        }
        // Need at least IAC + command
        if i + 1 >= pending.len() {
            break;
        }
        let cmd = pending[i + 1];
        match cmd {
            IAC => {
                // Escaped 0xFF data byte.
                text.push('\u{00ff}');
                i += 2;
            }
            WILL | WONT | DO | DONT => {
                if i + 2 >= pending.len() {
                    break;
                }
                let opt = pending[i + 2];
                replies.extend_from_slice(&iac_option_reply(cmd, opt));
                i += 3;
            }
            SB => {
                // Skip subnegotiation until IAC SE (IAC IAC is escaped data).
                let mut j = i + 2;
                let mut found = false;
                while j + 1 < pending.len() {
                    if pending[j] != IAC {
                        j += 1;
                        continue;
                    }
                    if pending[j + 1] == SE {
                        i = j + 2;
                        found = true;
                        break;
                    }
                    // IAC IAC (escaped data) or other IAC cmd inside SB — skip the pair.
                    j += 2;
                }
                if !found {
                    break;
                }
            }
            // Other single-byte commands (NOP, GA, …) — discard.
            _ => {
                i += 2;
            }
        }
    }
    pending.drain(..i);
    replies
}

fn iac_option_reply(cmd: u8, opt: u8) -> [u8; 3] {
    // Accept Echo / Suppress-Go-Ahead when peer enables them; refuse everything else.
    match (cmd, opt) {
        (WILL, OPT_ECHO | OPT_SUPPRESS_GO_AHEAD) => [IAC, DO, opt],
        (DO, OPT_ECHO | OPT_SUPPRESS_GO_AHEAD) => [IAC, WILL, opt],
        (WILL | WONT, _) => [IAC, DONT, opt],
        _ => [IAC, WONT, opt],
    }
}

fn append_lossy_utf8(text: &mut String, bytes: &[u8]) {
    text.push_str(&String::from_utf8_lossy(bytes));
    if text.len() > MAX_TEXT_BUF {
        let keep = MAX_TEXT_BUF / 2;
        let drained = text.len() - keep;
        text.drain(..drained);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn iac_will_echo_answered_with_do() {
        let mut pending = Vec::new();
        let mut text = String::new();
        let input = [IAC, WILL, OPT_ECHO, b'h', b'i'];
        let replies = feed_iac(&input, &mut pending, &mut text);
        assert_eq!(replies, [IAC, DO, OPT_ECHO]);
        assert_eq!(text, "hi");
        assert!(pending.is_empty());
    }

    #[test]
    fn iac_do_echo_answered_with_will() {
        let mut pending = Vec::new();
        let mut text = String::new();
        let replies = feed_iac(&[IAC, DO, OPT_ECHO], &mut pending, &mut text);
        assert_eq!(replies, [IAC, WILL, OPT_ECHO]);
        assert!(text.is_empty());
    }

    #[test]
    fn iac_will_unknown_refused() {
        let mut pending = Vec::new();
        let mut text = String::new();
        let replies = feed_iac(&[IAC, WILL, 42], &mut pending, &mut text);
        assert_eq!(replies, [IAC, DONT, 42]);
        assert!(text.is_empty());
    }

    #[test]
    fn iac_fragment_across_chunks_preserved() {
        let mut pending = Vec::new();
        let mut text = String::new();

        let replies = feed_iac(&[IAC], &mut pending, &mut text);
        assert!(replies.is_empty());
        assert_eq!(pending, [IAC]);

        let replies = feed_iac(&[WILL], &mut pending, &mut text);
        assert!(replies.is_empty());
        assert_eq!(pending, [IAC, WILL]);

        let replies = feed_iac(&[OPT_ECHO, b'x'], &mut pending, &mut text);
        assert_eq!(replies, [IAC, DO, OPT_ECHO]);
        assert_eq!(text, "x");
        assert!(pending.is_empty());
    }

    #[test]
    fn iac_escaped_ff_becomes_text() {
        let mut pending = Vec::new();
        let mut text = String::new();
        let replies = feed_iac(&[IAC, IAC, b'a'], &mut pending, &mut text);
        assert!(replies.is_empty());
        assert_eq!(text, "\u{00ff}a");
    }

    #[test]
    fn iac_subnegotiation_skipped() {
        let mut pending = Vec::new();
        let mut text = String::new();
        let input = [IAC, SB, 24, b'x', IAC, SE, b'o', b'k'];
        let replies = feed_iac(&input, &mut pending, &mut text);
        assert!(replies.is_empty());
        assert_eq!(text, "ok");
        assert!(pending.is_empty());
    }

    #[test]
    fn username_and_password_prompts_detected() {
        assert!(is_username_prompt("Ubuntu 22.04\r\nlogin: "));
        assert!(is_username_prompt("Username:"));
        assert!(is_password_prompt("Password: "));
        assert!(is_password_prompt("passwd:"));
        assert!(!is_username_prompt("Password: "));
    }

    #[test]
    fn classify_success_and_failure() {
        assert_eq!(
            classify_auth_result("Login incorrect\r\nlogin: "),
            AuthResult::Failure
        );
        assert_eq!(
            classify_auth_result("Last login: Mon Sep 1\r\nalice@host:~$ "),
            AuthResult::Success
        );
        assert_eq!(classify_auth_result("root@box:~# "), AuthResult::Success);
        assert_eq!(classify_auth_result("..."), AuthResult::Failure);
    }

    async fn mock_telnet(accept: bool) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Offer Echo; client should DO.
            sock.write_all(&[IAC, WILL, OPT_ECHO]).await.unwrap();
            sock.write_all(b"Welcome\r\nlogin: ").await.unwrap();

            let mut buf = vec![0u8; 256];
            // Drain IAC reply + username line.
            let n = sock.read(&mut buf).await.unwrap();
            let data = &buf[..n];
            // May arrive as IAC reply then username, or together — keep reading until LF.
            let mut collected = data.to_vec();
            while !collected.contains(&b'\n') {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                collected.extend_from_slice(&buf[..n]);
            }

            sock.write_all(b"Password: ").await.unwrap();
            collected.clear();
            while !collected.contains(&b'\n') {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                collected.extend_from_slice(&buf[..n]);
            }

            if accept {
                sock.write_all(b"Last login: today\r\nuser@host:~$ ")
                    .await
                    .unwrap();
            } else {
                sock.write_all(b"Login incorrect\r\nlogin: ").await.unwrap();
            }
        });
        port
    }

    fn local_target(port: u16) -> Target {
        Target {
            host: "127.0.0.1".into(),
            port,
            ssl: false,
            ip: Some("127.0.0.1".parse().unwrap()),
            path: None,
        }
    }

    #[tokio::test]
    async fn correct_credentials_succeed() {
        let port = mock_telnet(true).await;
        let module = TelnetModule::new();
        let result = module
            .authenticate(
                &local_target(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("secret".into()),
                },
                Duration::from_secs(3),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
    }

    #[tokio::test]
    async fn wrong_credentials_fail() {
        let port = mock_telnet(false).await;
        let module = TelnetModule::new();
        let result = module
            .authenticate(
                &local_target(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("wrong".into()),
                },
                Duration::from_secs(3),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Failure);
    }

    #[tokio::test]
    async fn missing_prompt_is_handshake_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"no prompts here\r\n").await.unwrap();
            // Close after a short delay so client sees EOF.
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(sock);
        });
        let module = TelnetModule::new();
        let err = module
            .authenticate(
                &local_target(port),
                &Credential {
                    username: "x".into(),
                    password: Some("y".into()),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProtocolError::HandshakeFailed(_)));
    }

    #[tokio::test]
    async fn fragmented_iac_before_login_prompt_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Split WILL ECHO across writes so the client must retain pending IAC.
            sock.write_all(&[IAC]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            sock.write_all(&[WILL, OPT_ECHO]).await.unwrap();
            sock.write_all(b"login: ").await.unwrap();

            let mut buf = vec![0u8; 256];
            let mut collected = Vec::new();
            while !collected.contains(&b'\n') {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                collected.extend_from_slice(&buf[..n]);
            }
            // Client must have answered DO Echo somewhere in the stream.
            assert!(
                collected.windows(3).any(|w| w == [IAC, DO, OPT_ECHO]),
                "expected IAC DO ECHO reply, got {collected:?}"
            );

            sock.write_all(b"Password: ").await.unwrap();
            collected.clear();
            while !collected.contains(&b'\n') {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                collected.extend_from_slice(&buf[..n]);
            }
            sock.write_all(b"Last login: today\r\nuser@host:~$ ")
                .await
                .unwrap();
        });

        let module = TelnetModule::new();
        let result = module
            .authenticate(
                &local_target(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("secret".into()),
                },
                Duration::from_secs(3),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
    }
}
