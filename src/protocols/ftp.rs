// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! FTP USER/PASS authentication over Tokio TCP with type-state connections.

use std::{marker::PhantomData, time::Duration};

use async_trait::async_trait;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

struct Disconnected;
struct Connected;
struct Ready;

struct FtpClient<State> {
    stream: Option<BufReader<TcpStream>>,
    _state: PhantomData<State>,
}

impl FtpClient<Disconnected> {
    const fn new() -> Self {
        Self {
            stream: None,
            _state: PhantomData,
        }
    }

    async fn connect(
        self,
        target: &Target,
        proxy: Option<&str>,
    ) -> Result<FtpClient<Connected>, ProtocolError> {
        let addr = target.dial_addr();
        let stream = match proxy {
            None => TcpStream::connect(&addr)
                .await
                .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?,
            Some(proxy) => super::socks::connect_socks5(proxy, &addr).await?,
        };
        Ok(FtpClient {
            stream: Some(BufReader::new(stream)),
            _state: PhantomData,
        })
    }
}

impl FtpClient<Connected> {
    async fn handshake(mut self) -> Result<FtpClient<Ready>, ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("FTP stream missing after connect".into()))?;
        let (code, _) = read_reply(stream).await?;
        if !(200..300).contains(&code) {
            return Err(ProtocolError::HandshakeFailed(format!(
                "unexpected FTP banner code {code}"
            )));
        }
        Ok(FtpClient {
            stream: self.stream.take(),
            _state: PhantomData,
        })
    }
}

impl FtpClient<Ready> {
    async fn login(
        mut self,
        username: &str,
        password: &str,
    ) -> Result<(AuthResult, FtpClient<Ready>), ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("FTP stream missing before login".into()))?;

        write_line(stream, &format!("USER {username}")).await?;
        let (user_code, _) = read_reply(stream).await?;
        if user_code == 230 {
            return Ok((AuthResult::Success, self));
        }
        if user_code == 530 {
            return Ok((AuthResult::Failure, self));
        }
        if user_code != 331 && user_code != 332 {
            return Err(ProtocolError::HandshakeFailed(format!(
                "unexpected FTP USER reply {user_code}"
            )));
        }

        write_line(stream, &format!("PASS {password}")).await?;
        let (pass_code, _) = read_reply(stream).await?;
        let result = match pass_code {
            230 => AuthResult::Success,
            530 => AuthResult::Failure,
            421 | 429 => AuthResult::RateLimited(Duration::from_secs(1)),
            other => AuthResult::Error(format!("unexpected FTP PASS reply {other}")),
        };
        Ok((result, self))
    }

    async fn quit(mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = write_line(&mut stream, "QUIT").await;
        }
    }
}

/// Native FTP authentication module (`USER` / `PASS`).
#[derive(Debug, Default, Clone)]
pub struct FtpModule {
    /// Reserved for later data-connection mode; auth uses the control channel only.
    pub passive: bool,
    proxy: Option<String>,
}

impl FtpModule {
    #[must_use]
    pub const fn new(passive: bool) -> Self {
        Self {
            passive,
            proxy: None,
        }
    }

    #[must_use]
    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = proxy;
        self
    }
}

#[async_trait]
impl ProtocolModule for FtpModule {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn default_port(&self) -> u16 {
        21
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_budget: Duration,
    ) -> Result<AuthResult, ProtocolError> {
        let _ = self.passive;
        if timeout_budget.is_zero() {
            return Err(ProtocolError::Timeout);
        }
        let username = credential.username.as_str();
        let password = credential.password.as_deref().unwrap_or("");

        let result = timeout(timeout_budget, async {
            let connected = FtpClient::new()
                .connect(target, self.proxy.as_deref())
                .await?;
            let ready = connected.handshake().await?;
            let (outcome, client) = ready.login(username, password).await?;
            client.quit().await;
            Ok::<AuthResult, ProtocolError>(outcome)
        })
        .await
        .map_err(|_| ProtocolError::Timeout)??;

        Ok(result)
    }
}

async fn write_line(stream: &mut BufReader<TcpStream>, line: &str) -> Result<(), ProtocolError> {
    let writer = stream.get_mut();
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    writer
        .write_all(b"\r\n")
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    Ok(())
}

/// Read one FTP reply, tolerating CRLF or bare LF and RFC 959 multi-line continuations.
async fn read_reply(stream: &mut BufReader<TcpStream>) -> Result<(u16, String), ProtocolError> {
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
                "FTP peer closed during reply".into(),
            ));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if !body.is_empty() {
            body.push('\n');
        }
        body.push_str(trimmed);

        if let Some(expected) = expected_code {
            // RFC 959: continuation concludes when a line starts with expected code
            // followed by a space (or end of line). Intervening lines may be arbitrary text.
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
                "FTP reply line too short".into(),
            ));
        }
        let code: u16 = trimmed[..3]
            .parse()
            .map_err(|_| ProtocolError::HandshakeFailed("FTP reply missing status code".into()))?;

        if trimmed.as_bytes().get(3).copied() == Some(b'-') {
            expected_code = Some(code);
            continue;
        }

        return Ok((code, body));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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

    fn target(port: u16) -> Target {
        Target {
            host: "127.0.0.1".into(),
            port,
            ssl: false,
            path: None,
            ip: Some("127.0.0.1".parse().unwrap()),
        }
    }

    #[tokio::test]
    async fn authenticates_against_in_process_ftp_mock() {
        let (port, server) = spawn_script(vec![
            ">>220 welcome\r\n",
            "<<USER alice\r\n",
            ">>331 password required\r\n",
            "<<PASS secret\r\n",
            ">>230 login ok\r\n",
            "<<QUIT\r\n",
        ])
        .await;

        let module = FtpModule::new(false);
        let result = module
            .authenticate(
                &target(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("secret".into()),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_invalid_password() {
        let (port, server) = spawn_script(vec![
            ">>220 ready\r\n",
            "<<USER bob\r\n",
            ">>331 go ahead\r\n",
            "<<PASS wrong\r\n",
            ">>530 denied\r\n",
            "<<QUIT\r\n",
        ])
        .await;

        let module = FtpModule::default();
        let result = module
            .authenticate(
                &target(port),
                &Credential {
                    username: "bob".into(),
                    password: Some("wrong".into()),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Failure);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tolerates_multiline_banner_and_bare_lf() {
        let (port, server) = spawn_script(vec![
            ">>220-line one\n220-line two\n220 done\n",
            "<<USER root\r\n",
            ">>331 need pass\n",
            "<<PASS x\r\n",
            ">>230 ok\n",
            "<<QUIT\r\n",
        ])
        .await;

        let module = FtpModule::default();
        let result = module
            .authenticate(
                &target(port),
                &Credential {
                    username: "root".into(),
                    password: Some("x".into()),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn read_reply_parses_dash_continuations() {
        let (port, server) = spawn_script(vec![">>123-a\r\n123-b\r\n123 end\r\n"]).await;
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut reader = BufReader::new(stream);
        let (code, body) = read_reply(&mut reader).await.unwrap();
        assert_eq!(code, 123);
        assert!(body.contains("123-a"));
        assert!(body.contains("123 end"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tolerates_multiline_banner_with_unprefixed_intervening_lines() {
        let (port, server) = spawn_script(vec![
            ">>220-Welcome to Betterh FTP\n   Arbitrary descriptive text\n220 Service ready\n",
            "<<USER anon\r\n",
            ">>331 Send password\n",
            "<<PASS pass\r\n",
            ">>230 Login successful\n",
            "<<QUIT\r\n",
        ])
        .await;

        let module = FtpModule::default();
        let result = module
            .authenticate(
                &target(port),
                &Credential {
                    username: "anon".into(),
                    password: Some("pass".into()),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }
}
