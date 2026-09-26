// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Redis RESP authentication (`AUTH` inline / ACL) over Tokio TCP.

use std::time::Duration;

use async_trait::async_trait;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

struct Disconnected;
struct Connected;

struct RedisClient<State> {
    stream: Option<BufReader<TcpStream>>,
    _state: State,
}

impl RedisClient<Disconnected> {
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
    ) -> Result<RedisClient<Connected>, ProtocolError> {
        let addr = target.dial_addr();
        let stream = match proxy {
            None => TcpStream::connect(&addr)
                .await
                .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?,
            Some(proxy) => super::socks::connect_socks5(proxy, &addr).await?,
        };
        Ok(RedisClient {
            stream: Some(BufReader::new(stream)),
            _state: Connected,
        })
    }
}

impl RedisClient<Connected> {
    async fn ping(&mut self) -> Result<String, ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("Redis stream missing before PING".into()))?;
        write_command(stream, &["PING"]).await?;
        read_line(stream).await
    }

    async fn authenticate(
        mut self,
        username: &str,
        password: &str,
    ) -> Result<(AuthResult, RedisClient<Connected>), ProtocolError> {
        // Pre-flight PING: +PONG (open) or -NOAUTH (auth required) are both fine.
        let ping_reply = self.ping().await?;
        if let Some(result) = map_rate_limited(&ping_reply) {
            return Ok((result, self));
        }

        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("Redis stream missing before AUTH".into()))?;

        if username.is_empty() {
            write_command(stream, &["AUTH", password]).await?;
        } else {
            write_command(stream, &["AUTH", username, password]).await?;
        }
        let reply = read_line(stream).await?;
        Ok((map_auth_reply(&reply), self))
    }

    async fn quit(mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = write_command(&mut stream, &["QUIT"]).await;
        }
    }
}

fn encode_command(args: &[&str]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for arg in args {
        buf.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        buf.extend_from_slice(arg.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf
}

async fn write_command(
    stream: &mut BufReader<TcpStream>,
    args: &[&str],
) -> Result<(), ProtocolError> {
    let packet = encode_command(args);
    stream
        .write_all(&packet)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    Ok(())
}

async fn read_line(stream: &mut BufReader<TcpStream>) -> Result<String, ProtocolError> {
    let mut line = String::new();
    let n = stream
        .read_line(&mut line)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    if n == 0 {
        return Err(ProtocolError::ConnectionError(
            "Redis peer closed the connection".into(),
        ));
    }
    Ok(line)
}

fn normalize_reply(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

fn map_rate_limited(line: &str) -> Option<AuthResult> {
    let reply = normalize_reply(line);
    let err = reply.strip_prefix('-')?;
    if err.to_ascii_lowercase().contains("max number of clients") {
        Some(AuthResult::RateLimited(Duration::from_secs(5)))
    } else {
        None
    }
}

fn map_auth_reply(line: &str) -> AuthResult {
    let reply = normalize_reply(line);
    if reply == "+OK" {
        return AuthResult::Success;
    }
    if let Some(result) = map_rate_limited(reply) {
        return result;
    }
    let Some(err) = reply.strip_prefix('-') else {
        return AuthResult::Error(format!("Unexpected Redis reply: {reply}"));
    };
    let lower = err.to_ascii_lowercase();
    if lower.starts_with("wrongpass")
        || lower.contains("invalid password")
        || lower.contains("invalid username-password")
        || lower.contains("wrong pass")
    {
        return AuthResult::Failure;
    }
    AuthResult::Error(format!("Redis error: {err}"))
}

/// Redis RESP authentication module.
#[derive(Debug, Default, Clone)]
pub struct RedisModule {
    proxy: Option<String>,
}

impl RedisModule {
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
impl ProtocolModule for RedisModule {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn default_port(&self) -> u16 {
        6379
    }

    async fn probe(&self, target: &Target) -> Result<(), ProtocolError> {
        let mut client = RedisClient::new()
            .connect(target, self.proxy.as_deref())
            .await?;
        let reply = client.ping().await?;
        let normalized = normalize_reply(&reply);
        if normalized == "+PONG"
            || normalized
                .strip_prefix('-')
                .is_some_and(|err| err.to_ascii_uppercase().starts_with("NOAUTH"))
        {
            client.quit().await;
            return Ok(());
        }
        if map_rate_limited(&reply).is_some() {
            client.quit().await;
            return Err(ProtocolError::HandshakeFailed(
                "Redis rejected probe: max number of clients reached".into(),
            ));
        }
        client.quit().await;
        Err(ProtocolError::HandshakeFailed(format!(
            "Unexpected Redis PING reply: {normalized}"
        )))
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
            let connected = RedisClient::new()
                .connect(target, self.proxy.as_deref())
                .await?;
            let (outcome, client) = connected.authenticate(username, password).await?;
            client.quit().await;
            Ok::<AuthResult, ProtocolError>(outcome)
        })
        .await
        .map_err(|_| ProtocolError::Timeout)??;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

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

    async fn expect_command(socket: &mut tokio::net::TcpStream, args: &[&str]) {
        let expected = encode_command(args);
        let mut buf = vec![0u8; expected.len()];
        tokio::io::AsyncReadExt::read_exact(socket, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, expected);
    }

    #[tokio::test]
    async fn authenticates_inline_password_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            expect_command(&mut socket, &["PING"]).await;
            tokio::io::AsyncWriteExt::write_all(&mut socket, b"+PONG\r\n")
                .await
                .unwrap();
            expect_command(&mut socket, &["AUTH", "s3cret"]).await;
            tokio::io::AsyncWriteExt::write_all(&mut socket, b"+OK\r\n")
                .await
                .unwrap();
            expect_command(&mut socket, &["QUIT"]).await;
        });

        let module = RedisModule::new();
        let credential = Credential {
            username: String::new(),
            password: Some("s3cret".into()),
        };
        let result = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn authenticates_acl_username_password_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            expect_command(&mut socket, &["PING"]).await;
            tokio::io::AsyncWriteExt::write_all(
                &mut socket,
                b"-NOAUTH Authentication required.\r\n",
            )
            .await
            .unwrap();
            expect_command(&mut socket, &["AUTH", "alice", "s3cret"]).await;
            tokio::io::AsyncWriteExt::write_all(&mut socket, b"+OK\r\n")
                .await
                .unwrap();
            expect_command(&mut socket, &["QUIT"]).await;
        });

        let module = RedisModule::new();
        let credential = Credential {
            username: "alice".into(),
            password: Some("s3cret".into()),
        };
        let result = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handles_wrongpass_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            expect_command(&mut socket, &["PING"]).await;
            tokio::io::AsyncWriteExt::write_all(&mut socket, b"+PONG\r\n")
                .await
                .unwrap();
            expect_command(&mut socket, &["AUTH", "wrong"]).await;
            tokio::io::AsyncWriteExt::write_all(
                &mut socket,
                b"-WRONGPASS invalid username-password pair\r\n",
            )
            .await
            .unwrap();
            expect_command(&mut socket, &["QUIT"]).await;
        });

        let module = RedisModule::new();
        let credential = Credential {
            username: String::new(),
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
    async fn handles_max_clients_as_rate_limited() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            expect_command(&mut socket, &["PING"]).await;
            tokio::io::AsyncWriteExt::write_all(
                &mut socket,
                b"-ERR max number of clients reached\r\n",
            )
            .await
            .unwrap();
            expect_command(&mut socket, &["QUIT"]).await;
        });

        let module = RedisModule::new();
        let credential = Credential {
            username: "alice".into(),
            password: Some("s3cret".into()),
        };
        let result = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result, AuthResult::RateLimited(Duration::from_secs(5)));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn probe_accepts_pong_and_noauth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            expect_command(&mut socket, &["PING"]).await;
            tokio::io::AsyncWriteExt::write_all(&mut socket, b"+PONG\r\n")
                .await
                .unwrap();
            expect_command(&mut socket, &["QUIT"]).await;
        });

        RedisModule::new().probe(&target(port)).await.unwrap();
        server.await.unwrap();
    }
}
