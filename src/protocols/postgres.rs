// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! `PostgreSQL` Frontend/Backend Protocol 3.0 authentication with cleartext and MD5 password challenges.

use std::time::Duration;

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

const PROTOCOL_VERSION_3_0: u32 = 196_608; // (3 << 16) | 0

struct Disconnected;
struct Connected;

struct PostgresClient<State> {
    stream: Option<TcpStream>,
    _state: State,
}

impl PostgresClient<Disconnected> {
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
    ) -> Result<PostgresClient<Connected>, ProtocolError> {
        let addr = target.dial_addr();
        let stream = match proxy {
            None => TcpStream::connect(&addr)
                .await
                .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?,
            Some(proxy) => super::socks::connect_socks5(proxy, &addr).await?,
        };
        Ok(PostgresClient {
            stream: Some(stream),
            _state: Connected,
        })
    }
}

impl PostgresClient<Connected> {
    async fn authenticate(
        mut self,
        username: &str,
        password: &str,
        database: Option<&str>,
    ) -> Result<(AuthResult, PostgresClient<Connected>), ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("Postgres stream missing before auth".into()))?;

        // 1. Send StartupMessage
        let startup_pkt = build_startup_message(username, database);
        stream
            .write_all(&startup_pkt)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

        // 2. Process authentication challenges or error response
        loop {
            let (msg_type, payload) = read_message(stream).await?;
            match msg_type {
                b'R' => {
                    if payload.len() < 4 {
                        return Err(ProtocolError::HandshakeFailed(
                            "Postgres Authentication request payload too short".into(),
                        ));
                    }
                    let auth_type =
                        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    match auth_type {
                        0 => {
                            // AuthenticationOk
                            return Ok((AuthResult::Success, self));
                        }
                        3 => {
                            // AuthenticationCleartextPassword
                            let password_pkt = build_password_message(password);
                            stream.write_all(&password_pkt).await.map_err(|error| {
                                ProtocolError::ConnectionError(error.to_string())
                            })?;
                            stream.flush().await.map_err(|error| {
                                ProtocolError::ConnectionError(error.to_string())
                            })?;
                        }
                        5 => {
                            // AuthenticationMD5Password: 4-byte salt
                            if payload.len() < 8 {
                                return Err(ProtocolError::HandshakeFailed(
                                    "Postgres MD5 auth request missing 4-byte salt".into(),
                                ));
                            }
                            let salt: [u8; 4] = [payload[4], payload[5], payload[6], payload[7]];
                            let md5_hash = compute_pg_md5(username, password, salt);
                            let password_pkt = build_password_message(&md5_hash);
                            stream.write_all(&password_pkt).await.map_err(|error| {
                                ProtocolError::ConnectionError(error.to_string())
                            })?;
                            stream.flush().await.map_err(|error| {
                                ProtocolError::ConnectionError(error.to_string())
                            })?;
                        }
                        10 => {
                            return Ok((
                                AuthResult::Error(
                                    "Server requested unsupported SASL/SCRAM authentication".into(),
                                ),
                                self,
                            ));
                        }
                        other => {
                            return Ok((
                                AuthResult::Error(format!(
                                    "Unsupported Postgres auth type {other}"
                                )),
                                self,
                            ));
                        }
                    }
                }
                b'E' => {
                    let (sqlstate, message) = parse_error_response(&payload);
                    let result = map_pg_error(&sqlstate, &message);
                    return Ok((result, self));
                }
                b'S' | b'K' | b'Z' => {
                    // Ignore parameter status, backend key data, ready for query
                }
                other => {
                    return Ok((
                        AuthResult::Error(format!(
                            "Unexpected Postgres message type 0x{other:02x}"
                        )),
                        self,
                    ));
                }
            }
        }
    }

    async fn terminate(mut self) {
        if let Some(mut stream) = self.stream.take() {
            // Terminate: 'X' + length 4 (no body)
            let term_pkt = [b'X', 0, 0, 0, 4];
            let _ = stream.write_all(&term_pkt).await;
            let _ = stream.flush().await;
        }
    }
}

fn compute_pg_md5(username: &str, password: &str, salt: [u8; 4]) -> String {
    // Step 1: MD5(password + username)
    let mut ctx = md5::Context::new();
    ctx.consume(password.as_bytes());
    ctx.consume(username.as_bytes());
    let digest1 = ctx.compute();
    let hex1 = format!("{digest1:02x}");

    // Step 2: MD5(hex1 + salt)
    let mut ctx = md5::Context::new();
    ctx.consume(hex1.as_bytes());
    ctx.consume(salt);
    let digest2 = ctx.compute();
    format!("md5{digest2:02x}")
}

fn build_startup_message(username: &str, database: Option<&str>) -> Vec<u8> {
    let mut body = Vec::with_capacity(64);
    body.extend_from_slice(&PROTOCOL_VERSION_3_0.to_be_bytes());

    // key-value pair: user
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(username.as_bytes());
    body.push(0);

    // key-value pair: database (defaults to username if not provided)
    let db = database.unwrap_or(username);
    body.extend_from_slice(b"database\0");
    body.extend_from_slice(db.as_bytes());
    body.push(0);

    // terminating null byte
    body.push(0);

    let total_len = u32::try_from(body.len() + 4).unwrap_or(0);
    let mut packet = Vec::with_capacity(usize::try_from(total_len).unwrap_or(body.len() + 4));
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

fn build_password_message(password_text: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(password_text.len() + 1);
    body.extend_from_slice(password_text.as_bytes());
    body.push(0);

    let total_len = u32::try_from(body.len() + 4).unwrap_or(0);
    let mut packet = Vec::with_capacity(1 + usize::try_from(total_len).unwrap_or(body.len() + 4));
    packet.push(b'p');
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

fn parse_error_response(payload: &[u8]) -> (String, String) {
    let mut sqlstate = String::new();
    let mut message = String::new();

    let mut i = 0;
    while i < payload.len() {
        let field_type = payload[i];
        if field_type == 0 {
            break;
        }
        i += 1;
        let start = i;
        while i < payload.len() && payload[i] != 0 {
            i += 1;
        }
        let val = String::from_utf8_lossy(&payload[start..i]).to_string();
        if i < payload.len() {
            i += 1; // skip null
        }
        match field_type {
            b'C' => sqlstate = val,
            b'M' => message = val,
            _ => {}
        }
    }

    (sqlstate, message)
}

fn map_pg_error(sqlstate: &str, message: &str) -> AuthResult {
    match sqlstate {
        "28P01" | "28000" => AuthResult::Failure,
        "53300" | "53400" => AuthResult::RateLimited(Duration::from_secs(5)),
        _ => AuthResult::Error(format!("Postgres error {sqlstate}: {message}")),
    }
}

async fn read_message(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), ProtocolError> {
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

    let msg_type = header[0];
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    if length < 4 {
        return Err(ProtocolError::HandshakeFailed(
            "Invalid Postgres message length".into(),
        ));
    }
    let payload_len = usize::try_from(length - 4)
        .map_err(|_| ProtocolError::HandshakeFailed("Message length overflow".into()))?;

    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    }

    Ok((msg_type, payload))
}

/// Native `PostgreSQL` authentication module (Frontend/Backend 3.0).
#[derive(Debug, Default, Clone)]
pub struct PostgresModule {
    pub database: Option<String>,
    proxy: Option<String>,
}

impl PostgresModule {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            database: None,
            proxy: None,
        }
    }

    #[must_use]
    pub fn with_database(mut self, database: Option<String>) -> Self {
        self.database = database;
        self
    }

    #[must_use]
    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = proxy;
        self
    }
}

#[async_trait]
impl ProtocolModule for PostgresModule {
    fn name(&self) -> &'static str {
        "postgres"
    }

    fn default_port(&self) -> u16 {
        5432
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
        let database = self.database.as_deref();

        let result = timeout(timeout_budget, async {
            let connected = PostgresClient::new()
                .connect(target, self.proxy.as_deref())
                .await?;
            let (outcome, client) = connected.authenticate(username, password, database).await?;
            client.terminate().await;
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

    #[tokio::test]
    async fn authenticates_postgres_md5_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let salt: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // 1. Read StartupMessage
            let mut len_buf = [0u8; 4];
            socket.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut startup_body = vec![0u8; len - 4];
            socket.read_exact(&mut startup_body).await.unwrap();
            assert!(startup_body.windows(5).any(|w| w == b"user\0"));

            // 2. Send AuthenticationMD5Password challenge (type 'R', len 12, auth_type 5, 4-byte salt)
            let mut challenge = Vec::new();
            challenge.push(b'R');
            challenge.extend_from_slice(&12u32.to_be_bytes());
            challenge.extend_from_slice(&5u32.to_be_bytes());
            challenge.extend_from_slice(&salt);
            socket.write_all(&challenge).await.unwrap();

            // 3. Read client 'p' PasswordMessage
            let mut p_header = [0u8; 5];
            socket.read_exact(&mut p_header).await.unwrap();
            assert_eq!(p_header[0], b'p');
            let p_len = (u32::from_be_bytes([p_header[1], p_header[2], p_header[3], p_header[4]])
                - 4) as usize;
            let mut p_body = vec![0u8; p_len];
            socket.read_exact(&mut p_body).await.unwrap();

            let expected_hash = compute_pg_md5("postgres", "secret", salt);
            assert_eq!(
                String::from_utf8_lossy(&p_body[..p_body.len() - 1]),
                expected_hash
            );

            // 4. Send AuthenticationOk (type 'R', len 8, auth_type 0)
            let mut ok_msg = Vec::new();
            ok_msg.push(b'R');
            ok_msg.extend_from_slice(&8u32.to_be_bytes());
            ok_msg.extend_from_slice(&0u32.to_be_bytes());
            socket.write_all(&ok_msg).await.unwrap();

            // 5. Read Terminate ('X')
            let mut term = [0u8; 5];
            let _ = socket.read_exact(&mut term).await;
        });

        let module = PostgresModule::new();
        let credential = Credential {
            username: "postgres".into(),
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
    async fn handles_postgres_password_failure_28p01() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let salt: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Read StartupMessage
            let mut len_buf = [0u8; 4];
            socket.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut startup_body = vec![0u8; len - 4];
            socket.read_exact(&mut startup_body).await.unwrap();

            // Send AuthenticationMD5Password challenge
            let mut challenge = Vec::new();
            challenge.push(b'R');
            challenge.extend_from_slice(&12u32.to_be_bytes());
            challenge.extend_from_slice(&5u32.to_be_bytes());
            challenge.extend_from_slice(&salt);
            socket.write_all(&challenge).await.unwrap();

            // Read client 'p' PasswordMessage
            let mut p_header = [0u8; 5];
            socket.read_exact(&mut p_header).await.unwrap();
            let p_len = (u32::from_be_bytes([p_header[1], p_header[2], p_header[3], p_header[4]])
                - 4) as usize;
            let mut p_body = vec![0u8; p_len];
            socket.read_exact(&mut p_body).await.unwrap();

            // Send ErrorResponse ('E') with SQLSTATE 28P01
            let mut err_body = Vec::new();
            err_body.push(b'S');
            err_body.extend_from_slice(b"FATAL\0");
            err_body.push(b'C');
            err_body.extend_from_slice(b"28P01\0");
            err_body.push(b'M');
            err_body.extend_from_slice(b"password authentication failed for user 'admin'\0");
            err_body.push(0);

            let err_len = u32::try_from(err_body.len() + 4).unwrap_or(0);
            let mut err_msg = Vec::new();
            err_msg.push(b'E');
            err_msg.extend_from_slice(&err_len.to_be_bytes());
            err_msg.extend_from_slice(&err_body);
            socket.write_all(&err_msg).await.unwrap();
        });

        let module = PostgresModule::new();
        let credential = Credential {
            username: "admin".into(),
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
    async fn handles_postgres_too_many_connections_53300() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Read StartupMessage
            let mut len_buf = [0u8; 4];
            socket.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut startup_body = vec![0u8; len - 4];
            socket.read_exact(&mut startup_body).await.unwrap();

            // Server immediately rejects with 53300 (too_many_connections)
            let mut err_body = Vec::new();
            err_body.push(b'S');
            err_body.extend_from_slice(b"FATAL\0");
            err_body.push(b'C');
            err_body.extend_from_slice(b"53300\0");
            err_body.push(b'M');
            err_body.extend_from_slice(b"sorry, too many clients already\0");
            err_body.push(0);

            let err_len = u32::try_from(err_body.len() + 4).unwrap_or(0);
            let mut err_msg = Vec::new();
            err_msg.push(b'E');
            err_msg.extend_from_slice(&err_len.to_be_bytes());
            err_msg.extend_from_slice(&err_body);
            socket.write_all(&err_msg).await.unwrap();
        });

        let module = PostgresModule::new();
        let credential = Credential {
            username: "admin".into(),
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
