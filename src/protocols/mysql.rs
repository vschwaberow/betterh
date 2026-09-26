// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! `MySQL` authentication over Tokio TCP with native wire packet framing and `mysql_native_password` scramble.

use std::time::Duration;

use async_trait::async_trait;
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_FOUND_ROWS: u32 = 0x0000_0002;
const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_INTERACTIVE: u32 = 0x0000_0400;
const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

struct Disconnected;
struct Connected;
struct Handshaked {
    salt: [u8; 20],
}

struct MysqlClient<State> {
    stream: Option<TcpStream>,
    state: State,
}

impl MysqlClient<Disconnected> {
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
    ) -> Result<MysqlClient<Connected>, ProtocolError> {
        let addr = target.dial_addr();
        let stream = match proxy {
            None => TcpStream::connect(&addr)
                .await
                .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?,
            Some(proxy) => super::socks::connect_socks5(proxy, &addr).await?,
        };
        Ok(MysqlClient {
            stream: Some(stream),
            state: Connected,
        })
    }
}

impl MysqlClient<Connected> {
    async fn handshake(mut self) -> Result<MysqlClient<Handshaked>, ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("MySQL stream missing after connect".into()))?;

        let (_seq, payload) = read_packet(stream).await?;
        if payload.is_empty() {
            return Err(ProtocolError::HandshakeFailed(
                "Empty handshake packet received from MySQL server".into(),
            ));
        }

        // Check if server sent an ERR packet immediately (e.g. host blocked or too many connections)
        if payload[0] == 0xFF {
            let (code, msg) = parse_err_packet(&payload)?;
            return Err(ProtocolError::HandshakeFailed(format!(
                "MySQL error during handshake {code}: {msg}"
            )));
        }

        let salt = parse_handshake_v10(&payload)?;
        Ok(MysqlClient {
            stream: self.stream.take(),
            state: Handshaked { salt },
        })
    }
}

impl MysqlClient<Handshaked> {
    async fn login(
        mut self,
        username: &str,
        password: &str,
        database: Option<&str>,
    ) -> Result<(AuthResult, MysqlClient<Handshaked>), ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("MySQL stream missing before login".into()))?;

        let scramble = scramble_password(password, &self.state.salt);
        let response_packet = build_handshake_response41(username, &scramble, database, 1);
        stream
            .write_all(&response_packet)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

        let (_seq, reply) = read_packet(stream).await?;
        if reply.is_empty() {
            return Err(ProtocolError::HandshakeFailed(
                "Empty auth reply from MySQL server".into(),
            ));
        }

        let result = match reply[0] {
            0x00 => AuthResult::Success,
            0xFF => {
                let (code, msg) = parse_err_packet(&reply)?;
                map_mysql_err(code, &msg)
            }
            0xFE => {
                // AuthSwitchRequest: server requests different auth plugin or new salt
                AuthResult::Error("Server requested unsupported AuthSwitch".into())
            }
            other => AuthResult::Error(format!("Unexpected MySQL auth reply byte: 0x{other:02x}")),
        };

        Ok((result, self))
    }

    async fn quit(mut self) {
        if let Some(mut stream) = self.stream.take() {
            // COM_QUIT: length 1, sequence 0, payload 0x01
            let quit_packet = [0x01, 0x00, 0x00, 0x00, 0x01];
            let _ = stream.write_all(&quit_packet).await;
            let _ = stream.flush().await;
        }
    }
}

fn scramble_password(password: &str, salt: &[u8; 20]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    // SHA1(password)
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let h1 = hasher.finalize();

    // SHA1(SHA1(password))
    let mut hasher = Sha1::new();
    hasher.update(h1);
    let h2 = hasher.finalize();

    // SHA1(salt + SHA1(SHA1(password)))
    let mut hasher = Sha1::new();
    hasher.update(salt);
    hasher.update(h2);
    let h3 = hasher.finalize();

    // h1 ^ h3
    let mut scramble = vec![0u8; 20];
    for i in 0..20 {
        scramble[i] = h1[i] ^ h3[i];
    }
    scramble
}

fn build_handshake_response41(
    username: &str,
    scramble: &[u8],
    database: Option<&str>,
    sequence_id: u8,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(128);

    let with_db = if database.is_some() {
        CLIENT_CONNECT_WITH_DB
    } else {
        0
    };
    let client_flags = CLIENT_LONG_PASSWORD
        | CLIENT_FOUND_ROWS
        | CLIENT_LONG_FLAG
        | CLIENT_PROTOCOL_41
        | CLIENT_INTERACTIVE
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
        | with_db;

    // 1. Client capability flags (4 bytes)
    payload.extend_from_slice(&client_flags.to_le_bytes());
    // 2. Max packet size (4 bytes) - 16MB
    payload.extend_from_slice(&(16 * 1024 * 1024u32).to_le_bytes());
    // 3. Character set (1 byte) - 45 for utf8mb4
    payload.push(45);
    // 4. Reserved (23 bytes zeros)
    payload.extend_from_slice(&[0u8; 23]);
    // 5. Username (null-terminated)
    payload.extend_from_slice(username.as_bytes());
    payload.push(0);
    // 6. Auth response (1-byte length prefix + scramble)
    let scramble_len = u8::try_from(scramble.len()).unwrap_or(0);
    payload.push(scramble_len);
    payload.extend_from_slice(scramble);
    // 7. Database name if provided (null-terminated)
    if let Some(db) = database {
        payload.extend_from_slice(db.as_bytes());
        payload.push(0);
    }
    // 8. Auth plugin name (null-terminated)
    payload.extend_from_slice(b"mysql_native_password\0");

    let payload_len = u32::try_from(payload.len()).unwrap_or(0);
    let len_bytes = payload_len.to_le_bytes();

    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(&len_bytes[..3]);
    packet.push(sequence_id);
    packet.extend_from_slice(&payload);
    packet
}

fn parse_handshake_v10(payload: &[u8]) -> Result<[u8; 20], ProtocolError> {
    if payload.len() < 30 {
        return Err(ProtocolError::HandshakeFailed(
            "MySQL HandshakeV10 packet is too short".into(),
        ));
    }
    // Protocol version must be 10 (0x0A)
    if payload[0] != 0x0A {
        return Err(ProtocolError::HandshakeFailed(format!(
            "Unsupported MySQL protocol version: 0x{:02x}",
            payload[0]
        )));
    }

    // Find end of server version string (null-terminated)
    let mut offset = 1;
    while offset < payload.len() && payload[offset] != 0 {
        offset += 1;
    }
    if offset >= payload.len() {
        return Err(ProtocolError::HandshakeFailed(
            "Missing null-terminator in MySQL server version".into(),
        ));
    }
    offset += 1; // skip null byte

    // Skip connection_id (4 bytes)
    if offset + 4 > payload.len() {
        return Err(ProtocolError::HandshakeFailed(
            "Truncated MySQL HandshakeV10 before connection ID".into(),
        ));
    }
    offset += 4;

    // Auth plugin data part 1 (8 bytes)
    if offset + 8 > payload.len() {
        return Err(ProtocolError::HandshakeFailed(
            "Truncated MySQL HandshakeV10 before auth data part 1".into(),
        ));
    }
    let mut salt = [0u8; 20];
    salt[..8].copy_from_slice(&payload[offset..offset + 8]);
    offset += 8;

    // Skip filler (1 byte)
    offset += 1;

    // Read lower capability flags (2 bytes)
    if offset + 2 > payload.len() {
        // Very old server with only 8 bytes salt
        return Ok(salt);
    }
    let cap_lower = u16::from_le_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;

    if offset + 16 > payload.len() {
        return Ok(salt);
    }
    // Skip character set (1 byte) + status flags (2 bytes)
    offset += 3;
    let cap_upper = u16::from_le_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;
    let capabilities = u32::from(cap_lower) | (u32::from(cap_upper) << 16);

    let auth_data_len = usize::from(payload[offset]);
    offset += 1;

    // Skip reserved (10 bytes)
    offset += 10;

    // Auth plugin data part 2
    if (capabilities & CLIENT_SECURE_CONNECTION != 0 || capabilities & CLIENT_PLUGIN_AUTH != 0)
        && offset < payload.len()
    {
        let part2_len = if auth_data_len > 8 {
            (auth_data_len - 8).min(13)
        } else {
            12
        };
        let available = (payload.len() - offset).min(part2_len);
        let to_copy = available.min(12);
        salt[8..8 + to_copy].copy_from_slice(&payload[offset..offset + to_copy]);
    }

    Ok(salt)
}

fn parse_err_packet(payload: &[u8]) -> Result<(u16, String), ProtocolError> {
    if payload.len() < 3 {
        return Err(ProtocolError::HandshakeFailed(
            "MySQL ERR packet too short".into(),
        ));
    }
    let code = u16::from_le_bytes([payload[1], payload[2]]);
    let message = if payload.len() > 3 {
        let msg_bytes = if payload.len() > 9 && payload[3] == b'#' {
            &payload[9..] // skip '#' and 5-byte SQLSTATE
        } else {
            &payload[3..]
        };
        String::from_utf8_lossy(msg_bytes).to_string()
    } else {
        String::new()
    };
    Ok((code, message))
}

fn map_mysql_err(code: u16, msg: &str) -> AuthResult {
    match code {
        1045 => AuthResult::Failure,
        1129 => AuthResult::RateLimited(Duration::from_mins(1)),
        1040 => AuthResult::RateLimited(Duration::from_secs(5)),
        _ => AuthResult::Error(format!("MySQL error {code}: {msg}")),
    }
}

async fn read_packet(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), ProtocolError> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

    let length =
        usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
    let sequence_id = header[3];

    let mut payload = vec![0u8; length];
    if length > 0 {
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    }

    Ok((sequence_id, payload))
}

/// Native `MySQL` authentication module (`mysql_native_password`).
#[derive(Debug, Default, Clone)]
pub struct MysqlModule {
    pub database: Option<String>,
    proxy: Option<String>,
}

impl MysqlModule {
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
impl ProtocolModule for MysqlModule {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn default_port(&self) -> u16 {
        3306
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
            let connected = MysqlClient::new()
                .connect(target, self.proxy.as_deref())
                .await?;
            let handshaked = connected.handshake().await?;
            let (outcome, client) = handshaked.login(username, password, database).await?;
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

    fn build_mock_handshake_v10(salt: &[u8; 20]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(0x0A); // protocol 10
        payload.extend_from_slice(b"8.0.35\0"); // server version
        payload.extend_from_slice(&1234u32.to_le_bytes()); // connection id
        payload.extend_from_slice(&salt[..8]); // salt part 1
        payload.push(0x00); // filler

        let cap_lower = u16::try_from(
            CLIENT_LONG_PASSWORD
                | CLIENT_FOUND_ROWS
                | CLIENT_LONG_FLAG
                | CLIENT_PROTOCOL_41
                | CLIENT_SECURE_CONNECTION,
        )
        .unwrap_or(0);
        payload.extend_from_slice(&cap_lower.to_le_bytes());
        payload.push(45); // charset
        payload.extend_from_slice(&0u16.to_le_bytes()); // status flags

        let cap_upper = u16::try_from(CLIENT_PLUGIN_AUTH >> 16).unwrap_or(0);
        payload.extend_from_slice(&cap_upper.to_le_bytes());
        payload.push(21); // auth data len (20 + 1)
        payload.extend_from_slice(&[0u8; 10]); // reserved

        payload.extend_from_slice(&salt[8..20]); // salt part 2
        payload.push(0x00); // trailing null
        payload.extend_from_slice(b"mysql_native_password\0");

        let len = u32::try_from(payload.len()).unwrap_or(0).to_le_bytes();
        let mut packet = Vec::new();
        packet.extend_from_slice(&len[..3]);
        packet.push(0); // sequence 0
        packet.extend_from_slice(&payload);
        packet
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
    async fn authenticates_mysql_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let salt: [u8; 20] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let handshake_pkt = build_mock_handshake_v10(&salt);
            socket.write_all(&handshake_pkt).await.unwrap();

            // Read client response
            let mut header = [0u8; 4];
            socket.read_exact(&mut header).await.unwrap();
            let len = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            assert_eq!(header[3], 1); // seq 1
            let mut payload = vec![0u8; len];
            socket.read_exact(&mut payload).await.unwrap();

            // Verify username in payload
            assert!(payload.windows(5).any(|w| w == b"root\0"));

            // Verify scramble calculation matches expected
            let expected_scramble = scramble_password("secret", &salt);
            assert!(
                payload
                    .windows(expected_scramble.len())
                    .any(|w| w == expected_scramble.as_slice())
            );

            // Send OK packet (seq 2, 0x00 OK)
            let ok_packet = [
                0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            ];
            socket.write_all(&ok_packet).await.unwrap();

            // Read COM_QUIT
            let mut quit = [0u8; 5];
            let _ = socket.read_exact(&mut quit).await;
        });

        let module = MysqlModule::new();
        let credential = Credential {
            username: "root".into(),
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
    async fn handles_mysql_access_denied_1045() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let salt: [u8; 20] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let handshake_pkt = build_mock_handshake_v10(&salt);
            socket.write_all(&handshake_pkt).await.unwrap();

            // Read client response
            let mut header = [0u8; 4];
            socket.read_exact(&mut header).await.unwrap();
            let len = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            let mut payload = vec![0u8; len];
            socket.read_exact(&mut payload).await.unwrap();

            // Send ERR packet code 1045
            let mut err_payload = Vec::new();
            err_payload.push(0xFF);
            err_payload.extend_from_slice(&1045u16.to_le_bytes());
            err_payload.push(b'#');
            err_payload.extend_from_slice(b"28000");
            err_payload.extend_from_slice(b"Access denied for user 'root'@'localhost'");

            let len = u32::try_from(err_payload.len()).unwrap_or(0).to_le_bytes();
            let mut err_packet = Vec::new();
            err_packet.extend_from_slice(&len[..3]);
            err_packet.push(2);
            err_packet.extend_from_slice(&err_payload);
            socket.write_all(&err_packet).await.unwrap();
        });

        let module = MysqlModule::new();
        let credential = Credential {
            username: "root".into(),
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
    async fn handles_mysql_host_blocked_1129() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Server immediately rejects with 1129 host blocked
            let mut err_payload = Vec::new();
            err_payload.push(0xFF);
            err_payload.extend_from_slice(&1129u16.to_le_bytes());
            err_payload.push(b'#');
            err_payload.extend_from_slice(b"HY000");
            err_payload.extend_from_slice(b"Host '127.0.0.1' is blocked because of many errors");

            let len = u32::try_from(err_payload.len()).unwrap_or(0).to_le_bytes();
            let mut err_packet = Vec::new();
            err_packet.extend_from_slice(&len[..3]);
            err_packet.push(0);
            err_packet.extend_from_slice(&err_payload);
            socket.write_all(&err_packet).await.unwrap();
        });

        let module = MysqlModule::new();
        let credential = Credential {
            username: "root".into(),
            password: Some("secret".into()),
        };

        let err = module
            .authenticate(&target(port), &credential, Duration::from_secs(5))
            .await
            .unwrap_err();

        assert!(matches!(err, ProtocolError::HandshakeFailed(_)));
        server.await.unwrap();
    }
}
