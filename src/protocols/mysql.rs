// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! `MySQL` authentication over Tokio TCP with native wire packet framing,
//! `mysql_native_password`, and `caching_sha2_password`.

use std::time::Duration;

use async_trait::async_trait;
use rand::rngs::OsRng;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha1::{Digest, Sha1};
use sha2::Sha256;
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

const AUTH_MORE_DATA: u8 = 0x01;
const CACHING_SHA2_FAST_AUTH: u8 = 0x03;
const CACHING_SHA2_FULL_AUTH: u8 = 0x04;
const REQUEST_PUBLIC_KEY: u8 = 0x02;

const PLUGIN_NATIVE: &str = "mysql_native_password";
const PLUGIN_CACHING_SHA2: &str = "caching_sha2_password";

struct Disconnected;
struct Connected;
struct Handshaked {
    salt: [u8; 20],
    plugin: String,
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

        let (salt, plugin) = parse_handshake_v10(&payload)?;
        Ok(MysqlClient {
            stream: self.stream.take(),
            state: Handshaked { salt, plugin },
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

        let scramble = scramble_for_plugin(&self.state.plugin, password, &self.state.salt)?;
        let response_packet =
            build_handshake_response41(username, &scramble, database, 1, &self.state.plugin);
        stream
            .write_all(&response_packet)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

        let result = complete_authentication(
            stream,
            password,
            &mut self.state.salt,
            &mut self.state.plugin,
        )
        .await?;

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

async fn complete_authentication(
    stream: &mut TcpStream,
    password: &str,
    salt: &mut [u8; 20],
    plugin: &mut String,
) -> Result<AuthResult, ProtocolError> {
    loop {
        let (seq, reply) = read_packet(stream).await?;
        if reply.is_empty() {
            return Err(ProtocolError::HandshakeFailed(
                "Empty auth reply from MySQL server".into(),
            ));
        }

        match reply[0] {
            0x00 => return Ok(AuthResult::Success),
            0xFF => {
                let (code, msg) = parse_err_packet(&reply)?;
                return Ok(map_mysql_err(code, &msg));
            }
            0xFE => {
                // AuthSwitchRequest: plugin name + new salt.
                let (new_plugin, new_salt) = parse_auth_switch(&reply)?;
                *plugin = new_plugin;
                *salt = new_salt;
                let scramble = scramble_for_plugin(plugin, password, salt)?;
                write_packet(stream, seq.wrapping_add(1), &scramble).await?;
            }
            AUTH_MORE_DATA => {
                let status = reply.get(1).copied().unwrap_or(0);
                match status {
                    CACHING_SHA2_FAST_AUTH => {
                        // Fast auth succeeded; OK packet follows.
                    }
                    CACHING_SHA2_FULL_AUTH => {
                        perform_caching_sha2_full_auth(stream, password, salt, seq.wrapping_add(1))
                            .await?;
                    }
                    _ if reply.len() > 1 => {
                        return Ok(AuthResult::Error(format!(
                            "Unexpected MySQL AuthMoreData status: 0x{status:02x}"
                        )));
                    }
                    _ => {
                        return Ok(AuthResult::Error(
                            "Empty MySQL AuthMoreData during authentication".into(),
                        ));
                    }
                }
            }
            other => {
                return Ok(AuthResult::Error(format!(
                    "Unexpected MySQL auth reply byte: 0x{other:02x}"
                )));
            }
        }
    }
}

async fn perform_caching_sha2_full_auth(
    stream: &mut TcpStream,
    password: &str,
    salt: &[u8; 20],
    seq: u8,
) -> Result<(), ProtocolError> {
    // Non-TLS path: request server RSA public key, then send OAEP-encrypted password.
    write_packet(stream, seq, &[REQUEST_PUBLIC_KEY]).await?;
    let (key_seq, key_reply) = read_packet(stream).await?;
    if key_reply.first().copied() != Some(AUTH_MORE_DATA) || key_reply.len() < 2 {
        return Err(ProtocolError::HandshakeFailed(
            "MySQL server did not return an RSA public key for full auth".into(),
        ));
    }
    let pem = std::str::from_utf8(&key_reply[1..]).map_err(|error| {
        ProtocolError::HandshakeFailed(format!("invalid MySQL RSA public key encoding: {error}"))
    })?;
    let encrypted = encrypt_password_rsa(password, salt, pem)?;
    write_packet(stream, key_seq.wrapping_add(1), &encrypted).await?;
    Ok(())
}

fn scramble_for_plugin(
    plugin: &str,
    password: &str,
    salt: &[u8; 20],
) -> Result<Vec<u8>, ProtocolError> {
    match plugin {
        PLUGIN_NATIVE => Ok(scramble_native_password(password, salt)),
        PLUGIN_CACHING_SHA2 => Ok(scramble_caching_sha2(password, salt)),
        other => Err(ProtocolError::HandshakeFailed(format!(
            "unsupported MySQL auth plugin: {other}"
        ))),
    }
}

fn scramble_native_password(password: &str, salt: &[u8; 20]) -> Vec<u8> {
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

fn scramble_caching_sha2(password: &str, salt: &[u8; 20]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    // scramble = SHA256(password) ⊕ SHA256(SHA256(SHA256(password)) ∥ salt)
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let message1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(message1);
    let message1_hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(message1_hash);
    hasher.update(salt);
    let message2 = hasher.finalize();

    message1
        .iter()
        .zip(message2.iter())
        .map(|(left, right)| left ^ right)
        .collect()
}

fn encrypt_password_rsa(
    password: &str,
    salt: &[u8; 20],
    pem: &str,
) -> Result<Vec<u8>, ProtocolError> {
    let public_key = RsaPublicKey::from_public_key_pem(pem).map_err(|error| {
        ProtocolError::HandshakeFailed(format!("failed to parse MySQL RSA public key: {error}"))
    })?;

    let mut plain = password.as_bytes().to_vec();
    plain.push(0);
    for (index, byte) in plain.iter_mut().enumerate() {
        *byte ^= salt[index % salt.len()];
    }

    let padding = Oaep::new::<Sha1>();
    public_key
        .encrypt(&mut OsRng, padding, &plain)
        .map_err(|error| {
            ProtocolError::HandshakeFailed(format!("MySQL RSA-OAEP encrypt failed: {error}"))
        })
}

fn build_handshake_response41(
    username: &str,
    scramble: &[u8],
    database: Option<&str>,
    sequence_id: u8,
    plugin: &str,
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
    payload.extend_from_slice(plugin.as_bytes());
    payload.push(0);

    let payload_len = u32::try_from(payload.len()).unwrap_or(0);
    let len_bytes = payload_len.to_le_bytes();

    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(&len_bytes[..3]);
    packet.push(sequence_id);
    packet.extend_from_slice(&payload);
    packet
}

fn parse_handshake_v10(payload: &[u8]) -> Result<([u8; 20], String), ProtocolError> {
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
        return Ok((salt, PLUGIN_NATIVE.to_owned()));
    }
    let cap_lower = u16::from_le_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;

    if offset + 16 > payload.len() {
        return Ok((salt, PLUGIN_NATIVE.to_owned()));
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
        offset += available;
    }

    let plugin = if capabilities & CLIENT_PLUGIN_AUTH != 0 && offset < payload.len() {
        // Skip trailing NUL of auth data if still present.
        if payload[offset] == 0 {
            offset += 1;
        }
        let end = payload[offset..]
            .iter()
            .position(|&byte| byte == 0)
            .map_or(payload.len(), |index| offset + index);
        let name = std::str::from_utf8(&payload[offset..end]).unwrap_or(PLUGIN_NATIVE);
        if name.is_empty() {
            PLUGIN_NATIVE.to_owned()
        } else {
            name.to_owned()
        }
    } else {
        PLUGIN_NATIVE.to_owned()
    };

    Ok((salt, plugin))
}

fn parse_auth_switch(payload: &[u8]) -> Result<(String, [u8; 20]), ProtocolError> {
    // 0xFE + plugin_name\0 + auth plugin data (salt, often 20 bytes + NUL)
    if payload.len() < 2 || payload[0] != 0xFE {
        return Err(ProtocolError::HandshakeFailed(
            "Invalid MySQL AuthSwitchRequest".into(),
        ));
    }
    let mut offset = 1;
    let name_end = payload[offset..]
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| {
            ProtocolError::HandshakeFailed("AuthSwitchRequest missing plugin name".into())
        })?;
    let plugin = std::str::from_utf8(&payload[offset..offset + name_end])
        .map_err(|error| {
            ProtocolError::HandshakeFailed(format!("invalid AuthSwitch plugin name: {error}"))
        })?
        .to_owned();
    offset += name_end + 1;

    let mut salt = [0u8; 20];
    let available = (payload.len() - offset).min(20);
    salt[..available].copy_from_slice(&payload[offset..offset + available]);
    Ok((plugin, salt))
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

async fn write_packet(
    stream: &mut TcpStream,
    sequence_id: u8,
    payload: &[u8],
) -> Result<(), ProtocolError> {
    let payload_len = u32::try_from(payload.len()).unwrap_or(0);
    let len_bytes = payload_len.to_le_bytes();
    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(&len_bytes[..3]);
    packet.push(sequence_id);
    packet.extend_from_slice(payload);
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

/// Native `MySQL` authentication module (`mysql_native_password` / `caching_sha2_password`).
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
    use rsa::pkcs8::EncodePublicKey;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use tokio::net::TcpListener;

    use super::*;

    fn build_mock_handshake_v10(salt: &[u8; 20], plugin: &str) -> Vec<u8> {
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
        payload.extend_from_slice(plugin.as_bytes());
        payload.push(0);

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

    async fn read_client_packet(socket: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut header = [0u8; 4];
        socket.read_exact(&mut header).await.unwrap();
        let len =
            usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
        let mut payload = vec![0u8; len];
        socket.read_exact(&mut payload).await.unwrap();
        (header[3], payload)
    }

    fn ok_packet(seq: u8) -> [u8; 11] {
        [
            0x07, 0x00, 0x00, seq, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn caching_sha2_scramble_is_32_bytes_and_deterministic() {
        let salt = [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let a = scramble_caching_sha2("secret", &salt);
        let b = scramble_caching_sha2("secret", &salt);
        assert_eq!(a.len(), 32);
        assert_eq!(a, b);
        assert_ne!(a, scramble_caching_sha2("other", &salt));
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
            let handshake_pkt = build_mock_handshake_v10(&salt, PLUGIN_NATIVE);
            socket.write_all(&handshake_pkt).await.unwrap();

            let (seq, payload) = read_client_packet(&mut socket).await;
            assert_eq!(seq, 1);
            assert!(payload.windows(5).any(|w| w == b"root\0"));

            let expected_scramble = scramble_native_password("secret", &salt);
            assert!(
                payload
                    .windows(expected_scramble.len())
                    .any(|w| w == expected_scramble.as_slice())
            );

            socket.write_all(&ok_packet(2)).await.unwrap();

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
    async fn caching_sha2_fast_auth_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let salt: [u8; 20] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(&build_mock_handshake_v10(&salt, PLUGIN_CACHING_SHA2))
                .await
                .unwrap();

            let (seq, payload) = read_client_packet(&mut socket).await;
            assert_eq!(seq, 1);
            assert!(
                payload
                    .windows(PLUGIN_CACHING_SHA2.len())
                    .any(|w| w == PLUGIN_CACHING_SHA2.as_bytes())
            );
            let expected = scramble_caching_sha2("secret", &salt);
            assert!(
                payload
                    .windows(expected.len())
                    .any(|w| w == expected.as_slice())
            );

            // Fast-cache hit: AuthMoreData(0x03) then OK.
            let more = [
                0x02,
                0x00,
                0x00,
                0x02,
                AUTH_MORE_DATA,
                CACHING_SHA2_FAST_AUTH,
            ];
            socket.write_all(&more).await.unwrap();
            socket.write_all(&ok_packet(3)).await.unwrap();

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
    async fn caching_sha2_full_auth_with_rsa_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let salt: [u8; 20] = [
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];

        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(&build_mock_handshake_v10(&salt, PLUGIN_CACHING_SHA2))
                .await
                .unwrap();

            let (_seq, payload) = read_client_packet(&mut socket).await;
            let expected = scramble_caching_sha2("secret", &salt);
            assert!(
                payload
                    .windows(expected.len())
                    .any(|w| w == expected.as_slice())
            );

            // Cache miss → full authentication.
            let more = [
                0x02,
                0x00,
                0x00,
                0x02,
                AUTH_MORE_DATA,
                CACHING_SHA2_FULL_AUTH,
            ];
            socket.write_all(&more).await.unwrap();

            // Client requests public key (0x02).
            let (seq, req) = read_client_packet(&mut socket).await;
            assert_eq!(req, vec![REQUEST_PUBLIC_KEY]);

            let mut key_payload = Vec::with_capacity(1 + pem.len());
            key_payload.push(AUTH_MORE_DATA);
            key_payload.extend_from_slice(pem.as_bytes());
            let key_len = u32::try_from(key_payload.len()).unwrap().to_le_bytes();
            let mut key_packet = Vec::new();
            key_packet.extend_from_slice(&key_len[..3]);
            key_packet.push(seq.wrapping_add(1));
            key_packet.extend_from_slice(&key_payload);
            socket.write_all(&key_packet).await.unwrap();

            let (enc_seq, encrypted) = read_client_packet(&mut socket).await;
            assert_eq!(enc_seq, seq.wrapping_add(2));

            let padding = Oaep::new::<Sha1>();
            let decrypted = private_key.decrypt(padding, &encrypted).unwrap();
            let mut expected_plain = b"secret\0".to_vec();
            for (index, byte) in expected_plain.iter_mut().enumerate() {
                *byte ^= salt[index % salt.len()];
            }
            assert_eq!(decrypted, expected_plain);

            socket
                .write_all(&ok_packet(enc_seq.wrapping_add(1)))
                .await
                .unwrap();

            let mut quit = [0u8; 5];
            let _ = socket.read_exact(&mut quit).await;
        });

        let module = MysqlModule::new();
        let credential = Credential {
            username: "root".into(),
            password: Some("secret".into()),
        };
        let result = module
            .authenticate(&target(port), &credential, Duration::from_secs(10))
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
            let handshake_pkt = build_mock_handshake_v10(&salt, PLUGIN_NATIVE);
            socket.write_all(&handshake_pkt).await.unwrap();

            let (_seq, _payload) = read_client_packet(&mut socket).await;

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
