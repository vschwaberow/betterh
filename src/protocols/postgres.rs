// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! `PostgreSQL` Frontend/Backend Protocol 3.0 authentication with cleartext,
//! MD5, and `SCRAM-SHA-256` SASL challenges.
//!
//! Oversized on purpose: framing, auth plugins, and hermetic mocks share one
//! dialogue type-state; further splits wait on shared crypto extraction.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

const PROTOCOL_VERSION_3_0: u32 = 196_608; // (3 << 16) | 0
const AUTH_OK: u32 = 0;
const AUTH_CLEARTEXT: u32 = 3;
const AUTH_MD5: u32 = 5;
const AUTH_SASL: u32 = 10;
const AUTH_SASL_CONTINUE: u32 = 11;
const AUTH_SASL_FINAL: u32 = 12;
const SCRAM_SHA_256: &str = "SCRAM-SHA-256";

type HmacSha256 = Hmac<Sha256>;

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
        let stream = super::io::dial(target, proxy).await?;
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
                        AUTH_OK => {
                            return Ok((AuthResult::Success, self));
                        }
                        AUTH_CLEARTEXT => {
                            let password_pkt = build_password_message(password);
                            stream.write_all(&password_pkt).await.map_err(|error| {
                                ProtocolError::ConnectionError(error.to_string())
                            })?;
                            stream.flush().await.map_err(|error| {
                                ProtocolError::ConnectionError(error.to_string())
                            })?;
                        }
                        AUTH_MD5 => {
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
                        AUTH_SASL => {
                            handle_scram_sha256(stream, username, password, &payload[4..]).await?;
                        }
                        AUTH_SASL_CONTINUE | AUTH_SASL_FINAL => {
                            return Err(ProtocolError::HandshakeFailed(
                                "Unexpected Postgres SASL continue/final without SASL start".into(),
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

async fn handle_scram_sha256(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
    mechanisms_payload: &[u8],
) -> Result<(), ProtocolError> {
    let mechanisms = parse_sasl_mechanisms(mechanisms_payload);
    if !mechanisms.iter().any(|name| name == SCRAM_SHA_256) {
        return Err(ProtocolError::HandshakeFailed(format!(
            "Postgres SASL mechanisms {mechanisms:?} do not include {SCRAM_SHA_256}"
        )));
    }

    let client_nonce = generate_nonce();
    let client_first_bare = format!("n={},r={client_nonce}", scram_escape(username));
    let client_first = format!("n,,{client_first_bare}");

    let initial = build_sasl_initial_response(SCRAM_SHA_256, client_first.as_bytes());
    stream
        .write_all(&initial)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

    let (msg_type, cont_payload) = read_message(stream).await?;
    if msg_type != b'R' || cont_payload.len() < 4 {
        return Err(ProtocolError::HandshakeFailed(
            "Expected Postgres AuthenticationSASLContinue".into(),
        ));
    }
    let cont_type = u32::from_be_bytes([
        cont_payload[0],
        cont_payload[1],
        cont_payload[2],
        cont_payload[3],
    ]);
    if cont_type != AUTH_SASL_CONTINUE {
        return Err(ProtocolError::HandshakeFailed(format!(
            "Expected AuthenticationSASLContinue (11), got {cont_type}"
        )));
    }
    let server_first = std::str::from_utf8(&cont_payload[4..]).map_err(|error| {
        ProtocolError::HandshakeFailed(format!("invalid SASL server-first encoding: {error}"))
    })?;

    let (combined_nonce, salt, iterations) = parse_server_first(server_first)?;
    if !combined_nonce.starts_with(&client_nonce) {
        return Err(ProtocolError::HandshakeFailed(
            "Postgres SCRAM server nonce does not start with client nonce".into(),
        ));
    }

    let (client_final, expected_server_sig) = compute_scram_client_final(
        password,
        &client_first_bare,
        server_first,
        &combined_nonce,
        &salt,
        iterations,
    )?;

    let response = build_sasl_response(client_final.as_bytes());
    stream
        .write_all(&response)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

    let (msg_type, final_payload) = read_message(stream).await?;
    if msg_type != b'R' || final_payload.len() < 4 {
        return Err(ProtocolError::HandshakeFailed(
            "Expected Postgres AuthenticationSASLFinal".into(),
        ));
    }
    let final_type = u32::from_be_bytes([
        final_payload[0],
        final_payload[1],
        final_payload[2],
        final_payload[3],
    ]);
    if final_type != AUTH_SASL_FINAL {
        return Err(ProtocolError::HandshakeFailed(format!(
            "Expected AuthenticationSASLFinal (12), got {final_type}"
        )));
    }
    let server_final = std::str::from_utf8(&final_payload[4..]).map_err(|error| {
        ProtocolError::HandshakeFailed(format!("invalid SASL server-final encoding: {error}"))
    })?;
    verify_server_final(server_final, &expected_server_sig)?;
    Ok(())
}

fn parse_sasl_mechanisms(payload: &[u8]) -> Vec<String> {
    let mut mechanisms = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        if payload[offset] == 0 {
            break;
        }
        let start = offset;
        while offset < payload.len() && payload[offset] != 0 {
            offset += 1;
        }
        mechanisms.push(String::from_utf8_lossy(&payload[start..offset]).into_owned());
        if offset < payload.len() {
            offset += 1;
        }
    }
    mechanisms
}

fn generate_nonce() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
    (0..24)
        .map(|_| CHARSET[fastrand::usize(..CHARSET.len())] as char)
        .collect()
}

fn scram_escape(value: &str) -> String {
    value.replace('=', "=3D").replace(',', "=2C")
}

fn parse_server_first(server_first: &str) -> Result<(String, Vec<u8>, u32), ProtocolError> {
    let mut combined_nonce = None;
    let mut salt = None;
    let mut iterations = None;
    for part in server_first.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            return Err(ProtocolError::HandshakeFailed(format!(
                "malformed SCRAM server-first attribute: {part}"
            )));
        };
        match key {
            "r" => combined_nonce = Some(value.to_owned()),
            "s" => {
                salt = Some(B64.decode(value).map_err(|error| {
                    ProtocolError::HandshakeFailed(format!("invalid SCRAM salt base64: {error}"))
                })?);
            }
            "i" => {
                iterations = Some(value.parse::<u32>().map_err(|error| {
                    ProtocolError::HandshakeFailed(format!(
                        "invalid SCRAM iteration count: {error}"
                    ))
                })?);
            }
            _ => {}
        }
    }
    let combined_nonce = combined_nonce
        .ok_or_else(|| ProtocolError::HandshakeFailed("SCRAM server-first missing nonce".into()))?;
    let salt = salt
        .ok_or_else(|| ProtocolError::HandshakeFailed("SCRAM server-first missing salt".into()))?;
    let iterations = iterations.ok_or_else(|| {
        ProtocolError::HandshakeFailed("SCRAM server-first missing iteration count".into())
    })?;
    if iterations == 0 {
        return Err(ProtocolError::HandshakeFailed(
            "SCRAM iteration count must be non-zero".into(),
        ));
    }
    Ok((combined_nonce, salt, iterations))
}

fn compute_scram_client_final(
    password: &str,
    client_first_bare: &str,
    server_first: &str,
    combined_nonce: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<(String, Vec<u8>), ProtocolError> {
    let client_final_without_proof = format!("c=biws,r={combined_nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{client_final_without_proof}");

    let (client_proof, server_signature) = scram_proofs(
        password.as_bytes(),
        salt,
        iterations,
        auth_message.as_bytes(),
    )?;
    let client_final = format!(
        "{client_final_without_proof},p={}",
        B64.encode(client_proof)
    );
    Ok((client_final, server_signature))
}

fn scram_proofs(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    auth_message: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let mut salted_password = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut salted_password);

    let client_key = hmac_sha256(&salted_password, b"Client Key")?;
    let stored_key = Sha256::digest(&client_key);
    let client_signature = hmac_sha256(stored_key.as_slice(), auth_message)?;
    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(left, right)| left ^ right)
        .collect();

    let server_key = hmac_sha256(&salted_password, b"Server Key")?;
    let server_signature = hmac_sha256(&server_key, auth_message)?;
    Ok((client_proof, server_signature))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|error| {
        ProtocolError::Internal(format!("HMAC-SHA256 key setup failed: {error}"))
    })?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_server_final(server_final: &str, expected_signature: &[u8]) -> Result<(), ProtocolError> {
    if let Some(error) = server_final
        .split(',')
        .find_map(|part| part.strip_prefix("e="))
    {
        return Err(ProtocolError::HandshakeFailed(format!(
            "SCRAM server error: {error}"
        )));
    }
    let Some(signature_b64) = server_final
        .split(',')
        .find_map(|part| part.strip_prefix("v="))
    else {
        return Err(ProtocolError::HandshakeFailed(
            "SCRAM server-final missing verifier".into(),
        ));
    };
    let signature = B64.decode(signature_b64).map_err(|error| {
        ProtocolError::HandshakeFailed(format!("invalid SCRAM server signature base64: {error}"))
    })?;
    if signature != expected_signature {
        return Err(ProtocolError::HandshakeFailed(
            "SCRAM server signature mismatch".into(),
        ));
    }
    Ok(())
}

fn build_sasl_initial_response(mechanism: &str, initial: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(mechanism.len() + 5 + initial.len());
    body.extend_from_slice(mechanism.as_bytes());
    body.push(0);
    let initial_len = i32::try_from(initial.len()).unwrap_or(0);
    body.extend_from_slice(&initial_len.to_be_bytes());
    body.extend_from_slice(initial);

    let total_len = u32::try_from(body.len() + 4).unwrap_or(0);
    let mut packet = Vec::with_capacity(1 + usize::try_from(total_len).unwrap_or(body.len() + 4));
    packet.push(b'p');
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

fn build_sasl_response(data: &[u8]) -> Vec<u8> {
    let total_len = u32::try_from(data.len() + 4).unwrap_or(0);
    let mut packet = Vec::with_capacity(1 + usize::try_from(total_len).unwrap_or(data.len() + 4));
    packet.push(b'p');
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(data);
    packet
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

/// Fuzz entry: walk Postgres 3.0 message frames and auth payloads.
pub fn fuzz_parse_messages(mut data: &[u8]) {
    let mut steps = 0usize;
    while data.len() >= 5 && steps < 256 {
        let len = usize::try_from(u32::from_be_bytes([data[1], data[2], data[3], data[4]]))
            .unwrap_or(usize::MAX);
        if !(4..=16 * 1024).contains(&len) || data.len() < 1 + len {
            break;
        }
        let payload = &data[5..=len];
        let _ = parse_sasl_mechanisms(payload);
        let _ = parse_error_response(payload);
        if let Ok(s) = std::str::from_utf8(payload) {
            let _ = parse_server_first(s);
        }
        data = &data[1 + len..];
        steps += 1;
    }
    let _ = parse_sasl_mechanisms(data);
    let _ = parse_error_response(data);
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

    fn write_auth_r(auth_type: u32, extra: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + extra.len());
        body.extend_from_slice(&auth_type.to_be_bytes());
        body.extend_from_slice(extra);
        let len = u32::try_from(body.len() + 4).unwrap();
        let mut msg = Vec::with_capacity(5 + body.len());
        msg.push(b'R');
        msg.extend_from_slice(&len.to_be_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    async fn read_startup(socket: &mut TcpStream) {
        let mut len_buf = [0u8; 4];
        socket.read_exact(&mut len_buf).await.unwrap();
        let len = usize::try_from(u32::from_be_bytes(len_buf)).unwrap();
        let mut startup_body = vec![0u8; len - 4];
        socket.read_exact(&mut startup_body).await.unwrap();
    }

    async fn read_frontend_p(socket: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 5];
        socket.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], b'p');
        let payload_len =
            usize::try_from(u32::from_be_bytes([header[1], header[2], header[3], header[4]]) - 4)
                .unwrap();
        let mut body = vec![0u8; payload_len];
        socket.read_exact(&mut body).await.unwrap();
        body
    }

    /// RFC 7677 Appendix A SCRAM-SHA-256 test vector.
    #[test]
    fn scram_sha256_rfc7677_client_proof_and_server_signature() {
        let client_nonce = "rOprNGfwEbeRWgbNEkqO";
        let client_first_bare = format!("n=user,r={client_nonce}");
        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let (combined_nonce, salt, iterations) = parse_server_first(server_first).unwrap();
        let (client_final, server_sig) = compute_scram_client_final(
            "pencil",
            &client_first_bare,
            server_first,
            &combined_nonce,
            &salt,
            iterations,
        )
        .unwrap();

        assert_eq!(
            client_final,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        assert_eq!(
            B64.encode(server_sig),
            "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
        );
    }

    #[tokio::test]
    async fn authenticates_postgres_scram_sha256_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_startup(&mut socket).await;

            // AuthenticationSASL offering SCRAM-SHA-256
            let mut mechs = Vec::new();
            mechs.extend_from_slice(SCRAM_SHA_256.as_bytes());
            mechs.push(0);
            mechs.push(0);
            socket
                .write_all(&write_auth_r(AUTH_SASL, &mechs))
                .await
                .unwrap();

            // SASLInitialResponse
            let initial = read_frontend_p(&mut socket).await;
            let nul = initial.iter().position(|&b| b == 0).unwrap();
            assert_eq!(&initial[..nul], SCRAM_SHA_256.as_bytes());
            let initial_len = i32::from_be_bytes([
                initial[nul + 1],
                initial[nul + 2],
                initial[nul + 3],
                initial[nul + 4],
            ]);
            let client_first = std::str::from_utf8(
                &initial[nul + 5..nul + 5 + usize::try_from(initial_len).unwrap()],
            )
            .unwrap();
            assert!(client_first.starts_with("n,,n=alice,r="));
            let client_first_bare = client_first.trim_start_matches("n,,");
            let client_nonce = client_first_bare
                .split(',')
                .find_map(|part| part.strip_prefix("r="))
                .unwrap();

            let salt = B64.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
            let iterations = 4096u32;
            let server_nonce_suffix = "serverNonceSuffixXYZ";
            let combined_nonce = format!("{client_nonce}{server_nonce_suffix}");
            let server_first = format!("r={combined_nonce},s={},i={iterations}", B64.encode(&salt));

            socket
                .write_all(&write_auth_r(AUTH_SASL_CONTINUE, server_first.as_bytes()))
                .await
                .unwrap();

            let client_final = String::from_utf8(read_frontend_p(&mut socket).await).unwrap();
            let (expected_final, server_sig) = compute_scram_client_final(
                "secret",
                client_first_bare,
                &server_first,
                &combined_nonce,
                &salt,
                iterations,
            )
            .unwrap();
            assert_eq!(client_final, expected_final);

            let server_final = format!("v={}", B64.encode(server_sig));
            socket
                .write_all(&write_auth_r(AUTH_SASL_FINAL, server_final.as_bytes()))
                .await
                .unwrap();
            socket.write_all(&write_auth_r(AUTH_OK, &[])).await.unwrap();

            let mut term = [0u8; 5];
            let _ = socket.read_exact(&mut term).await;
        });

        let module = PostgresModule::new();
        let credential = Credential {
            username: "alice".into(),
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
    async fn authenticates_postgres_md5_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let salt: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_startup(&mut socket).await;

            let mut challenge = Vec::new();
            challenge.push(b'R');
            challenge.extend_from_slice(&12u32.to_be_bytes());
            challenge.extend_from_slice(&5u32.to_be_bytes());
            challenge.extend_from_slice(&salt);
            socket.write_all(&challenge).await.unwrap();

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

            let mut ok_msg = Vec::new();
            ok_msg.push(b'R');
            ok_msg.extend_from_slice(&8u32.to_be_bytes());
            ok_msg.extend_from_slice(&0u32.to_be_bytes());
            socket.write_all(&ok_msg).await.unwrap();

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
            read_startup(&mut socket).await;

            let mut challenge = Vec::new();
            challenge.push(b'R');
            challenge.extend_from_slice(&12u32.to_be_bytes());
            challenge.extend_from_slice(&5u32.to_be_bytes());
            challenge.extend_from_slice(&salt);
            socket.write_all(&challenge).await.unwrap();

            let mut p_header = [0u8; 5];
            socket.read_exact(&mut p_header).await.unwrap();
            let p_len = (u32::from_be_bytes([p_header[1], p_header[2], p_header[3], p_header[4]])
                - 4) as usize;
            let mut p_body = vec![0u8; p_len];
            socket.read_exact(&mut p_body).await.unwrap();

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
            read_startup(&mut socket).await;

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
