// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! VNC / RFB password authentication (security type 2) over Tokio TCP.
//!
//! Supports RFB 3.8 (security-type list) and RFB 3.3 (fixed `u32` type).
//! Auth-only: no framebuffer / pixel protocol after `SecurityResult`.

use std::time::Duration;

use async_trait::async_trait;
use des::Des;
use des::cipher::{BlockEncrypt, KeyInit};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::io::dial;
use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

const CLIENT_VERSION: &[u8] = b"RFB 003.008\n";
const SEC_TYPE_NONE: u8 = 1;
const SEC_TYPE_VNC: u8 = 2;
const SECURITY_OK: u32 = 0;
const SECURITY_FAILED: u32 = 1;

/// VNC / RFB authentication module (feature = `vnc`).
#[derive(Debug, Default, Clone)]
pub struct VncModule {
    proxy: Option<String>,
}

impl VncModule {
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
impl ProtocolModule for VncModule {
    fn name(&self) -> &'static str {
        "vnc"
    }

    fn default_port(&self) -> u16 {
        5900
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
        let password = credential.password.clone().unwrap_or_default();
        let proxy = self.proxy.clone();

        timeout(timeout_budget, async move {
            let mut stream = dial(target, proxy.as_deref()).await?;
            run_vnc_auth(&mut stream, &password).await
        })
        .await
        .map_err(|_| ProtocolError::Timeout)?
    }
}

async fn run_vnc_auth(stream: &mut TcpStream, password: &str) -> Result<AuthResult, ProtocolError> {
    // Server version (12 bytes).
    let mut server_version = [0u8; 12];
    stream
        .read_exact(&mut server_version)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    if !server_version.starts_with(b"RFB ") {
        return Err(ProtocolError::HandshakeFailed(
            "peer did not speak RFB".into(),
        ));
    }

    stream
        .write_all(CLIENT_VERSION)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

    negotiate_vnc_auth(stream).await?;

    let mut challenge = [0u8; 16];
    stream
        .read_exact(&mut challenge)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

    let response = vnc_des_response(password, &challenge);
    stream
        .write_all(&response)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

    let mut result_buf = [0u8; 4];
    stream
        .read_exact(&mut result_buf)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    match u32::from_be_bytes(result_buf) {
        SECURITY_OK => Ok(AuthResult::Success),
        SECURITY_FAILED => Ok(AuthResult::Failure),
        other => Err(ProtocolError::HandshakeFailed(format!(
            "unexpected VNC SecurityResult {other}"
        ))),
    }
}

async fn negotiate_vnc_auth(stream: &mut TcpStream) -> Result<(), ProtocolError> {
    // Peek first byte: RFB 3.8 = number of types (usually small); RFB 3.3 = high bytes of u32 type.
    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

    // Heuristic: if first byte is 0..=16 treat as 3.8 type count; else finish u32 as 3.3.
    if first[0] > 0 && first[0] <= 16 {
        let count = usize::from(first[0]);
        let mut types = vec![0u8; count];
        stream
            .read_exact(&mut types)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        if !types.contains(&SEC_TYPE_VNC) {
            if types.iter().all(|&t| t == SEC_TYPE_NONE) {
                return Err(ProtocolError::HandshakeFailed(
                    "VNC server offers only SecurityType None (no password auth)".into(),
                ));
            }
            return Err(ProtocolError::HandshakeFailed(format!(
                "VNC server does not offer SecurityType 2 (got {types:?})"
            )));
        }
        stream
            .write_all(&[SEC_TYPE_VNC])
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        return Ok(());
    }

    // RFB 3.3: complete the remaining 3 bytes of the security-type u32.
    let mut rest = [0u8; 3];
    stream
        .read_exact(&mut rest)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    let sec_type = u32::from_be_bytes([first[0], rest[0], rest[1], rest[2]]);
    match sec_type {
        2 => Ok(()),
        1 => Err(ProtocolError::HandshakeFailed(
            "VNC RFB 3.3 peer selected SecurityType None".into(),
        )),
        0 => Err(ProtocolError::HandshakeFailed(
            "VNC RFB 3.3 connection failed (security type 0)".into(),
        )),
        other => Err(ProtocolError::HandshakeFailed(format!(
            "unsupported VNC RFB 3.3 security type {other}"
        ))),
    }
}

/// Classic VNC Authentication response: DES-ECB, bit-reversed 8-byte password key.
#[must_use]
pub fn vnc_des_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key_bytes = [0u8; 8];
    let pw = password.as_bytes();
    let n = pw.len().min(8);
    key_bytes[..n].copy_from_slice(&pw[..n]);
    for byte in &mut key_bytes {
        *byte = byte.reverse_bits();
    }

    let cipher = Des::new(&key_bytes.into());
    let mut out = [0u8; 16];
    let mut block0: [u8; 8] = challenge[..8].try_into().unwrap_or([0u8; 8]);
    let mut block1: [u8; 8] = challenge[8..].try_into().unwrap_or([0u8; 8]);
    cipher.encrypt_block((&mut block0).into());
    cipher.encrypt_block((&mut block1).into());
    out[..8].copy_from_slice(&block0);
    out[8..].copy_from_slice(&block1);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn vnc_des_is_deterministic() {
        let challenge = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let a = vnc_des_response("secret", &challenge);
        let b = vnc_des_response("secret", &challenge);
        assert_eq!(a, b);
        assert_ne!(a, challenge);
        // Wrong password must differ.
        assert_ne!(a, vnc_des_response("wrong", &challenge));
    }

    #[test]
    fn password_longer_than_8_is_truncated() {
        let challenge = [0x11u8; 16];
        let long = vnc_des_response("0123456789abcdef", &challenge);
        let trunc = vnc_des_response("01234567", &challenge);
        assert_eq!(long, trunc);
    }

    async fn mock_vnc_server(password: &'static str, accept: bool) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"RFB 003.008\n").await.unwrap();
            let mut client_ver = [0u8; 12];
            sock.read_exact(&mut client_ver).await.unwrap();
            // Offer VNC Authentication only.
            sock.write_all(&[1, SEC_TYPE_VNC]).await.unwrap();
            let mut chosen = [0u8; 1];
            sock.read_exact(&mut chosen).await.unwrap();
            assert_eq!(chosen[0], SEC_TYPE_VNC);
            let challenge = [0xAAu8; 16];
            sock.write_all(&challenge).await.unwrap();
            let mut response = [0u8; 16];
            sock.read_exact(&mut response).await.unwrap();
            let expected = vnc_des_response(password, &challenge);
            let result = if accept && response == expected {
                SECURITY_OK
            } else {
                SECURITY_FAILED
            };
            sock.write_all(&result.to_be_bytes()).await.unwrap();
        });
        port
    }

    #[tokio::test]
    async fn correct_password_succeeds() {
        let port = mock_vnc_server("hunter2", true).await;
        let module = VncModule::new();
        let target = Target {
            host: "127.0.0.1".into(),
            port,
            ssl: false,
            ip: Some("127.0.0.1".parse().unwrap()),
            path: None,
        };
        let result = module
            .authenticate(
                &target,
                &Credential {
                    username: String::new(),
                    password: Some("hunter2".into()),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
    }

    #[tokio::test]
    async fn wrong_password_fails() {
        let port = mock_vnc_server("hunter2", true).await;
        let module = VncModule::new();
        let target = Target {
            host: "127.0.0.1".into(),
            port,
            ssl: false,
            ip: Some("127.0.0.1".parse().unwrap()),
            path: None,
        };
        let result = module
            .authenticate(
                &target,
                &Credential {
                    username: String::new(),
                    password: Some("nope".into()),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Failure);
    }
}
