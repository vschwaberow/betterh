// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Kerberos v5 AS-REQ pre-authentication module (feature = `kerberos`).
//!
//! Two-stage exchange against a KDC on TCP/88:
//! 1. AS-REQ without PA → typically `KDC_ERR_PREAUTH_REQUIRED` (+ ETYPE-INFO2 salt)
//! 2. AS-REQ with `PA-ENC-TIMESTAMP` (AES-256) → `AS-REP` or mapped `KRB-ERROR`
//!
//! Crypto and DER codecs are provided by the MIT-licensed `kerbcore` crate;
//! this module owns I/O, result mapping, SOCKS5, and CLI integration.

mod codec;
mod crypto;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use self::codec::{
    KdcMessage, PreAuthMaterial, decode_kdc_message, encode_as_req, frame_tcp, preauth_from_edata,
    unframe_tcp,
};
use self::crypto::{build_pa_enc_timestamp, string_to_key};
use super::io::dial;
use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

pub use codec::{ETYPE_AES128, ETYPE_AES256, ETYPE_RC4_HMAC};

/// RFC 4120 KDC error codes used for auth auditing.
pub mod error_codes {
    pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;
    pub const KDC_ERR_CLIENT_REVOKED: i32 = 18;
    pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
    pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
    pub const KDC_ERR_SVC_UNAVAILABLE: i32 = 29;
}

/// Map a `KRB-ERROR` code to [`AuthResult`].
#[must_use]
pub fn map_kdc_error(code: i32) -> AuthResult {
    match code {
        error_codes::KDC_ERR_PREAUTH_FAILED | error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN => {
            AuthResult::Failure
        }
        error_codes::KDC_ERR_CLIENT_REVOKED => AuthResult::LockedOut,
        error_codes::KDC_ERR_SVC_UNAVAILABLE => AuthResult::RateLimited(Duration::from_secs(5)),
        error_codes::KDC_ERR_PREAUTH_REQUIRED => {
            AuthResult::Error("KDC demanded pre-auth but exchange incomplete (internal)".into())
        }
        other => AuthResult::Error(format!("Kerberos KDC_ERR {other}")),
    }
}

/// Derive a Kerberos realm from an FQDN host (`dc.corp.local` → `CORP.LOCAL`).
///
/// Returns `None` for bare labels, IPv4/IPv6 literals, and hosts without a DNS suffix.
#[must_use]
pub fn realm_from_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let (_, rest) = host.split_once('.')?;
    if rest.is_empty() || !rest.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(rest.to_ascii_uppercase())
}

/// Panic-free Kerberos decoder surface for fuzzing.
pub fn fuzz_decode(data: &[u8]) {
    let _ = decode_kdc_message(data);
    if let Ok(pdu) = unframe_tcp(data) {
        let _ = decode_kdc_message(pdu);
    }
}

/// CLI / module etype selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EtypeMode {
    #[default]
    Auto,
    Aes256,
    Aes128,
    Rc4,
}

impl EtypeMode {
    #[must_use]
    pub const fn forced_etype(self) -> Option<i32> {
        match self {
            Self::Auto => None,
            Self::Aes256 => Some(ETYPE_AES256),
            Self::Aes128 => Some(ETYPE_AES128),
            Self::Rc4 => Some(ETYPE_RC4_HMAC),
        }
    }
}

/// Kerberos AS-REQ authentication module.
#[derive(Debug, Default, Clone)]
pub struct KerberosModule {
    proxy: Option<String>,
    realm: Option<String>,
    etype: EtypeMode,
}

impl KerberosModule {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            proxy: None,
            realm: None,
            etype: EtypeMode::Auto,
        }
    }

    #[must_use]
    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = proxy;
        self
    }

    #[must_use]
    pub fn with_realm(mut self, realm: Option<String>) -> Self {
        self.realm = realm.map(|r| r.to_ascii_uppercase());
        self
    }

    #[must_use]
    pub fn with_etype(mut self, etype: EtypeMode) -> Self {
        self.etype = etype;
        self
    }

    fn resolve_realm(&self, target: &Target) -> Result<String, ProtocolError> {
        if let Some(realm) = &self.realm {
            return Ok(realm.clone());
        }
        realm_from_host(&target.host).ok_or_else(|| {
            ProtocolError::HandshakeFailed(
                "Kerberos requires --realm <REALM> when the target host is not an FQDN".into(),
            )
        })
    }
}

#[async_trait]
impl ProtocolModule for KerberosModule {
    fn name(&self) -> &'static str {
        "kerberos"
    }

    fn default_port(&self) -> u16 {
        88
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
        let realm = self.resolve_realm(target)?;
        let user = credential.username.clone();
        let password = credential.password.clone().unwrap_or_default();
        let proxy = self.proxy.clone();
        let forced = self.etype.forced_etype();

        timeout(timeout_budget, async move {
            let mut stream = dial(target, proxy.as_deref()).await?;
            run_as_exchange(&mut stream, &realm, &user, &password, forced).await
        })
        .await
        .map_err(|_| ProtocolError::Timeout)?
    }
}

async fn run_as_exchange(
    stream: &mut tokio::net::TcpStream,
    realm: &str,
    user: &str,
    password: &str,
    forced_etype: Option<i32>,
) -> Result<AuthResult, ProtocolError> {
    let nonce = fastrand::u32(..);
    let till = far_future_kerberos_time();

    // Stage 1: no PA — learn salt / etype (or proceed with default).
    let stage1 = encode_as_req(realm, user, nonce, &till, vec![]);
    write_framed(stream, &stage1).await?;
    let resp1 = read_framed(stream).await?;
    let material = match decode_kdc_message(&resp1)? {
        KdcMessage::AsRep => {
            // Rare: no-preauth account → success without password proof.
            return Ok(AuthResult::Success);
        }
        KdcMessage::Error { code, e_data } => {
            if code == error_codes::KDC_ERR_PREAUTH_REQUIRED {
                preauth_from_edata(e_data.as_deref(), realm, user, forced_etype)
            } else if code == error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN
                || code == error_codes::KDC_ERR_CLIENT_REVOKED
                || code == error_codes::KDC_ERR_SVC_UNAVAILABLE
                || code == error_codes::KDC_ERR_PREAUTH_FAILED
            {
                return Ok(map_kdc_error(code));
            } else {
                PreAuthMaterial {
                    salt: format!("{realm}{user}"),
                    etype: forced_etype.unwrap_or(ETYPE_AES256),
                    iterations: 4096,
                }
            }
        }
    };

    let password_owned = password.to_owned();
    let salt_owned = material.salt.clone();
    let etype = material.etype;
    let iterations = material.iterations;
    let key = tokio::task::spawn_blocking(move || {
        string_to_key(etype, &password_owned, salt_owned.as_bytes(), iterations)
    })
    .await
    .map_err(|error| ProtocolError::Internal(format!("Kerberos key worker failed: {error}")))?
    .ok_or_else(|| ProtocolError::HandshakeFailed(format!("unsupported Kerberos etype {etype}")))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let pa = build_pa_enc_timestamp(&key, now, 0);
    let stage2 = encode_as_req(realm, user, nonce, &till, vec![pa]);
    write_framed(stream, &stage2).await?;
    let resp2 = read_framed(stream).await?;
    match decode_kdc_message(&resp2)? {
        KdcMessage::AsRep => Ok(AuthResult::Success),
        KdcMessage::Error { code, .. } => Ok(map_kdc_error(code)),
    }
}

fn far_future_kerberos_time() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(10 * 3600);
    kerbcore::client::unix_to_kerberos_time(secs)
}

async fn write_framed(stream: &mut tokio::net::TcpStream, pdu: &[u8]) -> Result<(), ProtocolError> {
    let framed = frame_tcp(pdu);
    stream
        .write_all(&framed)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))
}

async fn read_framed(stream: &mut tokio::net::TcpStream) -> Result<Vec<u8>, ProtocolError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 1024 * 1024 {
        return Err(ProtocolError::HandshakeFailed(format!(
            "Kerberos TCP frame length out of range: {len}"
        )));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    // Validate via unframe for symmetry (already have body).
    let _ = unframe_tcp(&[&len_buf[..], &body[..]].concat())?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerbcore::messages::KrbError;
    use kerbcore::types::{KerberosTime, PrincipalName};
    use tokio::net::TcpListener;

    fn target(port: u16, host: &str) -> Target {
        Target {
            host: host.into(),
            port,
            ssl: false,
            path: None,
            ip: Some("127.0.0.1".parse().unwrap()),
        }
    }

    fn sample_error(code: i32) -> Vec<u8> {
        KrbError {
            stime: KerberosTime("20200101000000Z".into()),
            susec: 0,
            error_code: code,
            realm: "CORP.LOCAL".into(),
            sname: PrincipalName {
                name_type: 2,
                name_string: vec!["krbtgt".into(), "CORP.LOCAL".into()],
            },
            e_text: None,
            e_data: None,
        }
        .encode()
    }

    #[test]
    fn realm_from_fqdn() {
        assert_eq!(
            realm_from_host("dc01.corp.local"),
            Some("CORP.LOCAL".into())
        );
        assert_eq!(realm_from_host("localhost"), None);
    }

    #[test]
    fn maps_kdc_error_codes() {
        assert_eq!(
            map_kdc_error(error_codes::KDC_ERR_PREAUTH_FAILED),
            AuthResult::Failure
        );
        assert_eq!(
            map_kdc_error(error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN),
            AuthResult::Failure
        );
        assert_eq!(
            map_kdc_error(error_codes::KDC_ERR_CLIENT_REVOKED),
            AuthResult::LockedOut
        );
        assert_eq!(
            map_kdc_error(error_codes::KDC_ERR_SVC_UNAVAILABLE),
            AuthResult::RateLimited(Duration::from_secs(5))
        );
    }

    #[tokio::test]
    async fn unknown_principal_on_stage1_is_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut len = [0u8; 4];
            socket.read_exact(&mut len).await.unwrap();
            let n = u32::from_be_bytes(len) as usize;
            let mut req = vec![0u8; n];
            socket.read_exact(&mut req).await.unwrap();
            let body = sample_error(error_codes::KDC_ERR_C_PRINCIPAL_UNKNOWN);
            let framed = frame_tcp(&body);
            socket.write_all(&framed).await.unwrap();
        });

        let module = KerberosModule::new().with_realm(Some("CORP.LOCAL".into()));
        let result = module
            .authenticate(
                &target(port, "127.0.0.1"),
                &Credential {
                    username: "missing".into(),
                    password: Some("x".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Failure);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn preauth_failed_after_timestamp_is_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Stage 1
            let mut len = [0u8; 4];
            socket.read_exact(&mut len).await.unwrap();
            let n = u32::from_be_bytes(len) as usize;
            let mut req = vec![0u8; n];
            socket.read_exact(&mut req).await.unwrap();
            let body = sample_error(error_codes::KDC_ERR_PREAUTH_REQUIRED);
            socket.write_all(&frame_tcp(&body)).await.unwrap();
            // Stage 2
            socket.read_exact(&mut len).await.unwrap();
            let n = u32::from_be_bytes(len) as usize;
            let mut req = vec![0u8; n];
            socket.read_exact(&mut req).await.unwrap();
            let body = sample_error(error_codes::KDC_ERR_PREAUTH_FAILED);
            socket.write_all(&frame_tcp(&body)).await.unwrap();
        });

        let module = KerberosModule::new().with_realm(Some("CORP.LOCAL".into()));
        let result = module
            .authenticate(
                &target(port, "dc.corp.local"),
                &Credential {
                    username: "alice".into(),
                    password: Some("wrong".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Failure);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn revoked_client_is_locked_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut len = [0u8; 4];
            socket.read_exact(&mut len).await.unwrap();
            let n = u32::from_be_bytes(len) as usize;
            let mut req = vec![0u8; n];
            socket.read_exact(&mut req).await.unwrap();
            let body = sample_error(error_codes::KDC_ERR_CLIENT_REVOKED);
            socket.write_all(&frame_tcp(&body)).await.unwrap();
        });

        let module = KerberosModule::new().with_realm(Some("CORP.LOCAL".into()));
        let result = module
            .authenticate(
                &target(port, "127.0.0.1"),
                &Credential {
                    username: "locked".into(),
                    password: Some("x".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::LockedOut);
        server.await.unwrap();
    }

    #[test]
    fn missing_realm_on_bare_host_errors() {
        let module = KerberosModule::new();
        let err = module.resolve_realm(&target(88, "10.0.0.1")).unwrap_err();
        assert!(matches!(err, ProtocolError::HandshakeFailed(_)));
    }
}
