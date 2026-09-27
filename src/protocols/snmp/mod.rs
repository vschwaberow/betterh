// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! SNMP v1/v2c community and `SNMPv3` USM authentication (UDP/161).

mod ber;
mod codec;
mod usm;

use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use async_trait::async_trait;
use tokio::{net::UdpSocket, time::timeout};

use self::codec::{
    PduErrorStatus, SnmpVersion, decode_community_response, encode_community_get_request,
};
use self::usm::{
    AuthProtocol, PrivProtocol, decode_authenticated_response, decode_discovery_report,
    encode_authenticated_get_request, encode_discovery_request, password_to_key,
    password_to_priv_key,
};
use super::{AuthResult, CanaryStatus, Credential, ProtocolError, ProtocolModule, Target};

pub use codec::SnmpVersion as Version;
pub use usm::{AuthProtocol as SnmpAuthProtocol, PrivProtocol as SnmpPrivProtocol};

/// SNMP authentication auditor.
#[derive(Debug)]
pub struct SnmpModule {
    version: SnmpVersion,
    auth: AuthProtocol,
    priv_protocol: PrivProtocol,
    priv_password: Option<String>,
    retries: u32,
    request_counter: AtomicU32,
}

impl Default for SnmpModule {
    fn default() -> Self {
        Self::new()
    }
}

impl SnmpModule {
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: SnmpVersion::V2c,
            auth: AuthProtocol::Sha1,
            priv_protocol: PrivProtocol::None,
            priv_password: None,
            retries: 2,
            request_counter: AtomicU32::new(1),
        }
    }

    #[must_use]
    pub fn with_version(mut self, version: SnmpVersion) -> Self {
        self.version = version;
        self
    }

    #[must_use]
    pub fn with_auth(mut self, auth: AuthProtocol) -> Self {
        self.auth = auth;
        self
    }

    #[must_use]
    pub fn with_priv(mut self, priv_protocol: PrivProtocol) -> Self {
        self.priv_protocol = priv_protocol;
        self
    }

    #[must_use]
    pub fn with_priv_password(mut self, password: Option<String>) -> Self {
        self.priv_password = password;
        self
    }

    fn next_id(&self) -> u32 {
        self.request_counter.fetch_add(1, Ordering::Relaxed).max(1)
    }

    async fn resolve_addr(&self, target: &Target) -> Result<SocketAddr, ProtocolError> {
        if let Some(ip) = target.ip {
            return Ok(SocketAddr::new(ip, target.port));
        }
        if let Ok(ip) = target.host.parse() {
            return Ok(SocketAddr::new(ip, target.port));
        }
        let host_port = format!("{}:{}", target.host, target.port);
        let mut addrs = tokio::net::lookup_host(host_port.as_str())
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        addrs.next().ok_or_else(|| {
            ProtocolError::ConnectionError(format!("no addresses for {}", target.host))
        })
    }

    async fn exchange(
        &self,
        addr: SocketAddr,
        payload: &[u8],
        overall: Duration,
    ) -> Result<Vec<u8>, ProtocolError> {
        let attempts = self.retries.saturating_add(1).max(1);
        let per_try = overall
            .checked_div(attempts)
            .unwrap_or(Duration::from_millis(500));
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        socket
            .connect(addr)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;

        let mut last_err = ProtocolError::Timeout;
        for _ in 0..attempts {
            if let Err(error) = socket.send(payload).await {
                last_err = ProtocolError::ConnectionError(error.to_string());
                continue;
            }
            let mut buf = vec![0u8; 65535];
            match timeout(per_try, socket.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    buf.truncate(n);
                    return Ok(buf);
                }
                Ok(Err(error)) => {
                    last_err = ProtocolError::ConnectionError(error.to_string());
                }
                Err(_) => {
                    last_err = ProtocolError::Timeout;
                }
            }
        }
        Err(last_err)
    }

    async fn authenticate_community(
        &self,
        target: &Target,
        community: &[u8],
        timeout: Duration,
    ) -> Result<AuthResult, ProtocolError> {
        let addr = self.resolve_addr(target).await?;
        let request_id = i32::try_from(self.next_id() & 0x7fff_ffff).unwrap_or(1);
        let payload = encode_community_get_request(self.version, community, request_id)
            .map_err(|error| ProtocolError::Internal(error.to_string()))?;
        let response = match self.exchange(addr, &payload, timeout).await {
            Ok(bytes) => bytes,
            Err(ProtocolError::Timeout) => return Ok(AuthResult::Failure),
            Err(error) => return Err(error),
        };
        let Ok(decoded) = decode_community_response(&response) else {
            return Ok(AuthResult::Failure);
        };
        Ok(match decoded.error_status {
            PduErrorStatus::NoError | PduErrorStatus::NoSuchName => AuthResult::Success,
            PduErrorStatus::TooBig | PduErrorStatus::GenErr => {
                AuthResult::RateLimited(Duration::from_secs(1))
            }
            PduErrorStatus::AuthorizationError
            | PduErrorStatus::BadValue
            | PduErrorStatus::ReadOnly
            | PduErrorStatus::Other => AuthResult::Failure,
        })
    }

    async fn authenticate_v3(
        &self,
        target: &Target,
        user: &str,
        auth_password: &str,
        timeout: Duration,
    ) -> Result<AuthResult, ProtocolError> {
        let addr = self.resolve_addr(target).await?;
        let msg_id = i32::try_from(self.next_id() & 0x7fff_ffff).unwrap_or(1);
        let req_id = i32::try_from(self.next_id() & 0x7fff_ffff).unwrap_or(1);
        let discovery = encode_discovery_request(msg_id, req_id)
            .map_err(|error| ProtocolError::Internal(error.to_string()))?;
        let report = match self.exchange(addr, &discovery, timeout).await {
            Ok(bytes) => bytes,
            Err(ProtocolError::Timeout) => return Ok(AuthResult::Failure),
            Err(error) => return Err(error),
        };
        let Ok(engine) = decode_discovery_report(&report) else {
            return Ok(AuthResult::Failure);
        };
        let auth_key = password_to_key(auth_password.as_bytes(), &engine.engine_id, self.auth);
        let priv_password = self.priv_password.as_deref().unwrap_or(auth_password);
        let priv_key = password_to_priv_key(
            priv_password.as_bytes(),
            &engine.engine_id,
            self.auth,
            self.priv_protocol,
        );
        let msg_id = i32::try_from(self.next_id() & 0x7fff_ffff).unwrap_or(1);
        let req_id = i32::try_from(self.next_id() & 0x7fff_ffff).unwrap_or(1);
        let priv_salt = u64::from(self.next_id()) << 32 | u64::from(self.next_id());
        let request = encode_authenticated_get_request(
            msg_id,
            req_id,
            &engine,
            user.as_bytes(),
            &auth_key,
            self.auth,
            self.priv_protocol,
            &priv_key,
            priv_salt,
        )
        .map_err(|error| ProtocolError::Internal(error.to_string()))?;
        let response = match self.exchange(addr, &request, timeout).await {
            Ok(bytes) => bytes,
            Err(ProtocolError::Timeout) => return Ok(AuthResult::Failure),
            Err(error) => return Err(error),
        };
        match decode_authenticated_response(
            &response,
            &auth_key,
            self.auth,
            self.priv_protocol,
            &priv_key,
        ) {
            Ok(_) => Ok(AuthResult::Success),
            Err(_) => Ok(AuthResult::Failure),
        }
    }
}

/// Panic-free SNMP decoder surface for fuzzing.
pub fn fuzz_decode(data: &[u8]) {
    let _ = codec::decode_community_response(data);
    let _ = usm::decode_discovery_report(data);
}

#[async_trait]
impl ProtocolModule for SnmpModule {
    fn name(&self) -> &'static str {
        "snmp"
    }

    fn default_port(&self) -> u16 {
        161
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        timeout: Duration,
    ) -> Result<AuthResult, ProtocolError> {
        match self.version {
            SnmpVersion::V1 | SnmpVersion::V2c => {
                let community = cred
                    .password
                    .as_deref()
                    .ok_or_else(|| ProtocolError::Internal("SNMP community requires -p".into()))?;
                self.authenticate_community(target, community.as_bytes(), timeout)
                    .await
            }
            SnmpVersion::V3 => {
                let password = cred.password.as_deref().unwrap_or("");
                self.authenticate_v3(target, &cred.username, password, timeout)
                    .await
            }
        }
    }

    async fn canary_probe(&self, target: &Target) -> Result<CanaryStatus, ProtocolError> {
        // UDP reachability: bind + connect is enough; avoid sending credentials.
        let _ = self.resolve_addr(target).await?;
        Ok(CanaryStatus::Normal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::snmp::codec::encode_community_get_response;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn community_success_against_mock_agent() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            buf.truncate(n);
            let resp = encode_community_get_response(SnmpVersion::V2c, b"public", 1, 0).unwrap();
            let _ = server.send_to(&resp, peer).await;
        });

        let module = SnmpModule::new().with_version(SnmpVersion::V2c);
        let target = Target {
            host: addr.ip().to_string(),
            port: addr.port(),
            ssl: false,
            ip: Some(addr.ip()),
            path: None,
        };
        let result = module
            .authenticate(
                &target,
                &Credential {
                    username: String::new(),
                    password: Some("public".into()),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn community_timeout_is_failure() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        // Server never replies.
        let module = SnmpModule::new().with_version(SnmpVersion::V1);
        let target = Target {
            host: addr.ip().to_string(),
            port: addr.port(),
            ssl: false,
            ip: Some(addr.ip()),
            path: None,
        };
        let result = module
            .authenticate(
                &target,
                &Credential {
                    username: String::new(),
                    password: Some("nope".into()),
                },
                Duration::from_millis(80),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Failure);
        drop(server);
    }
}
