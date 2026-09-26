// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Shared protocol inputs, outcomes, and errors.

use std::{fmt, net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub ssl: bool,
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
}

impl Target {
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, ssl: bool) -> Self {
        let host = host.into();
        let ip = host.parse().ok();
        Self {
            host,
            port,
            ssl,
            path: None,
            ip,
        }
    }

    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    #[must_use]
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip = Some(ip);
        self
    }

    /// Format `host:port` for display and skip keys (ignores pinned `ip`).
    #[must_use]
    pub fn host_port(&self) -> String {
        format_endpoint(&self.host, self.port)
    }

    /// Address used for the TCP dial: pinned `ip:port` when set, else `host:port`.
    #[must_use]
    pub fn dial_addr(&self) -> String {
        match self.ip {
            Some(IpAddr::V4(ip)) => format!("{ip}:{}", self.port),
            Some(IpAddr::V6(ip)) => format!("[{ip}]:{}", self.port),
            None => self.host_port(),
        }
    }
}

pub(crate) fn format_endpoint(host: &str, port: u16) -> String {
    format!("{}:{port}", format_host(host))
}

pub(crate) fn format_host(host: &str) -> std::borrow::Cow<'_, str> {
    if host.contains(':') {
        std::borrow::Cow::Owned(format!("[{host}]"))
    } else {
        std::borrow::Cow::Borrowed(host)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)?;
        } else {
            write!(f, "{}:{}", self.host, self.port)?;
        }
        if let Some(path) = &self.path {
            f.write_str(path)?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub password: Option<String>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthResult {
    Success,
    Failure,
    LockedOut,
    RateLimited(Duration),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryStatus {
    Normal,
    WildcardDetected(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum ProtocolError {
    #[error("Connection failed: {0}")]
    ConnectionError(String),
    #[error("Timeout while communicating with target")]
    Timeout,
    #[error("Protocol handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("Proxy error: {0}")]
    ProxyError(String),
    #[error("Incompatible cipher or algorithm: {0}")]
    IncompatibleCipher(String),
    #[error("Internal module error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn dial_addr_prefers_pinned_ip_and_brackets_ipv6() {
        let v4 = Target::new("example.test", 22, false).with_ip("10.0.0.1".parse().unwrap());
        assert_eq!(v4.dial_addr(), "10.0.0.1:22");
        assert_eq!(v4.host_port(), "example.test:22");
        let v6 = Target::new("example.test", 22, false).with_ip("::1".parse().unwrap());
        assert_eq!(v6.dial_addr(), "[::1]:22");
    }

    #[test]
    fn target_round_trip_preserves_hash_identity_and_ipv6_display() {
        let target = Target {
            host: "::1".into(),
            port: 443,
            ssl: true,
            path: Some("/login?next=/".into()),
            ip: Some("::1".parse().unwrap()),
        };
        let json = serde_json::to_string(&target).unwrap();
        let restored: Target = serde_json::from_str(&json).unwrap();
        assert_eq!(target.to_string(), "[::1]:443/login?next=/");
        assert!(HashSet::from([target]).contains(&restored));

        // Backward compatibility: JSON without "ip" deserializes to ip: None
        let legacy_json = r#"{"host":"example.com","port":80,"ssl":false,"path":null}"#;
        let legacy_target: Target = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(legacy_target.ip, None);
        assert_eq!(legacy_target.host, "example.com");
    }

    #[test]
    fn credentials_preserve_absent_empty_and_present_passwords() {
        for password in [None, Some(String::new()), Some("secret".into())] {
            let credential = Credential {
                username: "admin".into(),
                password,
            };
            let json = serde_json::to_string(&credential).unwrap();
            assert_eq!(
                serde_json::from_str::<Credential>(&json).unwrap(),
                credential
            );
            assert!(!format!("{credential:?}").contains("secret"));
        }
    }

    #[test]
    fn outcomes_preserve_payloads_in_json() {
        for outcome in [
            AuthResult::Success,
            AuthResult::Failure,
            AuthResult::LockedOut,
            AuthResult::RateLimited(Duration::from_millis(150)),
            AuthResult::Error("broken".into()),
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            assert_eq!(serde_json::from_str::<AuthResult>(&json).unwrap(), outcome);
        }
        for status in [
            CanaryStatus::Normal,
            CanaryStatus::WildcardDetected("catch-all".into()),
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(serde_json::from_str::<CanaryStatus>(&json).unwrap(), status);
        }
    }

    #[test]
    fn protocol_errors_display_context_and_round_trip() {
        for (error, text) in [
            (
                ProtocolError::ConnectionError("refused".into()),
                "Connection failed: refused",
            ),
            (
                ProtocolError::Timeout,
                "Timeout while communicating with target",
            ),
            (
                ProtocolError::HandshakeFailed("banner".into()),
                "Protocol handshake failed: banner",
            ),
            (
                ProtocolError::ProxyError("offline".into()),
                "Proxy error: offline",
            ),
            (
                ProtocolError::IncompatibleCipher("diffie-hellman-group1-sha1".into()),
                "Incompatible cipher or algorithm: diffie-hellman-group1-sha1",
            ),
            (
                ProtocolError::Internal("state".into()),
                "Internal module error: state",
            ),
        ] {
            assert_eq!(error.to_string(), text);
            let json = serde_json::to_string(&error).unwrap();
            assert_eq!(serde_json::from_str::<ProtocolError>(&json).unwrap(), error);
        }
    }
}
