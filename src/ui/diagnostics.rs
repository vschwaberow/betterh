// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Cargo-style actionable diagnostics for operator-facing errors.

use std::fmt::{self, Write as _};

use crate::config::ConfigError;

/// Category of a user-facing diagnostic message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticKind {
    Connection,
    Tls,
    Config,
    Protocol,
    Other,
}

/// Structured diagnostic with optional location, cause, and remediation tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub kind: DiagnosticKind,
    pub message: String,
    pub location: Option<String>,
    pub cause: Option<String>,
    pub tip: Option<String>,
}

impl Diagnostic {
    /// Build a connection-refused style diagnostic for a target.
    #[must_use]
    pub fn connection_failed(host_port: &str, service: &str, cause: impl Into<String>) -> Self {
        Self {
            kind: DiagnosticKind::Connection,
            message: format!("connection to {host_port} failed"),
            location: Some(format!("target: {host_port} ({service})")),
            cause: Some(cause.into()),
            tip: Some(format!(
                "Verify that the {service} service is running and not blocked by a local firewall.\nTry: probe {host_port} from this host"
            )),
        }
    }

    /// Build a TLS handshake failure diagnostic.
    #[must_use]
    pub fn tls_handshake_failed(url: &str, cause: impl Into<String>) -> Self {
        Self {
            kind: DiagnosticKind::Tls,
            message: format!("TLS handshake failed for {url}"),
            location: Some(format!("target: {url}")),
            cause: Some(cause.into()),
            tip: Some(
                "Use `--insecure` or `-k` to bypass TLS certificate validation for testing.".into(),
            ),
        }
    }

    /// Build a configuration / CLI diagnostic.
    #[must_use]
    pub fn config(message: impl Into<String>, tip: impl Into<String>) -> Self {
        Self {
            kind: DiagnosticKind::Config,
            message: message.into(),
            location: None,
            cause: None,
            tip: Some(tip.into()),
        }
    }

    /// Map a [`ConfigError`] into an actionable diagnostic.
    #[must_use]
    pub fn from_config_error(error: &ConfigError) -> Self {
        let tip = match error {
            ConfigError::Read { path, .. } => format!(
                "Confirm that {} exists and is readable, or omit --config to use defaults.",
                path.display()
            ),
            ConfigError::Parse { path, .. } => format!(
                "Fix TOML syntax in {} (unknown keys are rejected). See docs/SPEC.md §9.3.",
                path.display()
            ),
            ConfigError::Environment(key) => {
                format!("Set {key} to a positive integer or valid value; unset it to use defaults.")
            }
            ConfigError::CurrentDirectory(_) => {
                "Run betterh from a readable working directory.".into()
            }
            ConfigError::Proxy => {
                "Use an http:// or socks5:// URL with a host and no path, query, or fragment."
                    .into()
            }
            ConfigError::ProxyConflict => {
                "Choose either --proxy / BETTERH_PROXY / config proxy, or --proxy-list — not both."
                    .into()
            }
        };
        Self::config(error.to_string(), tip)
    }

    /// Build a protocol-layer diagnostic with optional cause.
    #[must_use]
    pub fn protocol(
        message: impl Into<String>,
        location: Option<String>,
        cause: Option<String>,
        tip: Option<String>,
    ) -> Self {
        Self {
            kind: DiagnosticKind::Protocol,
            message: message.into(),
            location,
            cause,
            tip,
        }
    }

    /// Render as a multi-line Cargo-style error block.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "error: {}", self.message);
        if let Some(location) = &self.location {
            let _ = writeln!(out, "  --> {location}");
        }
        if let Some(cause) = &self.cause {
            let _ = writeln!(out, "  = cause: {cause}");
        }
        if let Some(tip) = &self.tip {
            let mut lines = tip.lines();
            if let Some(first) = lines.next() {
                let _ = writeln!(out, "  = tip: {first}");
                for line in lines {
                    let _ = writeln!(out, "         {line}");
                }
            }
        }
        out
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_diagnostic_matches_spec_shape() {
        let diag = Diagnostic::connection_failed(
            "192.168.1.50:22",
            "SSH",
            "Connection refused (os error 111)",
        );
        let rendered = diag.render();
        assert!(
            rendered.starts_with("error: connection to 192.168.1.50:22 failed\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("--> target: 192.168.1.50:22 (SSH)"),
            "{rendered}"
        );
        assert!(
            rendered.contains("= cause: Connection refused (os error 111)"),
            "{rendered}"
        );
        assert!(
            rendered.contains("= tip: Verify that the SSH service is running"),
            "{rendered}"
        );
        assert!(
            rendered.contains("Try: probe 192.168.1.50:22 from this host"),
            "{rendered}"
        );
    }

    #[test]
    fn tls_diagnostic_suggests_insecure_flag() {
        let diag = Diagnostic::tls_handshake_failed(
            "https://10.0.0.5:8443/login",
            "Invalid certificate authority (self-signed certificate)",
        );
        let rendered = diag.to_string();
        assert!(rendered.contains("error: TLS handshake failed for https://10.0.0.5:8443/login"));
        assert!(rendered.contains("--> target: https://10.0.0.5:8443/login"));
        assert!(rendered.contains("Use `--insecure` or `-k`"));
    }

    #[test]
    fn config_diagnostic_omits_empty_sections() {
        let diag = Diagnostic::config(
            "both username sources cannot read from stdin",
            "Use `-L users.txt` or `-u admin`, not both with `-`",
        );
        let rendered = diag.render();
        assert_eq!(
            rendered,
            "error: both username sources cannot read from stdin\n  = tip: Use `-L users.txt` or `-u admin`, not both with `-`\n"
        );
        assert!(!rendered.contains("-->"));
        assert!(!rendered.contains("= cause:"));
    }

    #[test]
    fn config_error_mapping_includes_remediation_tip() {
        let err = ConfigError::Environment("BETTERH_TIMEOUT_SECS");
        let rendered = Diagnostic::from_config_error(&err).render();
        assert!(rendered.contains("error: Invalid BETTERH_TIMEOUT_SECS"));
        assert!(rendered.contains("= tip: Set BETTERH_TIMEOUT_SECS"));
    }
}
