// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! MCP resource catalog and secure URI resolution.

use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::fs;
use tokio::sync::Mutex;

use super::tools::{ToolRuntime, list_protocols_payload};
use crate::engine::checkpoint::{self, Checkpoint};

/// MCP resource descriptor for `resources/list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDescriptor {
    /// Resource URI.
    pub uri: String,
    /// Human-readable name.
    pub name: &'static str,
    /// Description for clients.
    pub description: &'static str,
    /// MIME type of `resources/read` payloads.
    pub mime_type: &'static str,
}

/// One content entry returned by `resources/read`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContent {
    /// Echo of the requested URI.
    pub uri: String,
    /// MIME type.
    pub mime_type: &'static str,
    /// UTF-8 JSON (or text) body.
    pub text: String,
}

/// Resource resolution failures (mapped to JSON-RPC `-32602` by the transport).
#[derive(Debug, Error)]
pub enum ResourceError {
    /// URI is missing, malformed, or uses an unsupported scheme/path.
    #[error("invalid resource URI: {0}")]
    InvalidUri(String),
    /// Report hash failed validation or attempted path traversal.
    #[error("invalid report hash: {0}")]
    InvalidHash(String),
    /// Target file is missing.
    #[error("resource not found: {0}")]
    NotFound(String),
    /// File permissions are not owner-only `0600`.
    #[error("report file must have mode 0600: {0}")]
    InsecureMode(String),
    /// Symlinks are rejected to prevent traversal.
    #[error("report path must not be a symbolic link: {0}")]
    Symlink(String),
    /// Checkpoint / I/O failure after URI validation.
    #[error("resource read failed: {0}")]
    Io(String),
}

/// Shared live metrics for `betterh://session/current` (updated by the server loop).
#[derive(Debug, Default)]
pub struct SessionMetrics {
    inner: Mutex<SessionMetricsState>,
}

#[derive(Debug, Clone, Default)]
struct SessionMetricsState {
    attempts: u64,
    findings: u64,
    rate_per_sec: f64,
    active_targets: u64,
    concurrency: u64,
}

impl SessionMetrics {
    /// Create an empty metrics store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace live counters (used by later attack/session wiring).
    pub async fn set(
        &self,
        attempts: u64,
        findings: u64,
        rate_per_sec: f64,
        active_targets: u64,
        concurrency: u64,
    ) {
        let mut guard = self.inner.lock().await;
        guard.attempts = attempts;
        guard.findings = findings;
        guard.rate_per_sec = rate_per_sec;
        guard.active_targets = active_targets;
        guard.concurrency = concurrency;
    }

    async fn snapshot(&self) -> SessionMetricsState {
        self.inner.lock().await.clone()
    }
}

/// Static + discovered resource catalog.
///
/// # Errors
/// Returns I/O errors while scanning the report base for session checkpoints.
pub async fn list_resources(base_dir: &Path) -> Result<Vec<ResourceDescriptor>, ResourceError> {
    let mut resources = vec![
        ResourceDescriptor {
            uri: "betterh://protocols".into(),
            name: "Protocol registry",
            description: "Compiled protocol capabilities, default ports, and feature states",
            mime_type: "application/json",
        },
        ResourceDescriptor {
            uri: "betterh://session/current".into(),
            name: "Current session",
            description: "Live MCP session metrics, attempt counts, and rate information",
            mime_type: "application/json",
        },
    ];

    let mut entries = fs::read_dir(base_dir)
        .await
        .map_err(|err| ResourceError::Io(format!("cannot list {}: {err}", base_dir.display())))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|err| ResourceError::Io(err.to_string()))?
    {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(hash) = parse_session_filename(name) else {
            continue;
        };
        resources.push(ResourceDescriptor {
            uri: format!("betterh://reports/{hash}"),
            name: "Audit report",
            description: "Checkpointed findings and completed attempts for a session hash",
            mime_type: "application/json",
        });
    }

    resources.sort_by(|left, right| left.uri.cmp(&right.uri));
    Ok(resources)
}

/// Read a resource by URI with path-traversal and mode checks for reports.
///
/// # Errors
/// Returns [`ResourceError`] for invalid URIs, insecure files, or I/O failures.
pub async fn read_resource(
    uri: &str,
    runtime: &ToolRuntime,
    metrics: &SessionMetrics,
    base_dir: &Path,
) -> Result<ResourceContent, ResourceError> {
    let parsed = parse_uri(uri)?;
    match parsed {
        ParsedUri::Protocols => Ok(ResourceContent {
            uri: uri.to_owned(),
            mime_type: "application/json",
            text: list_protocols_payload().to_string(),
        }),
        ParsedUri::SessionCurrent => {
            let live = metrics.snapshot().await;
            let body = json!({
                "phase": runtime.phase,
                "last_tool": runtime.last_tool,
                "last_ok": runtime.last_ok,
                "findings": live.findings.max(runtime.findings),
                "attempts": live.attempts.max(runtime.attempts),
                "rate_per_sec": if live.rate_per_sec > 0.0 {
                    live.rate_per_sec
                } else {
                    runtime.rate_per_sec
                },
                "active_targets": live.active_targets,
                "concurrency": live.concurrency,
            });
            Ok(ResourceContent {
                uri: uri.to_owned(),
                mime_type: "application/json",
                text: body.to_string(),
            })
        }
        ParsedUri::Report { hash } => {
            let path = resolve_report_path(base_dir, &hash)?;
            ensure_secure_report_file(&path).await?;
            let checkpoint = checkpoint::load(&path)
                .await
                .map_err(|err| ResourceError::Io(err.to_string()))?;
            Ok(ResourceContent {
                uri: uri.to_owned(),
                mime_type: "application/json",
                text: checkpoint_report_json(&checkpoint).to_string(),
            })
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedUri {
    Protocols,
    SessionCurrent,
    Report { hash: String },
}

fn parse_uri(uri: &str) -> Result<ParsedUri, ResourceError> {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return Err(ResourceError::InvalidUri("empty URI".into()));
    }
    if trimmed.contains('\0') || trimmed.contains("..") {
        return Err(ResourceError::InvalidUri(
            "path traversal is not allowed".into(),
        ));
    }
    let Some(rest) = trimmed.strip_prefix("betterh://") else {
        return Err(ResourceError::InvalidUri(
            "URI must use the betterh:// scheme".into(),
        ));
    };
    if rest.is_empty() {
        return Err(ResourceError::InvalidUri("missing resource path".into()));
    }
    match rest {
        "protocols" => Ok(ParsedUri::Protocols),
        "session/current" => Ok(ParsedUri::SessionCurrent),
        other => {
            let Some(hash) = other.strip_prefix("reports/") else {
                return Err(ResourceError::InvalidUri(format!(
                    "unknown resource path: {other}"
                )));
            };
            if hash.is_empty() || hash.contains('/') || hash.contains('\\') {
                return Err(ResourceError::InvalidUri(
                    "report URI must be betterh://reports/{{hash}}".into(),
                ));
            }
            validate_hash(hash)?;
            Ok(ParsedUri::Report {
                hash: hash.to_ascii_lowercase(),
            })
        }
    }
}

fn validate_hash(hash: &str) -> Result<(), ResourceError> {
    if hash.is_empty() || hash.len() > 64 {
        return Err(ResourceError::InvalidHash(
            "hash length must be 1..=64 hex characters".into(),
        ));
    }
    if !hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ResourceError::InvalidHash(
            "hash must be hexadecimal".into(),
        ));
    }
    Ok(())
}

fn parse_session_filename(name: &str) -> Option<&str> {
    let hash = name
        .strip_prefix(".betterh-session-")?
        .strip_suffix(".json")?;
    validate_hash(hash).ok()?;
    Some(hash)
}

fn resolve_report_path(base_dir: &Path, hash: &str) -> Result<PathBuf, ResourceError> {
    validate_hash(hash)?;
    for component in base_dir.components() {
        if matches!(component, Component::ParentDir) {
            return Err(ResourceError::InvalidUri(
                "report base directory must not contain '..'".into(),
            ));
        }
    }
    let file_name = format!(".betterh-session-{hash}.json");
    let path = base_dir.join(file_name);
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ResourceError::InvalidUri(
            "path traversal is not allowed".into(),
        ));
    }
    Ok(path)
}

async fn ensure_secure_report_file(path: &Path) -> Result<(), ResourceError> {
    let meta = fs::symlink_metadata(path).await.map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            ResourceError::NotFound(path.display().to_string())
        } else {
            ResourceError::Io(err.to_string())
        }
    })?;
    if meta.file_type().is_symlink() {
        return Err(ResourceError::Symlink(path.display().to_string()));
    }
    if !meta.is_file() {
        return Err(ResourceError::NotFound(path.display().to_string()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(ResourceError::InsecureMode(format!(
                "{} has mode {mode:o}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn checkpoint_report_json(checkpoint: &Checkpoint) -> Value {
    json!({
        "version": checkpoint.version,
        "hash": checkpoint.hash,
        "service": checkpoint.service,
        "next_index": checkpoint.next_index,
        "completed": checkpoint.completed.iter().map(|entry| {
            json!({
                "target": entry.target,
                "username": entry.username,
                // Passwords are omitted from MCP resource reads.
            })
        }).collect::<Vec<_>>(),
        "findings": checkpoint.findings.iter().map(|entry| {
            json!({
                "target": entry.target,
                "username": entry.username,
            })
        }).collect::<Vec<_>>(),
    })
}

/// Helper for tests and later wiring that share metrics across the MCP server.
pub type SharedSessionMetrics = Arc<SessionMetrics>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::checkpoint::{Checkpoint, CheckpointEntry, save};
    use crate::mcp::tools::{SessionPhase, ToolRuntime};
    use crate::protocols::Credential;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn list_includes_static_and_discovered_reports() {
        let dir = tempfile::tempdir().unwrap();
        let mut checkpoint = Checkpoint::new("abc123", "ssh");
        checkpoint.findings.push(CheckpointEntry::new(
            "10.0.0.1:22",
            &Credential {
                username: "alice".into(),
                password: Some("secret".into()),
            },
        ));
        let path = dir.path().join(".betterh-session-abc123.json");
        save(&path, &checkpoint).await.unwrap();

        let listed = list_resources(dir.path()).await.unwrap();
        let uris: Vec<_> = listed.iter().map(|item| item.uri.as_str()).collect();
        assert!(uris.contains(&"betterh://protocols"));
        assert!(uris.contains(&"betterh://session/current"));
        assert!(uris.contains(&"betterh://reports/abc123"));
    }

    #[tokio::test]
    async fn read_protocols_and_session_current() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = ToolRuntime {
            last_tool: Some("audit_dryrun".into()),
            last_ok: true,
            findings: 2,
            attempts: 10,
            rate_per_sec: 1.5,
            phase: SessionPhase::DryRun,
        };
        let metrics = SessionMetrics::new();
        metrics.set(12, 3, 2.0, 1, 16).await;

        let protocols = read_resource("betterh://protocols", &runtime, &metrics, dir.path())
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&protocols.text).unwrap();
        assert!(
            body["protocols"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["name"] == "ssh")
        );

        let session = read_resource("betterh://session/current", &runtime, &metrics, dir.path())
            .await
            .unwrap();
        let session_body: Value = serde_json::from_str(&session.text).unwrap();
        assert_eq!(session_body["attempts"], 12);
        assert_eq!(session_body["findings"], 3);
        assert_eq!(session_body["rate_per_sec"], 2.0);
        assert_eq!(session_body["phase"], "dry_run");
    }

    #[tokio::test]
    async fn read_report_omits_passwords_and_requires_0600() {
        let dir = tempfile::tempdir().unwrap();
        let mut checkpoint = Checkpoint::new("deadbeef", "ssh");
        checkpoint.findings.push(CheckpointEntry::new(
            "10.0.0.1:22",
            &Credential {
                username: "alice".into(),
                password: Some("secret".into()),
            },
        ));
        let path = dir.path().join(".betterh-session-deadbeef.json");
        save(&path, &checkpoint).await.unwrap();

        let runtime = ToolRuntime::default();
        let metrics = SessionMetrics::new();
        let report = read_resource("betterh://reports/deadbeef", &runtime, &metrics, dir.path())
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&report.text).unwrap();
        assert_eq!(body["hash"], "deadbeef");
        assert_eq!(body["findings"][0]["username"], "alice");
        assert!(body["findings"][0].get("password").is_none());
        assert!(!report.text.contains("secret"));

        // Widen permissions and ensure read refuses the file.
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();
        let err = read_resource("betterh://reports/deadbeef", &runtime, &metrics, dir.path())
            .await
            .unwrap_err();
        assert!(matches!(err, ResourceError::InsecureMode(_)));
    }

    #[test]
    fn path_traversal_uris_are_rejected() {
        assert!(matches!(
            parse_uri("betterh://reports/../etc/passwd"),
            Err(ResourceError::InvalidUri(_))
        ));
        assert!(matches!(
            parse_uri("betterh://reports/abc/../deadbeef"),
            Err(ResourceError::InvalidUri(_))
        ));
        assert!(matches!(
            parse_uri("file:///etc/passwd"),
            Err(ResourceError::InvalidUri(_))
        ));
        assert!(matches!(
            parse_uri("betterh://reports/not-hex!"),
            Err(ResourceError::InvalidHash(_))
        ));
    }

    #[tokio::test]
    async fn missing_report_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_resource(
            "betterh://reports/abcdef01",
            &ToolRuntime::default(),
            &SessionMetrics::new(),
            dir.path(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ResourceError::NotFound(_)));
    }
}
