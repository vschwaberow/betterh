// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Streaming JSONL reporter with owner-only file permissions.

use std::{
    io::{self, BufWriter, Stdout, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::fsutil;
use crate::protocols::{AuthResult, Credential, Target};

/// One line of structured telemetry for pipes, files, and SIEM ingestion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ReportEvent {
    /// Successful authentication discovery.
    Success {
        service: String,
        target: String,
        username: String,
        password: Option<String>,
    },
    /// Non-success auth outcome worth recording (optional audit trail).
    Attempt {
        service: String,
        target: String,
        username: String,
        result: AuthResult,
    },
    /// Operator-visible warning (rate limit, lockout, etc.).
    Warn { message: String },
    /// Periodic progress snapshot.
    Stats {
        completed: u64,
        found: u64,
        rate_per_sec: f64,
        active_targets: usize,
        concurrency: usize,
    },
    /// Pre-flight dry-run combination audit.
    DryRun {
        service: String,
        target: String,
        targets: u64,
        proxies: u64,
        users: u64,
        passwords: u64,
        combinations: u64,
        concurrency: u64,
        estimated_ms: u128,
        request_interval_ms: u64,
        reachability: String,
    },
}

impl ReportEvent {
    /// Build a success event from domain types.
    #[must_use]
    pub fn success(service: &str, target: &Target, cred: &Credential) -> Self {
        Self::Success {
            service: service.into(),
            target: target.to_string(),
            username: cred.username.clone(),
            password: cred.password.clone(),
        }
    }

    /// Build an attempt event from domain types.
    #[must_use]
    pub fn attempt(service: &str, target: &Target, cred: &Credential, result: AuthResult) -> Self {
        Self::Attempt {
            service: service.into(),
            target: target.to_string(),
            username: cred.username.clone(),
            result,
        }
    }
}

#[derive(Debug, Error)]
pub enum JsonlError {
    #[error("Failed to create report file {}: {source}", path.display())]
    Create { path: PathBuf, source: io::Error },
    #[error("Failed to write JSONL event: {0}")]
    Write(#[from] io::Error),
    #[error("Failed to serialize JSONL event: {0}")]
    Serialize(#[from] serde_json::Error),
}

enum Sink {
    Stdout(BufWriter<Stdout>),
    File(BufWriter<std::fs::File>),
}

/// Streams [`ReportEvent`] values as newline-delimited JSON.
pub struct JsonlReporter {
    sink: Sink,
}

impl JsonlReporter {
    /// Write JSONL lines to stdout (typically for pipes / `--format jsonl`).
    #[must_use]
    pub fn stdout() -> Self {
        Self {
            sink: Sink::Stdout(BufWriter::new(io::stdout())),
        }
    }

    /// Create a new `path` with owner-only permissions and stream JSONL into it.
    ///
    /// # Errors
    /// Returns [`JsonlError::Create`] if the path already exists or creation fails.
    pub fn file(path: impl AsRef<Path>) -> Result<Self, JsonlError> {
        let path = path.as_ref();
        let file = fsutil::open_owner_only(path).map_err(|source| JsonlError::Create {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self {
            sink: Sink::File(BufWriter::new(file)),
        })
    }

    /// Serialize one event as a single JSON line and flush.
    ///
    /// # Errors
    /// Returns [`JsonlError`] when serialization or writing fails.
    pub fn emit(&mut self, event: &ReportEvent) -> Result<(), JsonlError> {
        let writer: &mut dyn Write = match &mut self.sink {
            Sink::Stdout(w) => w,
            Sink::File(w) => w,
        };
        serde_json::to_writer(&mut *writer, event)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{AuthResult, Credential, Target};

    #[test]
    fn success_event_round_trips_through_jsonl() {
        let target = Target {
            host: "10.0.0.1".into(),
            port: 22,
            ssl: false,
            path: None,
            ip: None,
        };
        let cred = Credential {
            username: "admin".into(),
            password: Some("s3cret".into()),
        };
        let event = ReportEvent::success("ssh", &target, &cred);
        let line = serde_json::to_string(&event).unwrap();
        let restored: ReportEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(restored, event);
        assert!(line.contains(r#""event":"success""#));
        assert!(line.contains(r#""password":"s3cret""#));
    }

    #[test]
    fn attempt_event_preserves_auth_result() {
        let target = Target {
            host: "example.test".into(),
            port: 80,
            ssl: false,
            path: Some("/login".into()),
            ip: None,
        };
        let cred = Credential {
            username: "user".into(),
            password: None,
        };
        let event = ReportEvent::attempt("http", &target, &cred, AuthResult::LockedOut);
        let restored: ReportEvent =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(restored, event);
    }

    #[test]
    fn file_reporter_rejects_existing_file_without_modifying_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("results.jsonl");
        std::fs::write(&path, "previous report\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        let result = JsonlReporter::file(&path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "previous report\n");
        assert!(matches!(result, Err(JsonlError::Create { source, .. })
            if source.kind() == io::ErrorKind::AlreadyExists));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_reporter_rejects_symlinks_including_dangling_links() {
        for target_exists in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("target");
            let path = dir.path().join("results.jsonl");
            if target_exists {
                std::fs::write(&target, "keep me\n").unwrap();
            }
            std::os::unix::fs::symlink(&target, &path).unwrap();

            let result = JsonlReporter::file(&path);
            assert_eq!(target.exists(), target_exists);
            if target_exists {
                assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep me\n");
            }
            assert_eq!(std::fs::read_link(&path).unwrap(), target);
            assert!(matches!(result, Err(JsonlError::Create { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists));
        }
    }

    #[test]
    fn file_reporter_rejects_hard_links_without_modifying_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let path = dir.path().join("results.jsonl");
        std::fs::write(&target, "keep me\n").unwrap();
        std::fs::hard_link(&target, &path).unwrap();

        let result = JsonlReporter::file(&path);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep me\n");
        assert!(matches!(result, Err(JsonlError::Create { source, .. })
            if source.kind() == io::ErrorKind::AlreadyExists));
    }

    #[test]
    fn file_reporter_writes_jsonl_with_owner_only_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("results.jsonl");
        let mut reporter = JsonlReporter::file(&path).unwrap();
        reporter
            .emit(&ReportEvent::Warn {
                message: "throttling".into(),
            })
            .unwrap();
        drop(reporter);

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.ends_with('\n'));
        let parsed: ReportEvent = serde_json::from_str(contents.trim_end()).unwrap();
        assert_eq!(
            parsed,
            ReportEvent::Warn {
                message: "throttling".into()
            }
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
