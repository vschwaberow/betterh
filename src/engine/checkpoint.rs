// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Cooperative session checkpointing with POSIX 0600 permissions.

use std::{
    io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs;

use crate::fsutil;

use crate::protocols::Credential;

const CHECKPOINT_VERSION: u32 = 1;

/// One completed or successful credential attempt recorded for resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointEntry {
    pub target: String,
    pub username: String,
    pub password: Option<String>,
}

impl CheckpointEntry {
    #[must_use]
    pub fn new(target: impl Into<String>, credential: &Credential) -> Self {
        Self {
            target: target.into(),
            username: credential.username.clone(),
            password: credential.password.clone(),
        }
    }
}

/// Serializable session progress (SPEC §8.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub version: u32,
    pub hash: String,
    pub service: String,
    pub completed: Vec<CheckpointEntry>,
    pub findings: Vec<CheckpointEntry>,
    pub next_index: u64,
}

impl Checkpoint {
    #[must_use]
    pub fn new(hash: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            version: CHECKPOINT_VERSION,
            hash: hash.into(),
            service: service.into(),
            completed: Vec::new(),
            findings: Vec::new(),
            next_index: 0,
        }
    }

    /// Default on-disk name for this session hash.
    #[must_use]
    pub fn default_path(&self) -> PathBuf {
        PathBuf::from(format!(".betterh-session-{}.json", self.hash))
    }
}

#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("Checkpoint I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Checkpoint JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Unsupported checkpoint version {found} (expected {CHECKPOINT_VERSION})")]
    UnsupportedVersion { found: u32 },
    #[error("Checkpoint hash mismatch: file has {found}, expected {expected}")]
    HashMismatch { found: String, expected: String },
}

/// Atomically write a checkpoint with mode `0600`.
///
/// # Errors
/// Returns I/O or serialization errors.
pub async fn save(path: &Path, checkpoint: &Checkpoint) -> Result<(), CheckpointError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = match parent {
        Some(dir) => dir.to_path_buf(),
        None => PathBuf::from("."),
    };
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "checkpoint path missing file name",
        )
    })?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    let json = serde_json::to_vec_pretty(checkpoint)?;
    fs::write(&tmp, &json).await?;
    fsutil::set_mode_0600(&tmp).await?;
    fs::rename(&tmp, path).await?;
    // Re-apply after rename for filesystems that don't preserve mode across rename.
    fsutil::set_mode_0600(path).await?;
    Ok(())
}

/// Load a checkpoint document.
///
/// # Errors
/// Returns I/O, JSON, or version/hash validation errors.
pub async fn load(path: &Path) -> Result<Checkpoint, CheckpointError> {
    let bytes = fs::read(path).await?;
    let checkpoint: Checkpoint = serde_json::from_slice(&bytes)?;
    if checkpoint.version != CHECKPOINT_VERSION {
        return Err(CheckpointError::UnsupportedVersion {
            found: checkpoint.version,
        });
    }
    Ok(checkpoint)
}

/// Load and assert the session hash matches the expected value.
///
/// # Errors
/// Returns load errors or a hash mismatch.
pub async fn load_for_hash(
    path: &Path,
    expected_hash: &str,
) -> Result<Checkpoint, CheckpointError> {
    let checkpoint = load(path).await?;
    if checkpoint.hash != expected_hash {
        return Err(CheckpointError::HashMismatch {
            found: checkpoint.hash,
            expected: expected_hash.to_owned(),
        });
    }
    Ok(checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn save_load_round_trip_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".betterh-session-deadbeef.json");
        let mut checkpoint = Checkpoint::new("deadbeef", "ssh");
        checkpoint.completed.push(CheckpointEntry::new(
            "10.0.0.1:22",
            &Credential {
                username: "alice".into(),
                password: Some("wrong".into()),
            },
        ));
        checkpoint.findings.push(CheckpointEntry::new(
            "10.0.0.1:22",
            &Credential {
                username: "alice".into(),
                password: Some("secret".into()),
            },
        ));
        checkpoint.next_index = 7;

        save(&path, &checkpoint).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let restored = load(&path).await.unwrap();
        assert_eq!(restored, checkpoint);
        let matched = load_for_hash(&path, "deadbeef").await.unwrap();
        assert_eq!(matched.findings.len(), 1);
        let err = load_for_hash(&path, "other").await.unwrap_err();
        assert!(matches!(err, CheckpointError::HashMismatch { .. }));
    }

    #[tokio::test]
    async fn default_path_uses_session_hash() {
        let checkpoint = Checkpoint::new("abc123", "ftp");
        assert_eq!(
            checkpoint.default_path(),
            PathBuf::from(".betterh-session-abc123.json")
        );
    }
}
