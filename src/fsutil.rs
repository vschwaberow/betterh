// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Owner-only file helpers (POSIX mode `0600`).

use std::{fs::OpenOptions, io, path::Path};

use tokio::fs;

/// Atomically create a new file with mode `0600` on Unix, subject to umask.
///
/// # Errors
/// Returns an I/O error if the path already exists (including a symbolic link)
/// or the file cannot be created.
pub fn open_owner_only(path: &Path) -> io::Result<std::fs::File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Set mode `0600` on an existing path (no-op on non-Unix).
///
/// # Errors
/// Returns an I/O error when metadata or chmod fails.
pub async fn set_mode_0600(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).await?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms).await?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
