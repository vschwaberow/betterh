// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>
//! Enforce SPEC §16.1: every Rust source under `src/` and `tests/` carries
//! the dual-license SPDX identifier and copyright notice as its first lines.

use std::fs;
use std::path::{Path, PathBuf};

const SPDX: &str = "// SPDX-License-Identifier: MIT OR Apache-2.0";
const COPYRIGHT: &str = "// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>";

fn collect_rust_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", root.display());
    });
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!("failed to read entry under {}: {error}", root.display());
        });
        let path = entry.path();
        let file_type = entry.file_type().unwrap_or_else(|error| {
            panic!("failed to stat {}: {error}", path.display());
        });
        if file_type.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn assert_header(path: &Path) {
    let source = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    });
    let mut lines = source.lines();
    let first = lines.next().unwrap_or("");
    let second = lines.next().unwrap_or("");
    assert_eq!(
        first,
        SPDX,
        "{}: expected first line to be the SPDX identifier",
        path.display()
    );
    assert_eq!(
        second,
        COPYRIGHT,
        "{}: expected second line to be the copyright notice",
        path.display()
    );
}

#[test]
fn all_rust_sources_start_with_spdx_and_copyright() {
    let mut files = Vec::new();
    collect_rust_files(Path::new("src"), &mut files);
    collect_rust_files(Path::new("tests"), &mut files);
    files.sort();
    assert!(
        !files.is_empty(),
        "expected to find Rust sources under src/ and tests/"
    );
    for path in &files {
        assert_header(path);
    }
}
