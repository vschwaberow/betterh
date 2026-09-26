// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Real stdin and isolated-process memory checks for the Phase 2 stream.

use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

use betterh::{
    cli::ManglingRule,
    engine::{
        MutationConfig,
        mutations::RuleSet,
        wordlist::{
            CredentialInput, CredentialStream, InputSource, credentials, credentials_with_mutations,
        },
    },
};
use futures::TryStreamExt;

fn child(case: &str, rows: usize, input: Option<&[u8]>) -> Output {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "wordlist_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("BETTERH_TEST_CASE", case)
        .env("BETTERH_TEST_ROWS", rows.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = child.stdin.take() {
        if case == "memory-stdin" {
            write_rows(&mut stdin, rows);
        } else if let Some(input) = input {
            stdin.write_all(input).unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn stdin_passwords_replay_user_file_after_one_mangling_pass() {
    child("passwords", 0, Some(b"one\r\n\ntwo\n"));
}

#[test]
fn stdin_users_replay_password_file() {
    child("users", 0, Some(b"ab\r\n\ncd"));
}

#[test]
fn stdin_combos_preserve_empty_password_and_colons() {
    child("combos", 0, Some(b"ab:one:two\r\ncd:\n"));
}

#[test]
fn stdin_passwords_work_with_a_single_user() {
    child("single", 0, Some(b"one\ntwo\n"));
}

#[cfg(target_os = "linux")]
#[test]
fn million_line_file_has_flat_memory_below_fifteen_megabytes() {
    assert_flat_memory("memory");
}

#[cfg(target_os = "linux")]
#[test]
fn million_line_pipe_has_flat_memory_below_fifteen_megabytes() {
    assert_flat_memory("memory-stdin");
}

#[cfg(target_os = "linux")]
#[test]
fn million_rule_mutations_have_flat_memory_below_thirty_megabytes() {
    fn peak(output: Output) -> u64 {
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("PEAK_KIB="))
            .unwrap()
            .parse()
            .unwrap()
    }
    let small = peak(child("memory-rules", 10_000, None));
    let large = peak(child("memory-rules", 200_000, None));
    assert!(
        large * 1024 < 30_000_000,
        "Peak RSS {large} KiB exceeds 30 MB"
    );
    assert!(
        large <= small + 2 * 1024,
        "RSS grew from {small} to {large} KiB"
    );
    println!(
        "memory-rules peak RSS: 50,000 candidates = {small} KiB; 1,000,000 candidates = {large} KiB"
    );
}

#[cfg(target_os = "linux")]
fn assert_flat_memory(case: &str) {
    fn peak(output: Output) -> u64 {
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("PEAK_KIB="))
            .unwrap()
            .parse()
            .unwrap()
    }
    let small = peak(child(case, 10_000, None));
    let large = peak(child(case, 1_000_000, None));
    assert!(
        large * 1024 < 15_000_000,
        "Peak RSS {large} KiB exceeds 15 MB"
    );
    assert!(
        large <= small + 2 * 1024,
        "RSS grew from {small} to {large} KiB"
    );
    println!("{case} peak RSS: 10,000 lines = {small} KiB; 1,000,000 lines = {large} KiB");
}

fn write_rows(writer: impl Write, rows: usize) {
    let mut writer = std::io::BufWriter::new(writer);
    for _ in 0..rows {
        writer
            .write_all(b"012345678901234567890123456789012345678901234567890123456789012\n")
            .unwrap();
    }
    writer.flush().unwrap();
}

async fn count_and_report(mut stream: CredentialStream, rows: usize) {
    let mut count = 0;
    while let Some(credential) = stream.try_next().await.unwrap() {
        assert_eq!(credential.username, "ab");
        count += 1;
    }
    assert_eq!(count, rows);
    #[cfg(target_os = "linux")]
    {
        let status = tokio::fs::read_to_string("/proc/self/status")
            .await
            .unwrap();
        let peak = status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap();
        println!("\nPEAK_KIB={peak}");
    }
}

// Re-executing just this test isolates process stdin and RSS from the test harness.
#[test]
fn wordlist_child() {
    let Ok(case) = std::env::var("BETTERH_TEST_CASE") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let users = dir.path().join("users");
    let passwords = dir.path().join("passwords");
    std::fs::write(&users, "ab\ncd\n").unwrap();
    std::fs::write(&passwords, "one\ntwo\n").unwrap();
    let rows = std::env::var("BETTERH_TEST_ROWS")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    if matches!(case.as_str(), "memory" | "memory-rules") {
        write_rows(std::fs::File::create(&passwords).unwrap(), rows);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let source = match case.as_str() {
            "passwords" => CredentialInput::Product {
                users: InputSource::File(users),
                passwords: Some(InputSource::Stdin),
            },
            "users" => CredentialInput::Product {
                users: InputSource::Stdin,
                passwords: Some(InputSource::File(passwords)),
            },
            "single" | "memory-stdin" => CredentialInput::Product {
                users: InputSource::Single("ab".into()),
                passwords: Some(InputSource::Stdin),
            },
            "combos" => CredentialInput::Combos(InputSource::Stdin),
            "memory" | "memory-rules" => CredentialInput::Product {
                users: InputSource::Single("ab".into()),
                passwords: Some(InputSource::File(passwords)),
            },
            _ => panic!("Unknown child test case"),
        };
        if case == "memory-rules" {
            let rules_content = "c\n$!\nu\n$1\n^0";
            let rule_set: RuleSet = rules_content.parse().unwrap();
            let config = MutationConfig {
                mangling: &[],
                rule_set: Some(&rule_set),
                rule_year: None,
            };
            let stream = credentials_with_mutations(source, &config).unwrap();
            count_and_report(stream, rows * 5).await;
            return;
        }
        let rules = if case == "passwords" {
            &[ManglingRule::Empty, ManglingRule::Reverse][..]
        } else {
            &[]
        };
        let stream = credentials(source, rules).unwrap();
        if matches!(case.as_str(), "memory" | "memory-stdin") {
            count_and_report(stream, rows).await;
            return;
        }
        let actual: Vec<_> = stream.try_collect().await.unwrap();
        let actual: Vec<_> = actual
            .iter()
            .map(|credential| {
                (
                    credential.username.as_str(),
                    credential.password.as_deref().unwrap(),
                )
            })
            .collect();
        let expected = match case.as_str() {
            "passwords" => vec![
                ("ab", ""),
                ("ab", "ba"),
                ("cd", ""),
                ("cd", "dc"),
                ("ab", "one"),
                ("cd", "one"),
                ("ab", "two"),
                ("cd", "two"),
            ],
            "users" => vec![("ab", "one"), ("ab", "two"), ("cd", "one"), ("cd", "two")],
            "single" => vec![("ab", "one"), ("ab", "two")],
            "combos" => vec![("ab", "one:two"), ("cd", "")],
            _ => panic!("Unknown child test case"),
        };
        assert_eq!(actual, expected);
    });
}
