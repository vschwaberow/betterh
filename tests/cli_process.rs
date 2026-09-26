// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Exercise the executable with isolated process environments and config files.

use std::process::{Command, Output};

fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_betterh"))
        .args(args)
        .env_clear()
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .envs(env.iter().copied())
        .current_dir(dir.path())
        .output()
        .unwrap()
}

#[test]
fn empty_invocation_prints_quickstart_without_ansi_in_a_pipe() {
    let result = run(&[], &[]);
    assert!(result.status.success());
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("Quickstart:"));
    assert!(stdout.contains("ssh://admin@127.0.0.1:2222"));
    assert!(!stdout.contains('\x1b'));
}

#[test]
fn executable_attack_path_fails_closed_without_leaking_password() {
    let result = run(
        &["ssh", "127.0.0.1", "-u", "admin", "-p", "secret"],
        &[("BETTERH_CONCURRENCY", "32")],
    );
    // Live path is wired; a closed local SSH port still fails the run.
    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(
        stderr.contains("Attack execution failed")
            || stderr.contains("Connection")
            || stderr.contains("Canary")
            || stderr.contains("Timeout")
            || stderr.contains("refused"),
        "unexpected stderr: {stderr}"
    );
    assert!(!stderr.contains("secret"));
}

#[test]
fn executable_rejects_invalid_environment_settings() {
    let result = run(&["ssh", "127.0.0.1"], &[("BETTERH_TIMEOUT_SECS", "0")]);
    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("error: Invalid BETTERH_TIMEOUT_SECS"));
    assert!(stderr.contains("= tip:"));
}

#[test]
fn inherited_proxy_conflicts_with_proxy_list() {
    let result = run(
        &["ssh", "127.0.0.1", "--proxy-list", "proxies.txt"],
        &[("BETTERH_PROXY", "http://localhost:8080")],
    );
    assert!(!result.status.success());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("--proxy-list conflicts")
    );
}

#[test]
fn dry_run_prints_combination_table_without_attacking() {
    let dir = tempfile::tempdir().unwrap();
    let users = dir.path().join("u.txt");
    let passwords = dir.path().join("p.txt");
    std::fs::write(&users, "alice\nbob\n").unwrap();
    std::fs::write(&passwords, "one\ntwo\n").unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_betterh"))
        .args([
            "ssh",
            "127.0.0.1",
            "-L",
            users.to_str().unwrap(),
            "-P",
            passwords.to_str().unwrap(),
            "--dry-run",
            "--timeout-secs",
            "1",
        ])
        .env_clear()
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("Dry-run audit"));
    assert!(stdout.contains("Combinations:  4"));
    assert!(stdout.contains("Targets:       1"));
    assert!(stdout.contains("Proxies:       0"));
    assert!(stdout.contains("No authentication attempts were sent."));
}

#[test]
fn completions_bash_lists_core_subcommands() {
    let result = run(&["completions", "bash"], &[]);
    assert!(result.status.success());
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("wizard"));
    assert!(stdout.contains("completions"));
    assert!(stdout.contains("man"));
}

#[test]
fn man_page_contains_binary_name() {
    let result = run(&["man"], &[]);
    assert!(result.status.success());
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("betterh"));
    assert!(stdout.contains(".TH") || stdout.contains("TH betterh"));
}

#[test]
fn dry_run_jsonl_emits_structured_event() {
    let dir = tempfile::tempdir().unwrap();
    let users = dir.path().join("u.txt");
    let passwords = dir.path().join("p.txt");
    std::fs::write(&users, "alice\n").unwrap();
    std::fs::write(&passwords, "one\n").unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_betterh"))
        .args([
            "ssh",
            "127.0.0.1",
            "-L",
            users.to_str().unwrap(),
            "-P",
            passwords.to_str().unwrap(),
            "--dry-run",
            "--format",
            "jsonl",
            "--timeout-secs",
            "1",
        ])
        .env_clear()
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains(r#""event":"dry_run""#));
    assert!(stdout.contains(r#""combinations":1"#));
}

#[cfg(target_os = "linux")]
#[test]
fn sigint_cancels_huge_dry_run_without_partial_output() {
    use std::{
        process::Stdio,
        time::{Duration, Instant},
    };

    for quiet in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let output_path = dir.path().join("report.jsonl");
        if !quiet {
            std::fs::write(&output_path, "existing report\n").unwrap();
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_betterh"));
        command
            .args([
                "ssh",
                "::/0",
                "-u",
                "test",
                "-p",
                "unused",
                "--dry-run",
                "--format",
                "jsonl",
                "--output",
            ])
            .arg(&output_path)
            .env_clear()
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path())
            .current_dir(dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if quiet {
            command.arg("--quiet");
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut sent = false;
        let mut exited = false;
        while Instant::now() < deadline {
            // Wait for Tokio's SIGINT handler; a fixed startup sleep can race process initialization.
            let registered = std::fs::read_to_string(format!("/proc/{}/status", child.id()))
                .ok()
                .and_then(|status| {
                    status.lines().find_map(|line| {
                        line.strip_prefix("SigCgt:")
                            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
                    })
                })
                .is_some_and(|mask| mask & 2 != 0);
            if registered && !sent {
                sent = Command::new("kill")
                    .args(["-INT", &child.id().to_string()])
                    .status()
                    .is_ok_and(|status| status.success());
            }
            if matches!(child.try_wait(), Ok(Some(_))) {
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !exited {
            let _ = child.kill();
        }
        let output = child.wait_with_output().unwrap();
        assert!(sent, "SIGINT handler was not registered");
        assert!(exited, "dry-run ignored SIGINT until the test deadline");
        assert_eq!(output.status.code(), Some(130));
        assert!(output.stdout.is_empty());
        if quiet {
            assert!(output.stderr.is_empty());
            assert!(!output_path.exists());
        } else {
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                "Dry-run cancelled.\n"
            );
            assert_eq!(
                std::fs::read_to_string(output_path).unwrap(),
                "existing report\n"
            );
        }
    }
}

#[test]
fn invalid_combo_dry_run_preserves_report_file_and_hides_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let combos = dir.path().join("combos.txt");
    let report = dir.path().join("report.jsonl");
    std::fs::write(&combos, "alice:valid\n:sensitive-password\n").unwrap();
    std::fs::write(&report, "existing report\n").unwrap();
    let result = run(
        &[
            "ssh",
            "198.51.100.1",
            "-C",
            combos.to_str().unwrap(),
            "--dry-run",
            "--format",
            "jsonl",
            "--output",
            report.to_str().unwrap(),
        ],
        &[],
    );
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("Combo rows require a nonempty username"));
    assert!(!stderr.contains("sensitive-password"));
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "existing report\n"
    );
}

#[test]
fn dry_run_reports_request_interval_and_zero_work_for_excluded_targets() {
    for (cli_value, env_value, expected) in [
        (None, None, 1000),
        (None, Some("1500"), 1500),
        (Some("2200"), Some("1500"), 2200),
    ] {
        let mut args = vec![
            "ssh",
            "127.0.0.1",
            "-u",
            "test",
            "-p",
            "unused",
            "--dry-run",
            "--exclude",
            "127.0.0.1",
            "--format",
            "jsonl",
        ];
        if let Some(value) = cli_value {
            args.extend(["--request-interval-ms", value]);
        }
        let env: Vec<_> = env_value
            .map(|value| ("BETTERH_REQUEST_INTERVAL_MS", value))
            .into_iter()
            .collect();
        let result = run(&args, &env);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["request_interval_ms"], expected);
        assert_eq!(report["targets"], 0);
        assert_eq!(report["combinations"], 0);
        assert_eq!(report["estimated_ms"], 0);
    }
}

#[test]
fn dry_run_text_displays_configured_request_interval() {
    let result = run(
        &[
            "ssh",
            "127.0.0.1",
            "-u",
            "test",
            "-p",
            "unused",
            "--dry-run",
            "--exclude",
            "127.0.0.1",
            "--request-interval-ms",
            "2200",
        ],
        &[],
    );
    assert!(result.status.success());
    assert!(
        String::from_utf8(result.stdout)
            .unwrap()
            .contains("Min. interval: 2200 ms per target")
    );
}

#[test]
fn dry_run_writes_report_file_in_every_display_mode() {
    for format in [None, Some("text"), Some("json"), Some("jsonl")] {
        for quiet in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("results.jsonl");
            let mut args = vec![
                "ssh",
                "198.51.100.1",
                "-u",
                "test",
                "-p",
                "unused",
                "--dry-run",
                "--output",
                path.to_str().unwrap(),
            ];
            if let Some(format) = format {
                args.extend(["--format", format]);
            }
            if quiet {
                args.push("--quiet");
            }

            let result = run(&args, &[]);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let contents = std::fs::read_to_string(&path).unwrap();
            assert_eq!(contents.lines().count(), 1);
            let event: serde_json::Value = serde_json::from_str(&contents).unwrap();
            assert_eq!(event["event"], "dry_run");
            assert_eq!(event["combinations"], 1);
            let stdout = String::from_utf8(result.stdout).unwrap();
            if !quiet && matches!(format, None | Some("text")) {
                assert!(stdout.contains("Reachability:"));
                assert!(!stdout.contains("\"event\""));
            } else {
                assert!(stdout.is_empty());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }
}

#[test]
fn dry_run_rejects_existing_output_even_with_force() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("results.jsonl");
    std::fs::write(&path, "previous report\n").unwrap();

    for format in ["text", "json", "jsonl"] {
        let result = run(
            &[
                "ssh",
                "198.51.100.1",
                "-u",
                "test",
                "-p",
                "unused",
                "--dry-run",
                "--force",
                "--exclude",
                "198.51.100.1",
                "--format",
                format,
                "--output",
                path.to_str().unwrap(),
            ],
            &[],
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "previous report\n");
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("Failed to create report file"));
    }
}

#[test]
fn dry_run_reports_nonlocal_probe_as_skipped_in_text_and_json() {
    for format in ["text", "jsonl"] {
        let result = run(
            &[
                "ssh",
                "198.51.100.1",
                "-u",
                "test",
                "-p",
                "unused",
                "--dry-run",
                "--format",
                format,
            ],
            &[],
        );
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        if format == "jsonl" {
            let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            assert!(
                report["reachability"]
                    .as_str()
                    .unwrap()
                    .starts_with("skipped (")
            );
            assert_eq!(report["targets"], 1);
            assert_eq!(report["combinations"], 1);
        } else {
            assert!(
                String::from_utf8(result.stdout)
                    .unwrap()
                    .contains("Reachability:  skipped (")
            );
        }
    }
}

#[test]
fn dry_run_extended_protocols_validate_and_estimate_work() {
    for service in [
        "smtp",
        "smtps",
        "mysql",
        "postgres",
        "postgresql",
        "redis",
        "imap",
        "imaps",
        "ldap",
        "ldaps",
    ] {
        let mut args = vec![
            service,
            "127.0.0.1",
            "-u",
            "audit",
            "-p",
            "secret",
            "--dry-run",
            "--format",
            "jsonl",
        ];
        if service == "mysql" || service == "postgres" {
            args.extend(["--database", "appdb"]);
        }
        let result = run(&args, &[]);
        assert!(
            result.status.success(),
            "dry-run for {service} failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["targets"], 1);
        assert_eq!(report["combinations"], 1);
    }
}

#[test]
fn database_flag_rejected_on_non_database_services() {
    for service in ["ssh", "ftp", "http", "smtp", "redis", "imap", "ldap"] {
        let result = run(
            &[
                service,
                "127.0.0.1",
                "-u",
                "test",
                "-p",
                "pass",
                "--database",
                "mydb",
            ],
            &[],
        );
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains("--database requires a mysql or postgres target"),
            "unexpected error for {service}: {stderr}"
        );
    }
}
