// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Success skip rules and shell-injection-safe post-finding hooks.

use std::{
    collections::HashSet,
    io::{self, Write},
    process::Stdio,
};

use thiserror::Error;
use tokio::process::Command;

use crate::protocols::{Credential, Target};

/// CLI-selected termination policy after a successful authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SkipRules {
    pub exit_user: bool,
    pub exit_host: bool,
    pub exit_first: bool,
}

impl SkipRules {
    #[must_use]
    pub const fn new(exit_user: bool, exit_host: bool, exit_first: bool) -> Self {
        Self {
            exit_user,
            exit_host,
            exit_first,
        }
    }
}

/// Mutable skip bookkeeping for an in-flight attack.
#[derive(Debug, Default, Clone)]
pub struct SkipState {
    rules: SkipRules,
    found_users: HashSet<(String, String)>,
    found_hosts: HashSet<String>,
    stop_all: bool,
}

impl SkipState {
    #[must_use]
    pub fn new(rules: SkipRules) -> Self {
        Self {
            rules,
            found_users: HashSet::new(),
            found_hosts: HashSet::new(),
            stop_all: false,
        }
    }

    #[must_use]
    pub fn stop_all(&self) -> bool {
        self.stop_all
    }

    /// Whether this attempt should be skipped given prior findings.
    #[must_use]
    pub fn should_skip(&self, target: &Target, username: &str) -> bool {
        if self.stop_all {
            return true;
        }
        let host = host_key(target);
        if self.rules.exit_host && self.found_hosts.contains(&host) {
            return true;
        }
        if self.rules.exit_user && self.found_users.contains(&(host, username.to_owned())) {
            return true;
        }
        false
    }

    /// Record a successful finding and update skip sets.
    pub fn record_success(&mut self, target: &Target, username: &str) {
        let host = host_key(target);
        if self.rules.exit_user {
            self.found_users.insert((host.clone(), username.to_owned()));
        }
        if self.rules.exit_host {
            self.found_hosts.insert(host);
        }
        if self.rules.exit_first {
            self.stop_all = true;
        }
    }
}

fn host_key(target: &Target) -> String {
    target.host_port()
}

#[derive(Debug, Error)]
pub enum ActionError {
    #[error("on-found command is empty")]
    EmptyCommand,
    #[error("Failed to spawn on-found command: {0}")]
    Spawn(#[from] io::Error),
}

/// Context passed to `--on-found` via environment variables only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundContext<'a> {
    pub service: &'a str,
    pub target: &'a Target,
    pub credential: &'a Credential,
}

/// Split a command string into program + args without invoking a shell.
#[must_use]
pub fn parse_command(command: &str) -> Option<(String, Vec<String>)> {
    let mut parts = command.split_whitespace();
    let program = parts.next()?.to_owned();
    if program.is_empty() {
        return None;
    }
    let args = parts.map(str::to_owned).collect();
    Some((program, args))
}

/// Spawn `--on-found` with credentials supplied only through `BETTERH_*` env vars.
///
/// # Errors
/// Returns an error when the command string is empty or the process cannot be spawned.
pub fn trigger_on_found(command: &str, ctx: &FoundContext<'_>) -> Result<(), ActionError> {
    let Some((program, args)) = parse_command(command) else {
        return Err(ActionError::EmptyCommand);
    };
    let password = ctx.credential.password.as_deref().unwrap_or("");
    let mut child = Command::new(&program);
    child
        .args(&args)
        .env("BETTERH_TARGET", ctx.target.to_string())
        .env("BETTERH_SERVICE", ctx.service)
        .env("BETTERH_USERNAME", &ctx.credential.username)
        .env("BETTERH_PASSWORD", password)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Detach: do not await completion so the attack loop stays responsive.
    let _child = child.spawn()?;
    Ok(())
}

/// Emit an ASCII bell to the given writer (typically stderr).
///
/// # Errors
/// Returns an I/O error when the writer fails.
pub fn ring_bell(out: &mut impl Write) -> io::Result<()> {
    out.write_all(b"\x07")?;
    out.flush()
}

/// Convenience: ring the terminal bell on stderr when `enabled`.
pub fn maybe_bell(enabled: bool) {
    if !enabled {
        return;
    }
    let mut stderr = io::stderr();
    let _ = ring_bell(&mut stderr);
}

/// Run on-found + optional bell for a discovery.
///
/// # Errors
/// Propagates spawn failures from [`trigger_on_found`].
pub fn on_discovery(
    on_found: Option<&str>,
    bell: bool,
    ctx: &FoundContext<'_>,
) -> Result<(), ActionError> {
    maybe_bell(bell);
    if let Some(command) = on_found {
        trigger_on_found(command, ctx)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::fs;

    fn target_user(host: &str, user: &str) -> (Target, Credential) {
        (
            Target::new(host, 22, false),
            Credential {
                username: user.into(),
                password: Some("secret".into()),
            },
        )
    }

    #[test]
    fn exit_user_skips_remaining_passwords_for_same_user() {
        let mut state = SkipState::new(SkipRules::new(true, false, false));
        let (target, cred) = target_user("10.0.0.1", "alice");
        assert!(!state.should_skip(&target, &cred.username));
        state.record_success(&target, &cred.username);
        assert!(state.should_skip(&target, "alice"));
        assert!(!state.should_skip(&target, "bob"));
        assert!(!state.should_skip(&Target::new("10.0.0.2", 22, false), "alice"));
    }

    #[test]
    fn exit_host_skips_entire_host_after_first_hit() {
        let mut state = SkipState::new(SkipRules::new(false, true, false));
        let (target, cred) = target_user("10.0.0.1", "alice");
        state.record_success(&target, &cred.username);
        assert!(state.should_skip(&target, "bob"));
        assert!(!state.should_skip(&Target::new("10.0.0.2", 22, false), "alice"));
    }

    #[test]
    fn exit_first_stops_all_further_attempts() {
        let mut state = SkipState::new(SkipRules::new(false, false, true));
        let (target, cred) = target_user("10.0.0.1", "alice");
        state.record_success(&target, &cred.username);
        assert!(state.stop_all());
        assert!(state.should_skip(&Target::new("10.0.0.9", 22, false), "other"));
    }

    #[test]
    fn parse_command_splits_without_shell() {
        let (program, args) = parse_command("./notify.sh --verbose").unwrap();
        assert_eq!(program, "./notify.sh");
        assert_eq!(args, vec!["--verbose"]);
        assert!(parse_command("   ").is_none());
    }

    #[test]
    fn ring_bell_writes_ascii_bel() {
        let mut buf = Vec::new();
        ring_bell(&mut buf).unwrap();
        assert_eq!(buf, b"\x07");
    }

    #[tokio::test]
    async fn on_found_passes_credentials_only_via_environment() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("env.txt");
        let script = dir.path().join("hook.sh");
        let script_body = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$BETTERH_TARGET\" \"$BETTERH_SERVICE\" \"$BETTERH_USERNAME\" \"$BETTERH_PASSWORD\" > '{}'\n",
            out.display()
        );
        fs::write(&script, script_body).await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script).await.unwrap().permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&script, perms).await.unwrap();
        }

        let target = Target::new("10.0.0.1", 22, false);
        let credential = Credential {
            username: "alice".into(),
            password: Some("p@ss;rm -rf /".into()),
        };
        trigger_on_found(
            &script.display().to_string(),
            &FoundContext {
                service: "ssh",
                target: &target,
                credential: &credential,
            },
        )
        .unwrap();

        // Allow the detached child to finish writing.
        let mut contents = String::new();
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if let Ok(text) = fs::read_to_string(&out).await
                && !text.is_empty()
            {
                contents = text;
                break;
            }
        }
        assert_eq!(contents, "10.0.0.1:22\nssh\nalice\np@ss;rm -rf /\n");
    }
}
