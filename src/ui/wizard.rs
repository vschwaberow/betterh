// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Interactive setup wizard (`betterh wizard` / `--interactive`).

use std::num::NonZeroUsize;
use std::path::PathBuf;

use thiserror::Error;

/// Service choices offered by the guided wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardService {
    Ftp,
    Ssh,
    Http,
    Https,
    Smtp,
    Mysql,
    Postgres,
}

impl WizardService {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ftp => "ftp",
            Self::Ssh => "ssh",
            Self::Http => "http",
            Self::Https => "https",
            Self::Smtp => "smtp",
            Self::Mysql => "mysql",
            Self::Postgres => "postgres",
        }
    }
}

impl std::fmt::Display for WizardService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Attack plan produced by the wizard; maps cleanly onto CLI flags for the operator to re-run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardPlan {
    pub service: WizardService,
    pub target: String,
    pub user_list: Option<PathBuf>,
    pub username: Option<String>,
    pub password_list: Option<PathBuf>,
    pub concurrency: NonZeroUsize,
    pub proxy: Option<String>,
}

impl WizardPlan {
    /// Render an equivalent argv suitable for logging / dry-run display.
    #[must_use]
    pub fn to_argv(&self) -> Vec<String> {
        let mut args = vec![
            "betterh".into(),
            self.service.as_str().into(),
            self.target.clone(),
        ];
        if let Some(user) = &self.username {
            args.push("-u".into());
            args.push(user.clone());
        }
        if let Some(path) = &self.user_list {
            args.push("-L".into());
            args.push(path.display().to_string());
        }
        if let Some(path) = &self.password_list {
            args.push("-P".into());
            args.push(path.display().to_string());
        }
        args.push("--concurrency".into());
        args.push(self.concurrency.to_string());
        if let Some(proxy) = &self.proxy {
            args.push("--proxy".into());
            args.push(proxy.clone());
        }
        args
    }

    /// Operator-facing summary after guided setup (non-attack path).
    #[must_use]
    pub fn ready_message(&self) -> String {
        format!(
            "Wizard plan ready. Re-run with:\n  {}\n\nNo authentication attempts were sent.",
            self.to_argv().join(" ")
        )
    }
}

#[derive(Debug, Error)]
pub enum WizardError {
    #[error("Wizard cancelled by user")]
    Cancelled,
    #[error("Invalid wizard input: {0}")]
    Invalid(String),
    #[error(transparent)]
    Inquire(#[from] inquire::InquireError),
}

/// Build a plan from already-chosen values (unit-test / non-interactive path).
///
/// The interactive `inquire` prompts live behind [`run_interactive`]; this
/// helper validates the same invariants without touching the TTY.
///
/// # Errors
/// Returns [`WizardError::Invalid`] when required fields are missing or empty.
pub fn plan_from_answers(
    service: WizardService,
    target: String,
    username: Option<String>,
    user_list: Option<PathBuf>,
    password_list: Option<PathBuf>,
    concurrency: NonZeroUsize,
    proxy: Option<String>,
) -> Result<WizardPlan, WizardError> {
    if target.trim().is_empty() {
        return Err(WizardError::Invalid("target must not be empty".into()));
    }
    if username.is_none() && user_list.is_none() {
        return Err(WizardError::Invalid(
            "provide a username (-u) or a user list (-L)".into(),
        ));
    }
    if password_list.is_none() {
        return Err(WizardError::Invalid("provide a password list (-P)".into()));
    }
    Ok(WizardPlan {
        service,
        target,
        user_list,
        username,
        password_list,
        concurrency,
        proxy,
    })
}

/// Run the interactive inquire prompts and return a validated plan.
///
/// # Errors
/// Returns [`WizardError::Cancelled`] when the operator aborts a prompt, or
/// [`WizardError::Invalid`] / [`WizardError::Inquire`] on bad input / I/O.
pub fn run_interactive() -> Result<WizardPlan, WizardError> {
    use inquire::{Select, Text};

    let service = Select::new(
        "Service",
        vec![
            WizardService::Ftp,
            WizardService::Ssh,
            WizardService::Http,
            WizardService::Https,
            WizardService::Smtp,
            WizardService::Mysql,
            WizardService::Postgres,
        ],
    )
    .prompt()?;

    let target = Text::new("Target (host, host:port, URL, or CIDR)")
        .prompt()
        .map_err(map_inquire)?;

    let user_mode = Select::new(
        "Username source",
        vec!["Single user (-u)", "User list (-L)"],
    )
    .prompt()
    .map_err(map_inquire)?;

    let (username, user_list) = if user_mode.starts_with("Single") {
        let user = Text::new("Username").prompt().map_err(map_inquire)?;
        (Some(user), None)
    } else {
        let path = Text::new("Path to username list")
            .prompt()
            .map_err(map_inquire)?;
        (None, Some(PathBuf::from(path)))
    };

    let password_list = PathBuf::from(
        Text::new("Path to password list (-P)")
            .prompt()
            .map_err(map_inquire)?,
    );

    let concurrency_raw = Text::new("Concurrency")
        .with_default("16")
        .prompt()
        .map_err(map_inquire)?;
    let concurrency: NonZeroUsize = concurrency_raw
        .parse()
        .map_err(|_| WizardError::Invalid(format!("invalid concurrency: {concurrency_raw}")))?;

    let proxy_raw = Text::new("Proxy URL (optional, empty to skip)")
        .with_default("")
        .prompt()
        .map_err(map_inquire)?;
    let proxy = if proxy_raw.trim().is_empty() {
        None
    } else {
        Some(proxy_raw)
    };

    plan_from_answers(
        service,
        target,
        username,
        user_list,
        Some(password_list),
        concurrency,
        proxy,
    )
}

fn map_inquire(err: inquire::InquireError) -> WizardError {
    match err {
        inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted => {
            WizardError::Cancelled
        }
        other => WizardError::Inquire(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_from_answers_builds_equivalent_argv() {
        let plan = plan_from_answers(
            WizardService::Ssh,
            "10.0.0.5:22".into(),
            Some("admin".into()),
            None,
            Some(PathBuf::from("rockyou.txt")),
            NonZeroUsize::new(32).unwrap(),
            Some("socks5://127.0.0.1:9050".into()),
        )
        .unwrap();

        assert_eq!(
            plan.to_argv(),
            vec![
                "betterh",
                "ssh",
                "10.0.0.5:22",
                "-u",
                "admin",
                "-P",
                "rockyou.txt",
                "--concurrency",
                "32",
                "--proxy",
                "socks5://127.0.0.1:9050",
            ]
        );
    }

    #[test]
    fn plan_rejects_missing_credential_sources() {
        let err = plan_from_answers(
            WizardService::Ftp,
            "192.168.1.1".into(),
            None,
            None,
            Some(PathBuf::from("p.txt")),
            NonZeroUsize::new(8).unwrap(),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, WizardError::Invalid(_)));
    }

    #[test]
    fn ready_message_lists_argv_and_confirms_no_attack() {
        let plan = plan_from_answers(
            WizardService::Ssh,
            "10.0.0.5:22".into(),
            Some("admin".into()),
            None,
            Some(PathBuf::from("rockyou.txt")),
            NonZeroUsize::new(32).unwrap(),
            None,
        )
        .unwrap();
        let message = plan.ready_message();
        assert!(
            message.contains("betterh ssh 10.0.0.5:22 -u admin -P rockyou.txt --concurrency 32")
        );
        assert!(message.contains("No authentication attempts were sent."));
        assert!(!message.contains("not implemented"));
    }
}
