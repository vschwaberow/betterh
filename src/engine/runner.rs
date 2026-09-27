// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Live attack orchestration: scope → canary → pool/spray → reporting.

use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use futures::StreamExt;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use crate::cli::{AttackMode, Cli, TargetInput};
use crate::config::Config;
use crate::engine::canary::{self, CanaryError};
use crate::engine::scope::{Scope, ScopeError};
use crate::engine::targets::{TargetError, expand};
use crate::engine::wordlist::{CredentialInput, InputSource, WordlistError};
use crate::engine::{
    Attempt, Checkpoint, CheckpointEntry, Finding, FoundContext, MutationConfig, Pacer, PoolConfig,
    PoolError, RuntimeCommand, SkipRules, SkipState, SprayConfig, SprayRound,
    credentials_with_mutations, listen_keys, on_discovery, prepare_target, run_brute, run_spray,
    save_checkpoint,
};
use crate::protocols::{Credential, ProtocolError, ProtocolModule, Target};
use crate::report::{ReporterMode, SessionReporter};
use crate::service::Service;

#[derive(Debug, Error)]
pub enum RunError {
    #[error("Attack cancelled")]
    Cancelled,
    #[error("Live attack requires credentials: use -u/-L and -p/-P, or -C")]
    MissingCredentials,
    #[error(transparent)]
    Wordlist(#[from] WordlistError),
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error(transparent)]
    Target(#[from] TargetError),
    #[error(transparent)]
    Pool(#[from] PoolError),
    #[error(transparent)]
    Canary(#[from] CanaryError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("Reporting failed: {0}")]
    Report(String),
    #[error("Checkpoint failed: {0}")]
    Checkpoint(String),
    #[error("{0}")]
    Message(String),
}

/// Execute a live authentication audit for the validated CLI invocation.
///
/// # Errors
/// Returns typed failures for credentials, scope, canary, pool, or reporting.
#[expect(
    clippy::too_many_lines,
    reason = "Live attack orchestration intentionally keeps admission, reporting, and pool dispatch in one function"
)]
pub async fn run_attack(
    cli: &Cli,
    config: &Config,
    input: &TargetInput,
) -> Result<Vec<Finding>, RunError> {
    let cancel = CancellationToken::new();
    let ctrl = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        ctrl.cancel();
    });

    let (key_tx, mut key_rx) = mpsc::channel(8);
    if !cli.quiet && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let key_cancel = cancel.clone();
        tokio::spawn(async move {
            let _ = listen_keys(key_tx, key_cancel).await;
        });
    }

    let module = build_module(cli, config, input.service)?;
    let scope = Scope::load(cli.exclude.clone(), cli.exclude_file.as_deref()).await?;
    let timeout = Duration::from_secs(config.timeout_secs.get());

    let rule_set = cli
        .rules_file
        .as_deref()
        .map(crate::engine::mutations::RuleSet::from_file)
        .transpose()
        .map_err(WordlistError::from)?;

    let mut prepared = Vec::new();
    let mut stream = expand(input.clone(), scope.clone());
    while let Some(item) = stream.next().await {
        if cancel.is_cancelled() {
            return Err(RunError::Cancelled);
        }
        let target = prepare_target(item?, &scope, cli.force).await?;
        canary::check(module.as_ref(), &target, cli.force, timeout, &cancel).await?;
        prepared.push(target);
    }
    if prepared.is_empty() {
        return Err(RunError::Message(
            "No targets remain after exclusions and scope checks".into(),
        ));
    }

    let mutation_config = MutationConfig {
        mangling: &cli.mangling,
        rule_set: rule_set.as_ref(),
        rule_year: cli.rule_year,
    };
    let mut cred_stream =
        credentials_with_mutations(credential_input(cli, input)?, &mutation_config)?;
    let mut credentials_list = Vec::new();
    while let Some(item) = cred_stream.next().await {
        if cancel.is_cancelled() {
            return Err(RunError::Cancelled);
        }
        credentials_list.push(item?);
    }
    if credentials_list.is_empty() {
        return Err(RunError::MissingCredentials);
    }

    let skip = Arc::new(Mutex::new(SkipState::new(SkipRules::new(
        cli.exit_user,
        cli.exit_host,
        cli.exit_first,
    ))));
    let (live_tx, mut live_rx) = mpsc::unbounded_channel::<Finding>();
    let total =
        u64::try_from(prepared.len().saturating_mul(credentials_list.len())).unwrap_or(u64::MAX);
    let mut session = SessionReporter::open(
        ReporterMode::from_cli(cli.format, cli.quiet),
        cli.quiet,
        cli.output.as_deref(),
        Some(total),
    )
    .map_err(|error| RunError::Report(error.to_string()))?;

    let service = service_name(input.service);
    let on_found = cli.on_found.clone();
    let bell = cli.bell;
    let findings_buf = Arc::new(Mutex::new(Vec::<Finding>::new()));
    let findings_for_live = Arc::clone(&findings_buf);
    let live_cancel = cancel.clone();
    let live_task = tokio::spawn(async move {
        while let Some(finding) = live_rx.recv().await {
            let _ = session.success(service, &finding.target, &finding.credential);
            let _ = on_discovery(
                on_found.as_deref(),
                bell,
                &FoundContext {
                    service,
                    target: &finding.target,
                    credential: &finding.credential,
                },
            );
            findings_for_live.lock().await.push(finding);
            if live_cancel.is_cancelled() {
                break;
            }
        }
        session.finish();
    });

    let pool = PoolConfig::new(config.concurrency.get(), timeout, cancel.clone())
        .with_skip(Arc::clone(&skip))
        .with_pacer(Pacer::new(cli.delay, cli.jitter))
        .with_live_findings(live_tx);

    let module_for_attack = Arc::clone(&module);
    let prepared_for_attack = prepared.clone();
    let creds_for_attack = credentials_list.clone();
    let mode = cli.mode;
    let spray_cooldown = cli.spray_cooldown;
    let mut attack = tokio::spawn(async move {
        match mode {
            AttackMode::BruteForce => {
                let attempts = build_attempts(&prepared_for_attack, &creds_for_attack);
                run_brute(module_for_attack, attempts, pool).await
            }
            AttackMode::Spray => {
                let rounds = build_spray_rounds(&prepared_for_attack, &creds_for_attack);
                run_spray(
                    module_for_attack,
                    rounds,
                    SprayConfig::new(pool, spray_cooldown),
                )
                .await
            }
        }
    });

    let hash = session_hash(input.service, cli);
    let checkpoint_path = cli
        .resume
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!(".betterh-session-{hash}.json")));

    let result = loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                attack.abort();
                let findings = findings_buf.lock().await.clone();
                let _ = write_checkpoint(&checkpoint_path, input.service, &hash, &findings).await;
                break Err(RunError::Cancelled);
            }
            cmd = key_rx.recv() => {
                if let Some(RuntimeCommand::SaveCheckpoint) = cmd {
                    let findings = findings_buf.lock().await.clone();
                    let _ = write_checkpoint(
                        &checkpoint_path,
                        input.service,
                        &hash,
                        &findings,
                    )
                    .await;
                } else if let Some(RuntimeCommand::Shutdown) = cmd {
                    cancel.cancel();
                }
            }
            joined = &mut attack => {
                break match joined {
                    Ok(Ok(findings)) => Ok(findings),
                    Ok(Err(PoolError::Cancelled)) => Err(RunError::Cancelled),
                    Ok(Err(error)) => Err(RunError::Pool(error)),
                    Err(error) => Err(RunError::Message(error.to_string())),
                };
            }
        }
    };

    let _ = live_task.await;
    if let (Ok(findings), Some(_)) = (&result, &cli.resume) {
        write_checkpoint(&checkpoint_path, input.service, &hash, findings).await?;
    }
    result
}

async fn write_checkpoint(
    path: &std::path::Path,
    service: Service,
    hash: &str,
    findings: &[Finding],
) -> Result<(), RunError> {
    let mut checkpoint = Checkpoint::new(hash, service_name(service));
    for finding in findings {
        checkpoint.findings.push(CheckpointEntry::new(
            finding.target.to_string(),
            &finding.credential,
        ));
    }
    checkpoint.next_index = u64::try_from(findings.len()).unwrap_or(u64::MAX);
    save_checkpoint(path, &checkpoint)
        .await
        .map_err(|error| RunError::Checkpoint(error.to_string()))
}

fn build_attempts(targets: &[Target], credentials: &[Credential]) -> Vec<Attempt> {
    let mut attempts = Vec::with_capacity(targets.len().saturating_mul(credentials.len()));
    for target in targets {
        for credential in credentials {
            attempts.push(Attempt {
                target: target.clone(),
                credential: credential.clone(),
            });
        }
    }
    attempts
}

fn build_spray_rounds(targets: &[Target], credentials: &[Credential]) -> Vec<SprayRound> {
    let mut by_password: BTreeMap<String, Vec<(Target, String)>> = BTreeMap::new();
    for credential in credentials {
        let password = credential.password.clone().unwrap_or_default();
        let entry = by_password.entry(password).or_default();
        for target in targets {
            entry.push((target.clone(), credential.username.clone()));
        }
    }
    by_password
        .into_iter()
        .map(|(password, pairs)| SprayRound { password, pairs })
        .collect()
}

fn credential_input(cli: &Cli, input: &TargetInput) -> Result<CredentialInput, RunError> {
    if let Some(combo) = &cli.combo_list {
        return Ok(CredentialInput::Combos(path_or_stdin(combo.clone())));
    }
    let users = if let Some(path) = &cli.user_list {
        path_or_stdin(path.clone())
    } else if let Some(user) = cli.username.as_ref().or(input.username.as_ref()) {
        InputSource::Single(user.clone())
    } else {
        return Err(RunError::MissingCredentials);
    };
    let passwords = if let Some(path) = &cli.password_list {
        Some(path_or_stdin(path.clone()))
    } else if let Some(password) = &cli.password {
        Some(InputSource::Single(password.clone()))
    } else if cli.mangling.is_empty() {
        return Err(RunError::MissingCredentials);
    } else {
        None
    };
    Ok(CredentialInput::Product { users, passwords })
}

fn path_or_stdin(path: PathBuf) -> InputSource {
    if path.as_os_str() == "-" {
        InputSource::Stdin
    } else {
        InputSource::from_path(path)
    }
}

fn service_name(service: Service) -> &'static str {
    service.scheme()
}

fn session_hash(service: Service, cli: &Cli) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    service_name(service).hash(&mut hasher);
    cli.service_or_url.hash(&mut hasher);
    cli.target.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

fn build_module(
    cli: &Cli,
    config: &Config,
    service: Service,
) -> Result<Arc<dyn ProtocolModule>, RunError> {
    crate::engine::modules::build_module(cli, config, service)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_vertical_attempts_and_spray_rounds() {
        let targets = vec![Target::new("127.0.0.1", 22, false)];
        let creds = vec![
            Credential {
                username: "a".into(),
                password: Some("p1".into()),
            },
            Credential {
                username: "b".into(),
                password: Some("p1".into()),
            },
            Credential {
                username: "a".into(),
                password: Some("p2".into()),
            },
        ];
        assert_eq!(build_attempts(&targets, &creds).len(), 3);
        let rounds = build_spray_rounds(&targets, &creds);
        assert_eq!(rounds.len(), 2);
    }
}
