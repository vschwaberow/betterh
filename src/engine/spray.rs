// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Horizontal password spraying coordinator.

use std::{collections::HashSet, sync::Arc, time::Duration};

use tokio::{
    sync::{Semaphore, mpsc},
    task::JoinSet,
    time::sleep,
};

use super::pool::{Attempt, Finding, PoolConfig, PoolError};
use crate::protocols::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

/// One spray round: a single password tested across many target/user pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SprayRound {
    pub password: String,
    pub pairs: Vec<(Target, String)>,
}

/// Configuration for horizontal spraying.
#[derive(Debug, Clone)]
pub struct SprayConfig {
    pub pool: PoolConfig,
    pub cooldown: Duration,
}

impl SprayConfig {
    #[must_use]
    pub fn new(pool: PoolConfig, cooldown: Duration) -> Self {
        Self { pool, cooldown }
    }
}

/// Run horizontal password spraying with inter-round cooldown.
///
/// Locked-out usernames (per target) are skipped in subsequent rounds.
///
/// # Errors
/// Propagates cancellation and worker failures from the underlying pool.
pub async fn run_spray<M>(
    module: Arc<M>,
    rounds: Vec<SprayRound>,
    config: SprayConfig,
) -> Result<Vec<Finding>, PoolError>
where
    M: ProtocolModule + ?Sized + 'static,
{
    let mut findings = Vec::new();
    let mut locked: HashSet<(String, String)> = HashSet::new();
    let total = rounds.len();

    for (index, round) in rounds.into_iter().enumerate() {
        if config.pool.cancel.is_cancelled() {
            return Err(PoolError::Cancelled);
        }

        let attempts: Vec<Attempt> = round
            .pairs
            .into_iter()
            .filter(|(target, user)| !locked.contains(&(target.to_string(), user.clone())))
            .map(|(target, username)| Attempt {
                target,
                credential: Credential {
                    username,
                    password: Some(round.password.clone()),
                },
            })
            .collect();

        if !attempts.is_empty() {
            let round_findings =
                run_spray_round(Arc::clone(&module), attempts, &config.pool, &mut locked).await?;
            findings.extend(round_findings);
        }

        if index + 1 < total && !config.cooldown.is_zero() {
            tokio::select! {
                biased;
                () = config.pool.cancel.cancelled() => return Err(PoolError::Cancelled),
                () = sleep(config.cooldown) => {}
            }
        }
    }

    Ok(findings)
}

async fn run_spray_round<M>(
    module: Arc<M>,
    attempts: Vec<Attempt>,
    config: &PoolConfig,
    locked: &mut HashSet<(String, String)>,
) -> Result<Vec<Finding>, PoolError>
where
    M: ProtocolModule + ?Sized + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Attempt>(config.concurrency.saturating_mul(2).max(8));
    let (lock_tx, mut lock_rx) = mpsc::unbounded_channel::<(String, String)>();
    let cancel = config.cancel.clone();

    let producer = tokio::spawn(async move {
        for attempt in attempts {
            if cancel.is_cancelled() {
                break;
            }
            if tx.send(attempt).await.is_err() {
                break;
            }
        }
    });

    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let mut join_set = JoinSet::new();
    let (find_tx, mut find_rx) = mpsc::unbounded_channel::<Finding>();

    loop {
        tokio::select! {
            biased;
            () = config.cancel.cancelled() => {
                join_set.abort_all();
                while join_set.join_next().await.is_some() {}
                return Err(PoolError::Cancelled);
            }
            attempt = rx.recv() => {
                let Some(attempt) = attempt else { break; };
                let permit = semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| PoolError::Cancelled)?;
                let module = Arc::clone(&module);
                let find_tx = find_tx.clone();
                let lock_tx = lock_tx.clone();
                let cancel = config.cancel.clone();
                let timeout = config.timeout;
                join_set.spawn(async move {
                    let _permit = permit;
                    if cancel.is_cancelled() {
                        return;
                    }
                    match module
                        .authenticate(&attempt.target, &attempt.credential, timeout)
                        .await
                    {
                        Ok(AuthResult::Success) => {
                            let _ = find_tx.send(Finding {
                                target: attempt.target,
                                credential: attempt.credential,
                            });
                        }
                        Ok(AuthResult::LockedOut) => {
                            let _ = lock_tx.send((
                                attempt.target.to_string(),
                                attempt.credential.username,
                            ));
                        }
                        Ok(_) | Err(ProtocolError::Timeout | _) => {}
                    }
                });
            }
        }
    }

    drop(find_tx);
    drop(lock_tx);
    while let Some(joined) = join_set.join_next().await {
        joined.map_err(|error| PoolError::Join(error.to_string()))?;
    }

    let mut findings = Vec::new();
    while let Some(finding) = find_rx.recv().await {
        findings.push(finding);
    }
    while let Some(entry) = lock_rx.recv().await {
        locked.insert(entry);
    }
    let _ = producer.await;
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::mock::MockProtocolModule;
    use tokio_util::sync::CancellationToken;

    fn target() -> Target {
        Target::new("127.0.0.1", 22, false)
    }

    #[tokio::test]
    async fn spray_tests_one_password_across_users_then_cools_down() {
        let module = Arc::new(MockProtocolModule::new(Duration::ZERO, 100, None, false).unwrap());
        let cancel = CancellationToken::new();
        let rounds = vec![
            SprayRound {
                password: "Spring2026!".into(),
                pairs: vec![(target(), "alice".into()), (target(), "bob".into())],
            },
            SprayRound {
                password: "Winter2026!".into(),
                pairs: vec![(target(), "alice".into())],
            },
        ];
        let start = tokio::time::Instant::now();
        let findings = run_spray(
            module,
            rounds,
            SprayConfig::new(
                PoolConfig::new(2, Duration::from_secs(2), cancel),
                Duration::from_millis(50),
            ),
        )
        .await
        .unwrap();
        assert_eq!(findings.len(), 3);
        assert!(start.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn spray_skips_locked_out_users_on_later_rounds() {
        use crate::protocols::CanaryStatus;
        use async_trait::async_trait;
        use std::sync::Mutex;

        struct LockOnce {
            locked: Mutex<HashSet<String>>,
        }

        #[async_trait]
        impl ProtocolModule for LockOnce {
            fn name(&self) -> &'static str {
                "lock-once"
            }
            fn default_port(&self) -> u16 {
                22
            }
            async fn authenticate(
                &self,
                _target: &Target,
                credential: &Credential,
                _timeout: Duration,
            ) -> Result<AuthResult, ProtocolError> {
                let Ok(mut guard) = self.locked.lock() else {
                    return Err(ProtocolError::Internal("lock poisoned".into()));
                };
                if guard.contains(&credential.username) {
                    return Ok(AuthResult::LockedOut);
                }
                if credential.password.as_deref() == Some("bad") {
                    guard.insert(credential.username.clone());
                    return Ok(AuthResult::LockedOut);
                }
                Ok(AuthResult::Failure)
            }
            async fn canary_probe(&self, _target: &Target) -> Result<CanaryStatus, ProtocolError> {
                Ok(CanaryStatus::Normal)
            }
        }

        let module = Arc::new(LockOnce {
            locked: Mutex::new(HashSet::new()),
        });
        let cancel = CancellationToken::new();
        let rounds = vec![
            SprayRound {
                password: "bad".into(),
                pairs: vec![(target(), "alice".into())],
            },
            SprayRound {
                password: "good".into(),
                pairs: vec![(target(), "alice".into()), (target(), "bob".into())],
            },
        ];
        let findings = run_spray(
            module,
            rounds,
            SprayConfig::new(
                PoolConfig::new(1, Duration::from_secs(2), cancel),
                Duration::ZERO,
            ),
        )
        .await
        .unwrap();
        assert!(findings.is_empty());
    }
}
