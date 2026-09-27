// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Bounded worker pool for vertical credential attempts.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{
    net::lookup_host,
    sync::{Semaphore, mpsc},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use super::{
    actions::SkipState,
    adaptive::AdaptiveLimiter,
    lockout::LockoutGuard,
    proxy::Pacer,
    scope::{Scope, ScopeDecision},
};
use crate::protocols::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

/// One authentication attempt scheduled for a worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub target: Target,
    pub credential: Credential,
}

/// Successful authentication discovered by the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub target: Target,
    pub credential: Credential,
}

#[derive(Debug, Error)]
pub enum PoolError {
    #[error("Attack cancelled")]
    Cancelled,
    #[error("Target {target} is excluded by scope guardrails")]
    Excluded { target: String },
    #[error(
        "Target {target} requires confirmation before network work; re-run with --force to proceed"
    )]
    ConfirmationRequired { target: String },
    #[error("DNS resolution failed for {target}: {reason}")]
    Dns { target: String, reason: String },
    #[error("No in-scope address for {target}")]
    NoAddress { target: String },
    #[error("Worker task failed: {0}")]
    Join(String),
}

/// Configuration for a bounded attack worker pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub concurrency: usize,
    pub timeout: Duration,
    pub cancel: CancellationToken,
    pub skip: Option<Arc<tokio::sync::Mutex<SkipState>>>,
    pub pacer: Option<Pacer>,
    pub live_findings: Option<mpsc::UnboundedSender<Finding>>,
    pub lockout: Option<Arc<tokio::sync::Mutex<LockoutGuard>>>,
    pub quarantine_tx: Option<mpsc::UnboundedSender<String>>,
}

impl PoolConfig {
    #[must_use]
    pub fn new(concurrency: usize, timeout: Duration, cancel: CancellationToken) -> Self {
        Self {
            concurrency: concurrency.max(1),
            timeout,
            cancel,
            skip: None,
            pacer: None,
            live_findings: None,
            lockout: None,
            quarantine_tx: None,
        }
    }

    #[must_use]
    pub fn with_skip(mut self, skip: Arc<tokio::sync::Mutex<SkipState>>) -> Self {
        self.skip = Some(skip);
        self
    }

    #[must_use]
    pub fn with_pacer(mut self, pacer: Pacer) -> Self {
        self.pacer = Some(pacer);
        self
    }

    #[must_use]
    pub fn with_live_findings(mut self, tx: mpsc::UnboundedSender<Finding>) -> Self {
        self.live_findings = Some(tx);
        self
    }

    #[must_use]
    pub fn with_lockout(mut self, lockout: Arc<tokio::sync::Mutex<LockoutGuard>>) -> Self {
        self.lockout = Some(lockout);
        self
    }

    #[must_use]
    pub fn with_quarantine_tx(mut self, tx: mpsc::UnboundedSender<String>) -> Self {
        self.quarantine_tx = Some(tx);
        self
    }
}

/// Resolve and pin `Target.ip`, enforcing scope / confirmation before any dial.
///
/// Hostname `host` is preserved for SNI / Host headers. Workers must dial the
/// pinned address and must not perform another DNS lookup.
///
/// # Errors
/// Returns scope, DNS, or confirmation failures.
pub async fn prepare_target(
    mut target: Target,
    scope: &Scope,
    force: bool,
) -> Result<Target, PoolError> {
    if let Some(ip) = target.ip {
        return authorize_ip(target, ip, scope, force);
    }

    if let Ok(ip) = target.host.parse() {
        target.ip = Some(ip);
        return authorize_ip(target, ip, scope, force);
    }

    match scope.classify(&target) {
        ScopeDecision::Excluded => {
            return Err(PoolError::Excluded {
                target: target.to_string(),
            });
        }
        ScopeDecision::NeedsResolution
        | ScopeDecision::Local
        | ScopeDecision::ConfirmationRequired => {}
    }

    let host_port = format!("{}:{}", target.host, target.port);
    let addrs = lookup_host(host_port.as_str())
        .await
        .map_err(|error| PoolError::Dns {
            target: target.to_string(),
            reason: error.to_string(),
        })?;

    let mut chosen: Option<SocketAddr> = None;
    for addr in addrs {
        match scope.classify_ip(addr.ip()) {
            ScopeDecision::Excluded => {}
            ScopeDecision::ConfirmationRequired if !force => {
                return Err(PoolError::ConfirmationRequired {
                    target: target.to_string(),
                });
            }
            ScopeDecision::Local
            | ScopeDecision::NeedsResolution
            | ScopeDecision::ConfirmationRequired => {
                chosen = Some(addr);
                break;
            }
        }
    }

    let Some(addr) = chosen else {
        return Err(PoolError::NoAddress {
            target: target.to_string(),
        });
    };
    target.ip = Some(addr.ip());
    Ok(target)
}

fn authorize_ip(
    target: Target,
    ip: std::net::IpAddr,
    scope: &Scope,
    force: bool,
) -> Result<Target, PoolError> {
    match scope.classify_ip(ip) {
        ScopeDecision::Excluded => Err(PoolError::Excluded {
            target: target.to_string(),
        }),
        ScopeDecision::ConfirmationRequired if !force => Err(PoolError::ConfirmationRequired {
            target: target.to_string(),
        }),
        _ => Ok(target),
    }
}

/// Run vertical brute-force attempts with bounded concurrency.
///
/// # Errors
/// Propagates cancellation and worker join failures. Authentication transport
/// errors are recorded as non-findings and do not abort the pool.
pub async fn run_brute<M>(
    module: Arc<M>,
    attempts: Vec<Attempt>,
    config: PoolConfig,
) -> Result<Vec<Finding>, PoolError>
where
    M: ProtocolModule + ?Sized + 'static,
{
    let (tx, rx) = mpsc::channel::<Attempt>(config.concurrency.saturating_mul(2).max(8));
    let producer_cancel = config.cancel.clone();
    let producer = tokio::spawn(async move {
        for attempt in attempts {
            if producer_cancel.is_cancelled() {
                break;
            }
            if tx.send(attempt).await.is_err() {
                break;
            }
        }
    });

    let findings = drain_workers(module, rx, config).await?;
    let _ = producer.await;
    Ok(findings)
}

#[expect(
    clippy::too_many_lines,
    reason = "Worker drain owns limiter, skip, pacing, and auth outcome handling together"
)]
pub(crate) async fn drain_workers<M>(
    module: Arc<M>,
    mut rx: mpsc::Receiver<Attempt>,
    config: PoolConfig,
) -> Result<Vec<Finding>, PoolError>
where
    M: ProtocolModule + ?Sized + 'static,
{
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let mut join_set = JoinSet::new();
    let (find_tx, mut find_rx) = mpsc::unbounded_channel::<Finding>();
    // Shared per-target limiters keyed by display string.
    let limiters = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::<
        String,
        Arc<tokio::sync::Mutex<AdaptiveLimiter>>,
    >::new()));

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
                let limiters = Arc::clone(&limiters);
                let timeout = config.timeout;
                let cancel = config.cancel.clone();
                let skip = config.skip.clone();
                let pacer = config.pacer;
                let live = config.live_findings.clone();
                let lockout = config.lockout.clone();
                let quarantine_tx = config.quarantine_tx.clone();
                join_set.spawn(async move {
                    let _permit = permit;
                    if cancel.is_cancelled() {
                        return;
                    }
                    if let Some(skip) = &skip {
                        let guard = skip.lock().await;
                        if guard.should_skip(&attempt.target, &attempt.credential.username) {
                            return;
                        }
                    }
                    if let Some(lockout) = &lockout {
                        let mut guard = lockout.lock().await;
                        if !guard.allow(&attempt.credential.username) {
                            return;
                        }
                    }
                    if let Some(pacer) = pacer {
                        pacer.pace().await;
                    }
                    let key = attempt.target.to_string();
                    let limiter = {
                        let mut guard = limiters.lock().await;
                        Arc::clone(guard.entry(key).or_insert_with(|| {
                            Arc::new(tokio::sync::Mutex::new(AdaptiveLimiter::new(1.0)))
                        }))
                    };
                    {
                        let mut limiter = limiter.lock().await;
                        limiter.acquire().await;
                    }
                    let result = module
                        .authenticate(&attempt.target, &attempt.credential, timeout)
                        .await;
                    match result {
                        Ok(AuthResult::Success) => {
                            let mut limiter = limiter.lock().await;
                            limiter.on_outcome_ok();
                            drop(limiter);
                            if let Some(lockout) = &lockout {
                                let mut guard = lockout.lock().await;
                                guard.record_success(&attempt.credential.username);
                            }
                            if let Some(skip) = &skip {
                                let mut guard = skip.lock().await;
                                guard.record_success(
                                    &attempt.target,
                                    &attempt.credential.username,
                                );
                                if guard.stop_all() {
                                    cancel.cancel();
                                }
                            }
                            let finding = Finding {
                                target: attempt.target,
                                credential: attempt.credential,
                            };
                            if let Some(live) = &live {
                                let _ = live.send(finding.clone());
                            }
                            let _ = find_tx.send(finding);
                        }
                        Ok(AuthResult::RateLimited(delay)) => {
                            let mut limiter = limiter.lock().await;
                            limiter.on_rate_limited(delay);
                        }
                        Ok(AuthResult::Failure) => {
                            let mut limiter = limiter.lock().await;
                            limiter.on_outcome_ok();
                            drop(limiter);
                            if let Some(lockout) = &lockout {
                                let mut guard = lockout.lock().await;
                                guard.record_failure(&attempt.credential.username);
                            }
                        }
                        Ok(AuthResult::LockedOut) => {
                            let mut limiter = limiter.lock().await;
                            limiter.on_outcome_ok();
                            drop(limiter);
                            if let Some(lockout) = &lockout {
                                let mut guard = lockout.lock().await;
                                if guard.quarantine(&attempt.credential.username)
                                    && let Some(tx) = &quarantine_tx
                                {
                                    let _ = tx.send(attempt.credential.username.clone());
                                }
                            }
                        }
                        Ok(AuthResult::Error(_)) => {
                            let mut limiter = limiter.lock().await;
                            limiter.on_outcome_ok();
                        }
                        Err(ProtocolError::Timeout) => {
                            let mut limiter = limiter.lock().await;
                            limiter.on_timeout();
                        }
                        Err(_) => {}
                    }
                });
            }
        }
    }

    drop(find_tx);
    while let Some(joined) = join_set.join_next().await {
        joined.map_err(|error| PoolError::Join(error.to_string()))?;
    }

    let mut findings = Vec::new();
    while let Some(finding) = find_rx.recv().await {
        findings.push(finding);
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::mock::MockProtocolModule;

    fn target(host: &str) -> Target {
        Target::new(host, 22, false)
    }

    #[tokio::test]
    async fn prepare_target_pins_literal_ip_and_rejects_excluded() {
        let scope = Scope::new(vec!["10.0.0.0/8".parse().unwrap()]);
        let prepared = prepare_target(target("127.0.0.1"), &scope, false)
            .await
            .unwrap();
        assert_eq!(prepared.ip, Some("127.0.0.1".parse().unwrap()));

        let err = prepare_target(target("10.1.2.3"), &scope, false)
            .await
            .unwrap_err();
        assert!(matches!(err, PoolError::Excluded { .. }));
    }

    #[tokio::test]
    async fn prepare_target_requires_force_for_public_literals() {
        let scope = Scope::new(Vec::new());
        let err = prepare_target(target("8.8.8.8"), &scope, false)
            .await
            .unwrap_err();
        assert!(matches!(err, PoolError::ConfirmationRequired { .. }));
        let ok = prepare_target(target("8.8.8.8"), &scope, true)
            .await
            .unwrap();
        assert_eq!(ok.ip, Some("8.8.8.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn brute_pool_respects_concurrency_and_finds_success() {
        let module =
            Arc::new(MockProtocolModule::new(Duration::from_millis(20), 100, None, false).unwrap());
        let attempts = vec![
            Attempt {
                target: target("127.0.0.1"),
                credential: Credential {
                    username: "a".into(),
                    password: Some("1".into()),
                },
            },
            Attempt {
                target: target("127.0.0.1"),
                credential: Credential {
                    username: "b".into(),
                    password: Some("2".into()),
                },
            },
        ];
        let cancel = CancellationToken::new();
        let findings = run_brute(
            module,
            attempts,
            PoolConfig::new(1, Duration::from_secs(2), cancel),
        )
        .await
        .unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[tokio::test]
    async fn brute_pool_cancels_cooperatively() {
        let module =
            Arc::new(MockProtocolModule::new(Duration::from_secs(5), 100, None, false).unwrap());
        let attempts: Vec<_> = (0..8)
            .map(|i| Attempt {
                target: target("127.0.0.1"),
                credential: Credential {
                    username: format!("u{i}"),
                    password: Some("p".into()),
                },
            })
            .collect();
        let cancel = CancellationToken::new();
        let cancel_worker = cancel.clone();
        let handle = tokio::spawn(async move {
            run_brute(
                module,
                attempts,
                PoolConfig::new(2, Duration::from_secs(10), cancel_worker),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        cancel.cancel();
        let err = handle.await.unwrap().unwrap_err();
        assert!(matches!(err, PoolError::Cancelled));
    }

    #[tokio::test(start_paused = true)]
    async fn lockout_skips_cooled_user_and_quarantines_on_locked_out() {
        use crate::protocols::CanaryStatus;
        use async_trait::async_trait;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::time::{Duration, advance};

        struct CountingFailThenLock {
            calls: AtomicUsize,
        }

        #[async_trait]
        impl ProtocolModule for CountingFailThenLock {
            fn name(&self) -> &'static str {
                "count-fail"
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
                let n = self.calls.fetch_add(1, Ordering::SeqCst);
                if credential.username == "locked" {
                    return Ok(AuthResult::LockedOut);
                }
                if n < 2 {
                    return Ok(AuthResult::Failure);
                }
                Ok(AuthResult::Success)
            }
            async fn canary_probe(&self, _target: &Target) -> Result<CanaryStatus, ProtocolError> {
                Ok(CanaryStatus::Normal)
            }
        }

        let module = Arc::new(CountingFailThenLock {
            calls: AtomicUsize::new(0),
        });
        let lockout = Arc::new(tokio::sync::Mutex::new(LockoutGuard::new(
            2,
            Duration::from_secs(10),
        )));
        let (q_tx, mut q_rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let attempts = vec![
            Attempt {
                target: target("127.0.0.1"),
                credential: Credential {
                    username: "alice".into(),
                    password: Some("1".into()),
                },
            },
            Attempt {
                target: target("127.0.0.1"),
                credential: Credential {
                    username: "alice".into(),
                    password: Some("2".into()),
                },
            },
            Attempt {
                target: target("127.0.0.1"),
                credential: Credential {
                    username: "alice".into(),
                    password: Some("3".into()),
                },
            },
            Attempt {
                target: target("127.0.0.1"),
                credential: Credential {
                    username: "locked".into(),
                    password: Some("x".into()),
                },
            },
            Attempt {
                target: target("127.0.0.1"),
                credential: Credential {
                    username: "locked".into(),
                    password: Some("y".into()),
                },
            },
        ];
        let findings = run_brute(
            module,
            attempts,
            PoolConfig::new(1, Duration::from_secs(2), cancel)
                .with_lockout(Arc::clone(&lockout))
                .with_quarantine_tx(q_tx),
        )
        .await
        .unwrap();
        assert!(findings.is_empty());
        assert_eq!(q_rx.recv().await.as_deref(), Some("locked"));
        assert!(lockout.lock().await.is_quarantined("locked"));
        assert!(!lockout.lock().await.allow("alice"));
        advance(Duration::from_secs(10)).await;
        assert!(lockout.lock().await.allow("alice"));
    }
}
