// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Pre-flight gate that never turns canary responses into credential findings.

use std::time::Duration;

use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::protocols::{CanaryStatus, ProtocolError, ProtocolModule, Target};

#[derive(Debug, Error)]
pub enum CanaryError {
    #[error("Canary probe cancelled")]
    Cancelled,
    #[error("Canary probe timed out")]
    Timeout,
    #[error("Canary probe failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error(
        "Canary rejected target {target}: {reason}; inspect the service or explicitly use --force"
    )]
    Wildcard { target: String, reason: String },
}

/// Check a target before dispatching real credentials.
///
/// The caller must authorize the target's scope before invoking this network probe.
/// A forced wildcard is returned unchanged so reports can retain the warning.
///
/// # Errors
/// Rejects unforced wildcards, inconclusive/failed probes, elapsed deadlines, and cancellation.
pub async fn check(
    module: &dyn ProtocolModule,
    target: &Target,
    force: bool,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<CanaryStatus, CanaryError> {
    if cancellation.is_cancelled() {
        return Err(CanaryError::Cancelled);
    }
    if timeout.is_zero() {
        return Err(CanaryError::Timeout);
    }
    let status = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(CanaryError::Cancelled),
        result = tokio::time::timeout(timeout, module.canary_probe(target)) => {
            result.map_err(|_| CanaryError::Timeout)??
        }
    };
    if let CanaryStatus::WildcardDetected(reason) = &status {
        tracing::warn!(target = %target, forced = force, %reason, "Canary accepted invalid credentials");
        if !force {
            return Err(CanaryError::Wildcard {
                target: target.to_string(),
                reason: reason.clone(),
            });
        }
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;

    use super::*;
    use crate::protocols::{AuthResult, Credential, mock::MockProtocolModule};

    fn target() -> Target {
        Target {
            host: "127.0.0.1".into(),
            port: 22,
            ssl: false,
            path: None,
            ip: Some("127.0.0.1".parse().unwrap()),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn normal_canary_allows_the_target() {
        let result = check(
            &MockProtocolModule::default(),
            &target(),
            false,
            Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(result, CanaryStatus::Normal);
    }

    #[tokio::test(start_paused = true)]
    async fn wildcard_rejects_by_default_and_remains_flagged_when_forced() {
        let mock = MockProtocolModule::new(Duration::ZERO, 0, None, true).unwrap();
        let token = CancellationToken::new();
        assert!(matches!(
            check(&mock, &target(), false, Duration::from_secs(1), &token).await,
            Err(CanaryError::Wildcard { .. })
        ));
        assert!(matches!(
            check(&mock, &target(), true, Duration::from_secs(1), &token)
                .await
                .unwrap(),
            CanaryStatus::WildcardDetected(_)
        ));
    }

    struct CountingModule {
        calls: AtomicUsize,
        result: Result<AuthResult, ProtocolError>,
    }

    #[async_trait]
    impl ProtocolModule for CountingModule {
        fn name(&self) -> &'static str {
            "counting"
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
            assert!(credential.username.starts_with("__canary_"));
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.result.clone()
        }
    }

    #[tokio::test]
    async fn force_never_bypasses_transport_errors_or_inconclusive_results() {
        for result in [
            Err(ProtocolError::ConnectionError("refused".into())),
            Err(ProtocolError::Timeout),
            Ok(AuthResult::LockedOut),
            Ok(AuthResult::RateLimited(Duration::from_secs(30))),
            Ok(AuthResult::Error("unknown".into())),
        ] {
            let module = CountingModule {
                calls: AtomicUsize::new(0),
                result,
            };
            assert!(matches!(
                check(
                    &module,
                    &target(),
                    true,
                    Duration::from_secs(1),
                    &CancellationToken::new()
                )
                .await,
                Err(CanaryError::Protocol(_))
            ));
            assert_eq!(module.calls.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn pre_cancelled_or_zero_deadline_never_calls_module() {
        let module = CountingModule {
            calls: AtomicUsize::new(0),
            result: Ok(AuthResult::Failure),
        };
        let token = CancellationToken::new();
        token.cancel();
        assert!(matches!(
            check(&module, &target(), false, Duration::from_secs(1), &token).await,
            Err(CanaryError::Cancelled)
        ));
        assert!(matches!(
            check(
                &module,
                &target(),
                true,
                Duration::ZERO,
                &CancellationToken::new()
            )
            .await,
            Err(CanaryError::Timeout)
        ));
        assert_eq!(module.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn overall_deadline_bounds_the_probe() {
        let mock = MockProtocolModule::new(Duration::from_secs(10), 0, None, false).unwrap();
        let start = tokio::time::Instant::now();
        assert!(matches!(
            check(
                &mock,
                &target(),
                true,
                Duration::from_secs(1),
                &CancellationToken::new()
            )
            .await,
            Err(CanaryError::Timeout)
        ));
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_interrupts_an_in_progress_probe() {
        let mock = MockProtocolModule::new(Duration::from_secs(10), 0, None, false).unwrap();
        let token = CancellationToken::new();
        let target = target();
        let (result, ()) = tokio::join!(
            check(&mock, &target, true, Duration::from_secs(20), &token),
            async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                token.cancel();
            }
        );
        assert!(matches!(result, Err(CanaryError::Cancelled)));
    }
}
