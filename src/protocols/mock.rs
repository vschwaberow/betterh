// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Deterministic, network-free protocol simulation for engine tests.

use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use async_trait::async_trait;

use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

#[derive(Debug)]
pub struct MockProtocolModule {
    latency: Duration,
    success_percent: u8,
    rate_limit: Option<Duration>,
    wildcard: bool,
    attempts: AtomicUsize,
}

impl MockProtocolModule {
    /// Configure repeatable responses. The first N of each 100 attempts succeed.
    ///
    /// # Errors
    /// Returns an error when `success_percent` exceeds 100.
    pub fn new(
        latency: Duration,
        success_percent: u8,
        rate_limit: Option<Duration>,
        wildcard: bool,
    ) -> Result<Self, ProtocolError> {
        if success_percent > 100 {
            return Err(ProtocolError::Internal(
                "Mock success percentage must be 0..=100".into(),
            ));
        }
        Ok(Self {
            latency,
            success_percent,
            rate_limit,
            wildcard,
            attempts: AtomicUsize::new(0),
        })
    }
}

impl Default for MockProtocolModule {
    fn default() -> Self {
        Self {
            latency: Duration::ZERO,
            success_percent: 0,
            rate_limit: None,
            wildcard: false,
            attempts: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ProtocolModule for MockProtocolModule {
    fn name(&self) -> &'static str {
        "mock"
    }
    fn default_port(&self) -> u16 {
        0
    }

    async fn authenticate(
        &self,
        _target: &Target,
        _credential: &Credential,
        timeout: Duration,
    ) -> Result<AuthResult, ProtocolError> {
        if timeout.is_zero() {
            return Err(ProtocolError::Timeout);
        }
        tokio::time::timeout(timeout, tokio::time::sleep(self.latency))
            .await
            .map_err(|_| ProtocolError::Timeout)?;
        if let Some(delay) = self.rate_limit {
            return Ok(AuthResult::RateLimited(delay));
        }
        let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
        if self.wildcard || attempt % 100 < usize::from(self.success_percent) {
            Ok(AuthResult::Success)
        } else {
            Ok(AuthResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::CanaryStatus;

    fn target() -> Target {
        Target {
            host: "localhost".into(),
            port: 0,
            ssl: false,
            path: None,
            ip: None,
        }
    }

    fn credential() -> Credential {
        Credential {
            username: "test".into(),
            password: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn success_percentage_is_repeatable() {
        let mock = MockProtocolModule::new(Duration::ZERO, 25, None, false).unwrap();
        let mut successes = 0;
        for _ in 0..200 {
            if mock
                .authenticate(&target(), &credential(), Duration::from_secs(1))
                .await
                .unwrap()
                == AuthResult::Success
            {
                successes += 1;
            }
        }
        assert_eq!(successes, 50);
    }

    #[tokio::test(start_paused = true)]
    async fn canary_detects_catch_all() {
        let mock = MockProtocolModule::new(Duration::ZERO, 0, None, true).unwrap();
        assert!(matches!(
            mock.canary_probe(&target()).await.unwrap(),
            CanaryStatus::WildcardDetected(_)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn canary_accepts_explicit_rejection() {
        assert_eq!(
            MockProtocolModule::default()
                .canary_probe(&target())
                .await
                .unwrap(),
            CanaryStatus::Normal
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limit_takes_precedence_and_canary_is_inconclusive() {
        let delay = Duration::from_secs(30);
        let mock = MockProtocolModule::new(Duration::ZERO, 100, Some(delay), true).unwrap();
        assert_eq!(
            mock.authenticate(&target(), &credential(), Duration::from_secs(1))
                .await
                .unwrap(),
            AuthResult::RateLimited(delay)
        );
        assert!(matches!(
            mock.canary_probe(&target()).await,
            Err(ProtocolError::Internal(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn latency_respects_timeout() {
        let mock = MockProtocolModule::new(Duration::from_secs(10), 0, None, false).unwrap();
        let start = tokio::time::Instant::now();
        assert_eq!(
            mock.authenticate(&target(), &credential(), Duration::from_secs(1))
                .await,
            Err(ProtocolError::Timeout)
        );
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        assert_eq!(
            mock.canary_probe(&target()).await,
            Err(ProtocolError::Timeout)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn latency_delays_success_and_zero_timeout_fails() {
        let mock = MockProtocolModule::new(Duration::from_secs(1), 100, None, false).unwrap();
        let start = tokio::time::Instant::now();
        assert_eq!(
            mock.authenticate(&target(), &credential(), Duration::from_secs(2))
                .await
                .unwrap(),
            AuthResult::Success
        );
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        assert_eq!(
            mock.authenticate(&target(), &credential(), Duration::ZERO)
                .await,
            Err(ProtocolError::Timeout)
        );
    }

    #[test]
    fn invalid_success_percentage_is_rejected() {
        assert!(MockProtocolModule::new(Duration::ZERO, 101, None, false).is_err());
    }
}
