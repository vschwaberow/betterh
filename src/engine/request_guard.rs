// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Fixed admission pacing and terminal stops for one target.

use std::time::Duration;

use thiserror::Error;
use tokio::{sync::Mutex, time::Instant};
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::protocols::AuthResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StopReason {
    #[error("the target reported an account lockout")]
    LockedOut,
    #[error("the target reported a rate limit")]
    RateLimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GuardError {
    #[error("The request interval must be positive and fit within the monotonic clock")]
    InvalidInterval,
    #[error("Request admission cancelled")]
    Cancelled,
    #[error("Request admission stopped: {0}")]
    Stopped(StopReason),
}

/// Share one guard across all workers for a target, for example using `Arc`.
/// A stop is permanent for this guard; it cannot be reset or forced open.
#[derive(Debug)]
pub struct RequestGuard {
    interval: Duration,
    state: Mutex<State>,
    stopped: CancellationToken,
}

#[derive(Debug)]
struct State {
    next: Instant,
    reason: Option<StopReason>,
}

impl RequestGuard {
    /// Create a target guard using the resolved CLI, environment, or file setting.
    ///
    /// # Errors
    /// Returns an error if the interval exceeds the monotonic clock's range.
    pub fn from_config(config: &Config) -> Result<Self, GuardError> {
        Self::new(Duration::from_millis(config.request_interval_ms.get()))
    }

    /// Create a guard with a fixed minimum interval between admissions.
    ///
    /// # Errors
    /// Rejects zero intervals and deadlines outside the monotonic clock's range.
    pub fn new(interval: Duration) -> Result<Self, GuardError> {
        let now = Instant::now();
        if interval.is_zero() || now.checked_add(interval).is_none() {
            return Err(GuardError::InvalidInterval);
        }
        Ok(Self {
            interval,
            state: Mutex::new(State {
                next: now,
                reason: None,
            }),
            stopped: CancellationToken::new(),
        })
    }

    /// Wait for admission immediately before dispatch; do not queue granted admissions.
    /// The first admission is immediate. Idle time never builds burst capacity.
    /// Dropping or cancelling a pending wait does not consume an admission.
    ///
    /// # Errors
    /// Returns cancellation, a permanent target stop, or clock overflow.
    pub async fn wait(&self, cancellation: &CancellationToken) -> Result<(), GuardError> {
        loop {
            let next = {
                let mut state = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => return Err(GuardError::Cancelled),
                    state = self.state.lock() => state,
                };
                if let Some(reason) = state.reason {
                    return Err(GuardError::Stopped(reason));
                }
                let now = Instant::now();
                if now >= state.next {
                    state.next = now
                        .checked_add(self.interval)
                        .ok_or(GuardError::InvalidInterval)?;
                    return Ok(());
                }
                state.next
            };
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(GuardError::Cancelled),
                () = self.stopped.cancelled() => {},
                () = tokio::time::sleep_until(next) => {},
            }
        }
    }

    /// Record a response before dispatching further work to this target.
    /// Lockouts and rate limits wake waiters and permanently stop admissions.
    /// The first stop reason wins; later responses never reopen the guard.
    /// Already admitted requests remain the caller's responsibility to cancel.
    pub async fn record_result(&self, result: &AuthResult) {
        let reason = match result {
            AuthResult::LockedOut => StopReason::LockedOut,
            AuthResult::RateLimited(_) => StopReason::RateLimited,
            _ => return,
        };
        let mut state = self.state.lock().await;
        if state.reason.is_none() {
            state.reason = Some(reason);
            self.stopped.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use futures::poll;
    use tokio::time::{advance, timeout};

    use super::*;

    const INTERVAL: Duration = Duration::from_secs(1);

    #[test]
    fn rejects_zero_and_unrepresentable_intervals() {
        for interval in [Duration::ZERO, Duration::MAX] {
            assert!(matches!(
                RequestGuard::new(interval),
                Err(GuardError::InvalidInterval)
            ));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn spaces_admissions_without_accumulating_idle_capacity() {
        let guard = RequestGuard::new(INTERVAL).unwrap();
        let cancellation = CancellationToken::new();
        let start = Instant::now();
        guard.wait(&cancellation).await.unwrap();
        assert_eq!(Instant::now(), start);
        guard.wait(&cancellation).await.unwrap();
        assert_eq!(start.elapsed(), INTERVAL);

        advance(INTERVAL * 10).await;
        let after_idle = Instant::now();
        guard.wait(&cancellation).await.unwrap();
        assert_eq!(Instant::now(), after_idle);
        guard.wait(&cancellation).await.unwrap();
        assert_eq!(after_idle.elapsed(), INTERVAL);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_waiters_share_the_same_limit() {
        let guard = RequestGuard::new(INTERVAL).unwrap();
        let cancellation = CancellationToken::new();
        let admit = || async {
            guard.wait(&cancellation).await.unwrap();
            Instant::now()
        };
        let (first, second, third) = tokio::join!(admit(), admit(), admit());
        let mut times = [first, second, third];
        times.sort_unstable();
        for pair in times.windows(2) {
            assert!(pair[1].duration_since(pair[0]) >= INTERVAL);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_and_dropped_waits_do_not_reserve_admissions() {
        let guard = RequestGuard::new(INTERVAL).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(guard.wait(&cancellation).await, Err(GuardError::Cancelled));

        let active = CancellationToken::new();
        let start = Instant::now();
        guard.wait(&active).await.unwrap();
        assert_eq!(Instant::now(), start);
        {
            let mut pending = Box::pin(guard.wait(&active));
            assert!(poll!(&mut pending).is_pending());
        }
        let cancelled_wait = CancellationToken::new();
        let mut pending = Box::pin(guard.wait(&cancelled_wait));
        assert!(poll!(&mut pending).is_pending());
        cancelled_wait.cancel();
        assert_eq!(poll!(&mut pending), Poll::Ready(Err(GuardError::Cancelled)));
        guard.wait(&active).await.unwrap();
        assert_eq!(start.elapsed(), INTERVAL);
    }

    #[tokio::test(start_paused = true)]
    async fn lockout_wakes_all_waiters_and_stops_future_admissions() {
        let guard = RequestGuard::new(INTERVAL).unwrap();
        let cancellation = CancellationToken::new();
        guard.wait(&cancellation).await.unwrap();
        let mut first = Box::pin(guard.wait(&cancellation));
        let mut second = Box::pin(guard.wait(&cancellation));
        assert!(poll!(&mut first).is_pending());
        assert!(poll!(&mut second).is_pending());

        guard.record_result(&AuthResult::LockedOut).await;
        let stopped = Err(GuardError::Stopped(StopReason::LockedOut));
        assert_eq!(
            timeout(Duration::from_millis(1), first).await.unwrap(),
            stopped
        );
        assert_eq!(
            timeout(Duration::from_millis(1), second).await.unwrap(),
            stopped
        );
        advance(INTERVAL * 100).await;
        assert_eq!(guard.wait(&cancellation).await, stopped);
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limit_is_terminal_even_after_retry_duration_and_later_results() {
        let guard = RequestGuard::new(INTERVAL).unwrap();
        let cancellation = CancellationToken::new();
        guard.wait(&cancellation).await.unwrap();
        let mut pending = Box::pin(guard.wait(&cancellation));
        assert!(poll!(&mut pending).is_pending());
        guard
            .record_result(&AuthResult::RateLimited(INTERVAL))
            .await;
        let stopped = Err(GuardError::Stopped(StopReason::RateLimited));
        assert_eq!(
            timeout(Duration::from_millis(1), pending).await.unwrap(),
            stopped
        );
        advance(INTERVAL * 100).await;
        for result in [
            AuthResult::Success,
            AuthResult::Failure,
            AuthResult::LockedOut,
        ] {
            guard.record_result(&result).await;
            assert_eq!(guard.wait(&cancellation).await, stopped);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ordinary_results_preserve_pacing_and_other_targets_are_independent() {
        let guard = RequestGuard::new(INTERVAL).unwrap();
        let other = RequestGuard::new(INTERVAL).unwrap();
        let cancellation = CancellationToken::new();
        guard.wait(&cancellation).await.unwrap();
        for result in [
            AuthResult::Success,
            AuthResult::Failure,
            AuthResult::Error("error".into()),
        ] {
            let start = Instant::now();
            guard.record_result(&result).await;
            guard.wait(&cancellation).await.unwrap();
            assert_eq!(start.elapsed(), INTERVAL);
        }
        guard.record_result(&AuthResult::LockedOut).await;
        let start = Instant::now();
        other.wait(&cancellation).await.unwrap();
        assert_eq!(Instant::now(), start);
    }
}
