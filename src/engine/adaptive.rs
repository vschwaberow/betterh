// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Per-target leaky-bucket rate limiter with adaptive backoff.

use std::time::Duration;

use tokio::time::{Instant, sleep};

/// Minimum refill rate (requests per second) after repeated throttling.
const MIN_RATE: f64 = 0.05;
/// Multiplicative recovery step toward the baseline after healthy responses.
const RECOVERY_FACTOR: f64 = 1.25;
/// Base backoff applied for the first consecutive timeout.
const TIMEOUT_BACKOFF_BASE: Duration = Duration::from_millis(250);
/// Cap for timeout-driven exponential backoff.
const TIMEOUT_BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Leaky-bucket limiter that slows on `RateLimited` / timeouts without dropping work.
#[derive(Debug, Clone)]
pub struct AdaptiveLimiter {
    capacity: f64,
    tokens: f64,
    rate: f64,
    base_rate: f64,
    last_refill: Instant,
    backoff_until: Option<Instant>,
    timeout_streak: u32,
}

impl AdaptiveLimiter {
    /// Create a limiter with the given baseline request rate (req/s).
    ///
    /// Rates below [`MIN_RATE`] are clamped upward so the bucket always progresses.
    #[must_use]
    pub fn new(base_rate: f64) -> Self {
        let base_rate = base_rate.max(MIN_RATE);
        let now = Instant::now();
        Self {
            capacity: base_rate.max(1.0),
            tokens: base_rate.max(1.0),
            rate: base_rate,
            base_rate,
            last_refill: now,
            backoff_until: None,
            timeout_streak: 0,
        }
    }

    /// Current adaptive refill rate in requests per second.
    #[must_use]
    pub fn current_rate(&self) -> f64 {
        self.rate
    }

    /// Baseline rate configured at construction.
    #[must_use]
    pub fn base_rate(&self) -> f64 {
        self.base_rate
    }

    /// Remaining backoff window, if any.
    #[must_use]
    pub fn backoff_remaining(&self) -> Option<Duration> {
        let until = self.backoff_until?;
        let now = Instant::now();
        if until <= now {
            return None;
        }
        Some(until.saturating_duration_since(now))
    }

    /// Wait until a token is available and any backoff window has elapsed.
    ///
    /// Never drops the caller: the future resolves once the attempt may proceed.
    pub async fn acquire(&mut self) {
        loop {
            self.refill();
            let now = Instant::now();
            if let Some(until) = self.backoff_until {
                if until > now {
                    sleep(until.saturating_duration_since(now)).await;
                    continue;
                }
                self.backoff_until = None;
            }
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return;
            }
            let missing = 1.0 - self.tokens;
            let wait_secs = missing / self.rate;
            let wait = Duration::from_secs_f64(wait_secs.max(0.0));
            sleep(wait.max(Duration::from_millis(1))).await;
        }
    }

    /// Record a healthy outcome (success or ordinary auth failure) and recover rate.
    pub fn on_outcome_ok(&mut self) {
        self.timeout_streak = 0;
        self.refill();
        if self.rate < self.base_rate {
            self.rate = (self.rate * RECOVERY_FACTOR).min(self.base_rate);
        }
    }

    /// Apply a server-suggested rate-limit backoff and halve the refill rate.
    pub fn on_rate_limited(&mut self, suggested: Duration) {
        self.timeout_streak = 0;
        self.refill();
        self.rate = (self.rate * 0.5).max(MIN_RATE);
        self.extend_backoff(suggested.max(Duration::from_millis(1)));
    }

    /// Record a transport timeout; repeated timeouts reduce rate exponentially.
    pub fn on_timeout(&mut self) {
        self.timeout_streak = self.timeout_streak.saturating_add(1);
        self.refill();
        self.rate = (self.rate * 0.5).max(MIN_RATE);
        let shift = self.timeout_streak.saturating_sub(1).min(8);
        let backoff = TIMEOUT_BACKOFF_BASE
            .saturating_mul(2u32.pow(shift))
            .min(TIMEOUT_BACKOFF_CAP);
        self.extend_backoff(backoff);
    }

    fn extend_backoff(&mut self, duration: Duration) {
        let until = Instant::now() + duration;
        self.backoff_until = Some(match self.backoff_until {
            Some(existing) if existing > until => existing,
            _ => until,
        });
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;
        let added = self.rate * elapsed.as_secs_f64();
        self.tokens = (self.tokens + added).min(self.capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration as TokioDuration, advance, pause};

    #[tokio::test]
    async fn rate_limited_signal_decreases_rate() {
        pause();
        let mut limiter = AdaptiveLimiter::new(10.0);
        assert!((limiter.current_rate() - 10.0).abs() < f64::EPSILON);
        limiter.on_rate_limited(TokioDuration::from_secs(1));
        assert!(limiter.current_rate() < 10.0);
        assert!((limiter.current_rate() - 5.0).abs() < f64::EPSILON);
        // Second throttle halves again.
        limiter.on_rate_limited(TokioDuration::from_millis(100));
        assert!((limiter.current_rate() - 2.5).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn consecutive_timeouts_decrease_rate() {
        pause();
        let mut limiter = AdaptiveLimiter::new(8.0);
        limiter.on_timeout();
        assert!((limiter.current_rate() - 4.0).abs() < f64::EPSILON);
        limiter.on_timeout();
        assert!((limiter.current_rate() - 2.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn acquire_waits_out_backoff_without_dropping() {
        pause();
        let mut limiter = AdaptiveLimiter::new(100.0);
        limiter.on_rate_limited(TokioDuration::from_secs(2));

        let wait = tokio::spawn(async move {
            limiter.acquire().await;
            Instant::now()
        });

        // Before backoff ends, the acquire task must still be pending.
        advance(TokioDuration::from_millis(500)).await;
        assert!(!wait.is_finished());

        advance(TokioDuration::from_millis(1600)).await;
        // Task completed rather than being dropped/cancelled.
        let _finished_at = wait.await.unwrap();
    }

    #[tokio::test]
    async fn healthy_outcomes_recover_toward_baseline() {
        pause();
        let mut limiter = AdaptiveLimiter::new(10.0);
        limiter.on_rate_limited(TokioDuration::from_millis(1));
        advance(TokioDuration::from_millis(2)).await;
        let throttled = limiter.current_rate();
        assert!(throttled < 10.0);
        for _ in 0..8 {
            limiter.on_outcome_ok();
        }
        assert!(limiter.current_rate() > throttled);
        assert!(
            (limiter.current_rate() - limiter.base_rate()).abs() < 0.01
                || limiter.current_rate() <= limiter.base_rate()
        );
        assert!(limiter.current_rate() <= limiter.base_rate() + f64::EPSILON);
    }

    #[tokio::test]
    async fn acquire_consumes_tokens_at_configured_rate() {
        pause();
        let mut limiter = AdaptiveLimiter::new(2.0);
        // Drain initial capacity.
        limiter.acquire().await;
        limiter.acquire().await;
        // Next acquire needs refill (~0.5s at 2 rps with empty bucket).
        let start = Instant::now();
        let pending = tokio::spawn(async move {
            limiter.acquire().await;
            Instant::now()
        });
        advance(TokioDuration::from_millis(200)).await;
        assert!(!pending.is_finished());
        advance(TokioDuration::from_millis(400)).await;
        let end = pending.await.unwrap();
        assert!(end.duration_since(start) >= TokioDuration::from_millis(400));
    }
}
