// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Per-user lockout safeguard: cooling windows and permanent quarantine.

use std::{collections::HashMap, time::Duration};

use tokio::time::Instant;

/// Lifecycle state of a username under the lockout policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserLockStatus {
    /// Attempts may proceed.
    Active,
    /// Temporarily suspended until the cooldown elapses.
    Cooling,
    /// Permanently barred for the remainder of the session.
    Quarantined,
}

#[derive(Debug, Clone)]
struct UserEntry {
    consecutive_failures: u32,
    cooling_until: Option<Instant>,
    quarantined: bool,
}

/// In-memory per-user failure tracker shared across targets and workers.
#[derive(Debug, Clone)]
pub struct LockoutGuard {
    max_failures: u32,
    cooldown: Duration,
    users: HashMap<String, UserEntry>,
}

impl LockoutGuard {
    /// Create a guard. `max_failures == 0` disables threshold cooling; quarantine still applies.
    #[must_use]
    pub fn new(max_failures: u32, cooldown: Duration) -> Self {
        Self {
            max_failures,
            cooldown,
            users: HashMap::new(),
        }
    }

    #[must_use]
    pub const fn max_failures(&self) -> u32 {
        self.max_failures
    }

    #[must_use]
    pub const fn cooldown(&self) -> Duration {
        self.cooldown
    }

    /// Whether an authentication attempt may proceed for `username`.
    pub fn allow(&mut self, username: &str) -> bool {
        matches!(self.refresh_status(username), UserLockStatus::Active)
    }

    /// Current status after applying any elapsed cooldown.
    pub fn status(&mut self, username: &str) -> UserLockStatus {
        self.refresh_status(username)
    }

    fn refresh_status(&mut self, username: &str) -> UserLockStatus {
        let Some(entry) = self.users.get_mut(username) else {
            return UserLockStatus::Active;
        };
        if entry.quarantined {
            return UserLockStatus::Quarantined;
        }
        if let Some(until) = entry.cooling_until {
            if Instant::now() < until {
                return UserLockStatus::Cooling;
            }
            entry.cooling_until = None;
            entry.consecutive_failures = 0;
        }
        UserLockStatus::Active
    }

    /// Record a failed authentication. May enter [`UserLockStatus::Cooling`].
    pub fn record_failure(&mut self, username: &str) -> UserLockStatus {
        if self.max_failures == 0 {
            return self.refresh_status(username);
        }
        match self.refresh_status(username) {
            UserLockStatus::Quarantined => return UserLockStatus::Quarantined,
            UserLockStatus::Cooling => return UserLockStatus::Cooling,
            UserLockStatus::Active => {}
        }
        let entry = self.users.entry(username.to_owned()).or_insert(UserEntry {
            consecutive_failures: 0,
            cooling_until: None,
            quarantined: false,
        });
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        if entry.consecutive_failures >= self.max_failures {
            entry.cooling_until = Some(Instant::now() + self.cooldown);
            entry.consecutive_failures = 0;
            return UserLockStatus::Cooling;
        }
        UserLockStatus::Active
    }

    /// Reset consecutive failures after a successful authentication.
    pub fn record_success(&mut self, username: &str) {
        let Some(entry) = self.users.get_mut(username) else {
            return;
        };
        if entry.quarantined {
            return;
        }
        entry.consecutive_failures = 0;
        entry.cooling_until = None;
    }

    /// Permanently quarantine a user. Returns `true` if newly quarantined.
    pub fn quarantine(&mut self, username: &str) -> bool {
        let entry = self.users.entry(username.to_owned()).or_insert(UserEntry {
            consecutive_failures: 0,
            cooling_until: None,
            quarantined: false,
        });
        if entry.quarantined {
            return false;
        }
        entry.quarantined = true;
        entry.cooling_until = None;
        entry.consecutive_failures = 0;
        true
    }

    #[must_use]
    pub fn is_quarantined(&self, username: &str) -> bool {
        self.users.get(username).is_some_and(|e| e.quarantined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, advance};

    #[test]
    fn disabled_threshold_never_cools() {
        let mut guard = LockoutGuard::new(0, Duration::from_mins(1));
        for _ in 0..10 {
            assert_eq!(guard.record_failure("alice"), UserLockStatus::Active);
            assert!(guard.allow("alice"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn threshold_cools_then_resumes_after_cooldown() {
        let cooldown = Duration::from_secs(15);
        let mut guard = LockoutGuard::new(2, cooldown);

        assert_eq!(guard.record_failure("alice"), UserLockStatus::Active);
        assert_eq!(guard.record_failure("alice"), UserLockStatus::Cooling);
        assert!(!guard.allow("alice"));
        assert_eq!(guard.status("alice"), UserLockStatus::Cooling);

        advance(cooldown).await;
        assert!(guard.allow("alice"));
        assert_eq!(guard.status("alice"), UserLockStatus::Active);
    }

    #[tokio::test(start_paused = true)]
    async fn success_resets_consecutive_failures() {
        let mut guard = LockoutGuard::new(3, Duration::from_mins(1));
        assert_eq!(guard.record_failure("bob"), UserLockStatus::Active);
        assert_eq!(guard.record_failure("bob"), UserLockStatus::Active);
        guard.record_success("bob");
        assert_eq!(guard.record_failure("bob"), UserLockStatus::Active);
        assert_eq!(guard.record_failure("bob"), UserLockStatus::Active);
        assert!(guard.allow("bob"));
    }

    #[test]
    fn locked_out_quarantines_permanently() {
        let mut guard = LockoutGuard::new(0, Duration::from_secs(1));
        assert!(guard.quarantine("carol"));
        assert!(!guard.quarantine("carol"));
        assert!(!guard.allow("carol"));
        assert!(guard.is_quarantined("carol"));
        assert_eq!(guard.status("carol"), UserLockStatus::Quarantined);
        // Failures / success must not lift quarantine.
        assert_eq!(guard.record_failure("carol"), UserLockStatus::Quarantined);
        guard.record_success("carol");
        assert!(!guard.allow("carol"));
    }

    #[tokio::test(start_paused = true)]
    async fn users_are_tracked_independently() {
        let mut guard = LockoutGuard::new(1, Duration::from_secs(30));
        assert_eq!(guard.record_failure("alice"), UserLockStatus::Cooling);
        assert!(guard.allow("bob"));
        assert!(!guard.allow("alice"));
    }
}
