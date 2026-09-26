// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Adaptive indicatif dashboard with pinned success feed.

use std::io::{self, IsTerminal};

use console::style;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

/// Live counters shown on the progress bar template.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DashboardStats {
    pub completed: u64,
    pub found: u64,
    pub rate_per_sec: f64,
    pub active_targets: usize,
    pub concurrency: usize,
}

/// Live TTY progress UI, or a silent no-op sink for pipes / quiet mode.
pub struct ProgressDashboard {
    inner: Option<ActiveDashboard>,
}

struct ActiveDashboard {
    multi: MultiProgress,
    bar: ProgressBar,
}

impl ProgressDashboard {
    /// Create a dashboard when stdout is a TTY and quiet mode is off.
    ///
    /// `total` is the known candidate count when available; otherwise an
    /// indeterminate spinner-style bar is used.
    #[must_use]
    pub fn new(quiet: bool, total: Option<u64>) -> Self {
        if quiet || !io::stdout().is_terminal() {
            return Self { inner: None };
        }

        let multi = MultiProgress::new();
        let bar = match total {
            Some(n) => ProgressBar::new(n),
            None => ProgressBar::new_spinner(),
        };
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} [{elapsed_precise}] {wide_bar:.cyan/blue} {pos}/{len} \
                 {msg} ({per_sec}, ETA {eta})",
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("##-"),
        );
        let bar = multi.add(bar);
        bar.enable_steady_tick(std::time::Duration::from_millis(120));

        Self {
            inner: Some(ActiveDashboard { multi, bar }),
        }
    }

    /// Whether the dashboard is actively drawing (TTY and not quiet).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.inner.is_some()
    }

    /// Pin a success line above the progress bars so it never scrolls away.
    pub fn success(&self, target: &str, username: &str, password: Option<&str>) {
        let Some(active) = &self.inner else {
            return;
        };
        let pass = password.unwrap_or("");
        let line = format!(
            "{} {target} - {username}:{pass}",
            style("[SUCCESS]").green().bold()
        );
        active.bar.println(line);
    }

    /// Pin a throttling / backoff warning above the progress bars.
    pub fn warn(&self, message: &str) {
        let Some(active) = &self.inner else {
            return;
        };
        let line = format!("{} {message}", style("[WARN]").yellow().bold());
        active.bar.println(line);
    }

    /// Refresh counters shown in the progress message area.
    pub fn set_stats(&self, stats: DashboardStats) {
        let Some(active) = &self.inner else {
            return;
        };
        active.bar.set_position(stats.completed);
        active.bar.set_message(format!(
            "found={} active={} conc={} {:.1}/s",
            stats.found, stats.active_targets, stats.concurrency, stats.rate_per_sec
        ));
    }

    /// Mark the known total (e.g. after dry-run estimation finishes).
    pub fn set_length(&self, total: u64) {
        let Some(active) = &self.inner else {
            return;
        };
        active.bar.set_length(total);
    }

    /// Finish and clear the live bars.
    pub fn finish(&self) {
        let Some(active) = &self.inner else {
            return;
        };
        active.bar.finish_and_clear();
        let _ = &active.multi;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_mode_never_activates_dashboard() {
        let dash = ProgressDashboard::new(true, Some(100));
        assert!(!dash.is_active());
        // Must not panic or write ANSI when inactive.
        dash.success("10.0.0.1:22", "admin", Some("pass"));
        dash.warn("rate limited");
        dash.set_stats(DashboardStats {
            completed: 1,
            found: 0,
            rate_per_sec: 0.0,
            active_targets: 0,
            concurrency: 1,
        });
        dash.finish();
    }

    #[test]
    fn forced_inactive_dashboard_is_noop() {
        // Construct via quiet path so CI / non-TTY runners stay clean.
        let dash = ProgressDashboard::new(true, None);
        assert!(!dash.is_active());
        dash.set_length(50);
        dash.finish();
    }
}
