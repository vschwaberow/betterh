// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Adaptive session reporter: TUI dashboard and/or JSONL sink.

use std::path::Path;

use crate::cli::OutputFormat;
use crate::protocols::{Credential, Target};
use crate::report::{
    jsonl::{JsonlError, JsonlReporter, ReportEvent},
    tui::{DashboardStats, ProgressDashboard},
};

/// How the operator requested output to be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReporterMode {
    /// Live text dashboard when stdout is a TTY (unless quiet).
    Text,
    /// Line-delimited JSON events (stdout or `--output` file).
    Jsonl,
    /// Compact JSON object stream (treated like JSONL for MVP).
    Json,
}

impl ReporterMode {
    /// Derive the mode from CLI flags and stdout TTY state.
    #[must_use]
    pub fn from_cli(format: Option<OutputFormat>, quiet: bool) -> Self {
        match format {
            Some(OutputFormat::Jsonl) => Self::Jsonl,
            Some(OutputFormat::Json) => Self::Json,
            Some(OutputFormat::Text) | None if quiet => Self::Text,
            None if !std::io::IsTerminal::is_terminal(&std::io::stdout()) => Self::Jsonl,
            Some(OutputFormat::Text) | None => Self::Text,
        }
    }
}

/// Dual-sink reporter used by the attack engine and dry-run paths.
pub struct SessionReporter {
    mode: ReporterMode,
    jsonl: Option<JsonlReporter>,
    tui: ProgressDashboard,
}

impl SessionReporter {
    /// Build a reporter from CLI-equivalent options.
    ///
    /// # Errors
    /// Returns [`JsonlError`] when an output file cannot be created.
    pub fn open(
        mode: ReporterMode,
        quiet: bool,
        output: Option<&Path>,
        total: Option<u64>,
    ) -> Result<Self, JsonlError> {
        let jsonl = match (mode, output) {
            (ReporterMode::Jsonl | ReporterMode::Json, Some(path)) => {
                Some(JsonlReporter::file(path)?)
            }
            (ReporterMode::Jsonl | ReporterMode::Json, None) => Some(JsonlReporter::stdout()),
            (ReporterMode::Text, Some(path)) => Some(JsonlReporter::file(path)?),
            (ReporterMode::Text, None) => None,
        };

        let suppress_tui = quiet || !matches!(mode, ReporterMode::Text);
        let tui = ProgressDashboard::new(suppress_tui, total);

        Ok(Self { mode, jsonl, tui })
    }

    #[must_use]
    pub const fn mode(&self) -> ReporterMode {
        self.mode
    }

    #[must_use]
    pub fn tui_active(&self) -> bool {
        self.tui.is_active()
    }

    /// Record a successful credential discovery.
    ///
    /// # Errors
    /// Returns [`JsonlError`] when the JSONL sink fails.
    pub fn success(
        &mut self,
        service: &str,
        target: &Target,
        cred: &Credential,
    ) -> Result<(), JsonlError> {
        self.tui.success(
            &target.to_string(),
            &cred.username,
            cred.password.as_deref(),
        );
        if let Some(jsonl) = &mut self.jsonl {
            jsonl.emit(&ReportEvent::success(service, target, cred))?;
        }
        Ok(())
    }

    /// Emit a SPEC-style throttling warning for a target.
    ///
    /// # Errors
    /// Returns [`JsonlError`] when the JSONL sink fails.
    pub fn rate_limited(
        &mut self,
        target: &str,
        retry_after: std::time::Duration,
    ) -> Result<(), JsonlError> {
        let secs = retry_after.as_secs_f64();
        self.warn(format!(
            "Target {target} returned rate-limit; throttling back for {secs:.1}s..."
        ))
    }

    /// Emit a lockout warning for a target/user pair.
    ///
    /// # Errors
    /// Returns [`JsonlError`] when the JSONL sink fails.
    pub fn locked_out(&mut self, target: &str, username: &str) -> Result<(), JsonlError> {
        self.warn(format!(
            "Target {target} locked out account {username}; skipping remaining work"
        ))
    }

    /// Permanently quarantine a username and emit structured telemetry.
    ///
    /// # Errors
    /// Returns [`JsonlError`] when the JSONL sink fails.
    pub fn account_quarantined(&mut self, username: &str) -> Result<(), JsonlError> {
        self.tui.warn(&format!(
            "Account {username} quarantined after lockout signal; skipping remaining work"
        ));
        self.emit(&ReportEvent::account_quarantined(username, "locked_out"))
    }

    /// Pin / emit an operator warning.
    ///
    /// # Errors
    /// Returns [`JsonlError`] when the JSONL sink fails.
    pub fn warn(&mut self, message: impl Into<String>) -> Result<(), JsonlError> {
        let message = message.into();
        self.tui.warn(&message);
        if let Some(jsonl) = &mut self.jsonl {
            jsonl.emit(&ReportEvent::Warn { message })?;
        }
        Ok(())
    }

    /// Refresh live counters.
    pub fn set_stats(&self, stats: DashboardStats) {
        self.tui.set_stats(stats);
    }

    /// Emit a raw structured event (JSONL / file sinks only).
    ///
    /// # Errors
    /// Returns [`JsonlError`] when the JSONL sink fails.
    pub fn emit(&mut self, event: &ReportEvent) -> Result<(), JsonlError> {
        if let Some(jsonl) = &mut self.jsonl {
            jsonl.emit(event)?;
        }
        Ok(())
    }

    pub fn finish(&self) {
        self.tui.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_modes_reject_existing_output_without_modifying_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.jsonl");
        std::fs::write(&path, "previous report\n").unwrap();

        for mode in [ReporterMode::Text, ReporterMode::Json, ReporterMode::Jsonl] {
            let result = SessionReporter::open(mode, true, Some(&path), None);
            assert!(matches!(result, Err(JsonlError::Create { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists));
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "previous report\n");
        }
    }

    #[test]
    fn quiet_text_mode_keeps_tui_inactive() {
        let session = SessionReporter::open(ReporterMode::Text, true, None, Some(10)).unwrap();
        assert!(!session.tui_active());
        session.finish();
    }

    #[test]
    fn rate_limited_warning_matches_spec_shape() {
        let mut session = SessionReporter::open(ReporterMode::Text, true, None, None).unwrap();
        session
            .rate_limited("192.168.1.100", std::time::Duration::from_millis(4200))
            .unwrap();
        session.finish();
    }

    #[test]
    fn jsonl_mode_writes_events_to_owner_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.jsonl");
        let mut session =
            SessionReporter::open(ReporterMode::Jsonl, false, Some(&path), None).unwrap();
        session.warn("hello").unwrap();
        session.finish();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(r#""event":"warn""#));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
