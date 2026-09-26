// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Machine-readable and interactive attack reporting.

pub mod jsonl;
pub mod session;
pub mod tui;

pub use jsonl::{JsonlError, JsonlReporter, ReportEvent};
pub use session::{ReporterMode, SessionReporter};
pub use tui::{DashboardStats, ProgressDashboard};
