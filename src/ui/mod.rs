// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Interactive UX helpers: diagnostics, wizard, completions, and man pages.

pub mod completions;
pub mod diagnostics;
pub mod wizard;

pub use completions::{generate_completions, generate_manpage};
pub use diagnostics::{Diagnostic, DiagnosticKind};
pub use wizard::{WizardPlan, WizardService, run_interactive};
