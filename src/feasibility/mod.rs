// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Phase 11 enterprise protocol feasibility prototypes (feature-gated).

#[cfg(feature = "feasibility-rdp")]
pub mod rdp;

#[cfg(feature = "feasibility-smb")]
pub mod smb;
