// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Phase 11.2 offline RDP / `CredSSP` framing harness.
//!
//! Production codecs live in `crate::protocols::rdp`; this module re-exports them
//! so `feasibility-rdp` keeps a stable path for docs and feature gates.

pub use crate::protocols::rdp::*;
