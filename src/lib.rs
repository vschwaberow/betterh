// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Shared contracts, command-line parsing, and configuration for Betterh.

pub mod cli;
pub mod config;
pub mod engine;
pub mod feasibility;
pub mod fsutil;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod protocols;
pub mod report;
pub mod service;
pub mod ui;
