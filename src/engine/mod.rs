// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Streaming inputs and attack execution support.

pub mod actions;
pub mod adaptive;
pub mod canary;
pub mod checkpoint;
pub mod dryrun;
pub mod keys;
pub mod mutations;
pub mod pool;
pub mod proxy;
pub mod request_guard;
pub mod runner;
pub mod scope;
pub mod spray;
pub mod targets;
pub mod wordlist;

pub use actions::{FoundContext, SkipRules, SkipState, on_discovery, parse_command};
pub use adaptive::AdaptiveLimiter;
pub use checkpoint::{
    Checkpoint, CheckpointEntry, CheckpointError, load as load_checkpoint, save as save_checkpoint,
};
pub use dryrun::{
    DryRunError, DryRunReport, Reachability, audit, audit_with_cancellation, render_table,
};
pub use keys::{RuntimeCommand, interpret_key, listen as listen_keys};
pub use mutations::{
    MutationError, Rule, RuleOp, RuleSet, generate_leet_candidates, generate_season_candidates,
    generate_year_candidates,
};
pub use pool::{Attempt, Finding, PoolConfig, PoolError, prepare_target, run_brute};
pub use proxy::{Pacer, ProxyError, ProxyPool};
pub use request_guard::{GuardError, RequestGuard, StopReason};
pub use runner::{RunError, run_attack};
pub use spray::{SprayConfig, SprayRound, run_spray};
pub use wordlist::{
    CredentialInput, CredentialStream, InputSource, Wordlist, WordlistError, credentials,
};
