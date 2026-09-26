# AGENTS.md — Agent Operating Guide for Betterh

Betterh is a modern, high-performance, memory-safe network authentication auditor written in Rust.

This document defines the operational rules, architectural references, idiomatic Rust standards, and workflows for AI agents working in this repository.

---

## 1. Core Reference & Source of Truth

- **Technical Specification**: Consult [`docs/SPEC.md`](file:///home/volker/Sources/betterh/docs/SPEC.md) for detailed architecture, the `ProtocolModule` trait contract, concurrency engine design, and CLI parameters.
- **Implementation Plan & Tasks**: Consult [`docs/PLAN.md`](file:///home/volker/Sources/betterh/docs/PLAN.md) for the phased roadmap, task lists, and verification checkpoints.
- **Spec-First Rule**: Any architectural deviation, trait adjustment, or feature scope change must be updated in `docs/SPEC.md` before writing implementation code.

---

## 2. Behavioral Guidelines (Karpathy Principles)

All agents working on this codebase must adhere to these four core principles:

### A. Think Before Coding
- **Don't assume. Don't hide confusion. Surface trade-offs.**
- Before implementing a protocol, error condition, or feature, state assumptions explicitly.
- If multiple protocol variants or interpretations exist (e.g., HTTP Form URL-encoded vs. multipart, SSH auth methods), present them rather than deciding silently.
- Push back if an ask overcomplicates the tool.

### B. Simplicity First
- **Minimum code that solves the problem. Nothing speculative.**
- No speculative dynamic plugins or script runtimes in MVP; keep to native Rust traits.
- No single-use abstractions or unnecessary wrappers over Tokio / standard libraries.
- No unrequested features or premature configuration layers.
- If an implementation can be done cleanly in 50 lines instead of 200, rewrite it.

### C. Surgical Changes
- **Touch only what you must. Clean up only your own mess.**
- When modifying an existing protocol or engine file, do not reformat or "improve" adjacent unrelated code.
- Match existing repository style and idioms.
- Every changed line in a diff must directly trace back to the prompt/task.
- Clean up any imports or types that your changes made unused.

### D. Goal-Driven Execution
- **Define success criteria. Loop until verified.**
- Structure multi-step work into verifiable checkpoints:
  1. Define test case or reproduction → verify
  2. Implement minimal logic → verify (`cargo test`)
  3. Strict lint & format check → verify (`cargo clippy`, `cargo fmt`)
- Never conclude a task without verifying code compilation and tests.

---

## 3. Idiomatic Rust Coding Standards (Apollo & Tokio Guidelines)

To achieve enterprise-grade, high-level Rust code, every module must adhere to these extracted guidelines:

### A. Ownership, Borrowing & Zero Allocation
- **Borrow over Clone**: Prefer `&T` over `.clone()`. Use `&str` over `&String` and `&[T]` over `&Vec<T>` in function signatures.
- **Pass Copy Types by Value**: Small `Copy` types ($\le 24$ bytes / 3 words of memory, e.g., primitive integers, booleans, small coordinate/port structs) should be passed by value, not by reference.
- **Lazy Evaluation**: Never use eager allocation methods when lazy equivalents exist:
  - Prefer `.unwrap_or_else(|| ...)` / `.unwrap_or_default()` over `.unwrap_or(...)`.
  - Prefer `.ok_or_else(|| ...)` over `.ok_or(...)` when the error requires allocation or string formatting.
- **Avoid Unnecessary Collections**: Prefer iterators over manual loops; avoid intermediate `.collect()` calls just to iterate again.
- **Conditional Ownership**: Use `std::borrow::Cow<'_, str>` or `Cow<'_, [u8]>` when data might be borrowed in the fast path and owned only when modified or decoded.

### B. Error Handling Discipline
- **Zero Unwraps**: Never call `.unwrap()` or `.expect()` in protocol or attack engine paths. Bubble errors via `Result` and `?`.
- **Domain vs. App Errors**:
  - Use `thiserror::Error` for internal protocol, network, and engine modules.
  - Use `anyhow` or `eyre` with `.context(...)` exclusively in application/CLI entrypoints (`main.rs`, `cli.rs`).
- **Idiomatic Pattern Matching**:
  - Prefer `let Some(x) = expr else { return ... };` for early returns over deep nesting.
  - Use `.inspect_err(|e| tracing::warn!(...))` for observability before transforming errors.

### C. Async & Tokio Concurrency Rules
- **Never Block the Runtime**:
  - Strictly forbid `std::thread::sleep`, blocking file I/O, or blocking network calls inside async functions. Use `tokio::time::sleep` and Tokio async I/O.
  - Offload heavy CPU computations (e.g., cryptographic hashing) to `tokio::task::spawn_blocking`.
- **No Locks Across Await**:
  - Never hold a standard `std::sync::MutexGuard` across an `.await` point. If synchronization is needed, use `tokio::sync::Mutex` or restructure to message passing.
- **Channels Over Shared Mutable State**:
  - Prefer `tokio::sync::mpsc` for producer-consumer pipelines (e.g., wordlist dispatchers) and `oneshot` for task responses.
- **Bounded Spawning**:
  - Never spawn unbounded tasks in a loop (`for _ in ... { tokio::spawn(...) }`). Control concurrency using `tokio::sync::Semaphore` or worker pools.
  - Manage task lifecycles with `tokio::task::JoinSet` so child tasks can be awaited or aborted collectively.
- **Cooperative Cancellation**:
  - Integrate `tokio_util::sync::CancellationToken` and `tokio::select!` for clean, immediate shutdown on user cancel (`SIGINT`).

### D. Type Safety & Type-State Pattern
- **Make Illegal States Unrepresentable**:
  - Use the Newtype pattern for domain types (e.g., `struct Port(u16)`, `struct RateLimit(u32)`).
  - Use the Type-State pattern to enforce connection and protocol lifecycles at compile time (e.g., `Connection<Disconnected>` cannot call `.send()`; only `Connection<Connected>` can).
- **Enums**:
  - Guard against `large_enum_variant` by `Box`-ing oversized variant payloads to keep the enum tag small.

### E. Clippy & Linting Discipline
- Always run: `cargo clippy --all-targets --all-features --locked -- -D warnings`
- Enable `pedantic` and `perf` lint groups in `Cargo.toml`.
- **No Silent Allows**: Never use `#[allow(clippy::...)]` unless documented. Prefer `#[expect(clippy::lint_name)]` with a comment explaining the rationale, so Clippy alerts us when the suppression becomes obsolete.

### F. Licensing & SPDX Headers
- Every Rust source file (`src/**/*.rs`, `tests/**/*.rs`) MUST begin with the standardized SPDX license identifier and copyright header:
  ```rust
  // SPDX-License-Identifier: MIT OR Apache-2.0
  // Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>
  ```

---

## 4. How to Add a New Protocol Module

When prompted to implement a new protocol (e.g., `smtp`, `mysql`, `rdp`), follow this checklist:

1. **Read the Spec**: Verify the [`ProtocolModule`](file:///home/volker/Sources/betterh/docs/SPEC.md#5-core-trait-protocolmodule) trait definition in `src/protocols/mod.rs`.
2. **Create Module File**: Add `src/protocols/<service>.rs`.
3. **Implement Trait**:
   ```rust
   use crate::protocols::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};
   use async_trait::async_trait;
   use std::time::Duration;

   pub struct ExampleModule;

   #[async_trait]
   impl ProtocolModule for ExampleModule {
       fn name(&self) -> &'static str { "example" }
       fn default_port(&self) -> u16 { 1234 }

       async fn authenticate(
           &self,
           target: &Target,
           cred: &Credential,
           timeout: Duration,
       ) -> Result<AuthResult, ProtocolError> {
           // Surgical, minimal protocol authentication attempt
           todo!()
       }
   }
   ```
4. **Register Module**: Add the module to the registry in `src/protocols/mod.rs` and the CLI enum in `src/cli.rs`.
5. **Unit / Mock Tests**: Add unit tests using local mock listeners (e.g., `tokio::net::TcpListener` or mock HTTP server) within the module's `#[cfg(test)]` block.
6. **Verify**: Run `cargo test --bin betterh protocols::<service>` and `cargo clippy`.

---

## 5. Standard Verification Commands

Agents must run these checks before completing any task:

```bash
# Verify formatting
cargo fmt --check

# Strict linting (pedantic + perf + zero warnings)
cargo clippy --all-targets --all-features --locked -- -D warnings

# Execute all tests
cargo test
```

---

## 6. Mandatory GitHub Pull Request (PR) Workflow

Every agent (Cursor, Codex, Antigravity, etc.) working on this repository MUST strictly follow a GitHub Pull Request workflow:

1. **Branch-Per-Feature / Phase**:
   - Never work directly on `master` or `main`.
   - All work must be developed on focused topic branches:
     - `feat/phase-<N>-<topic>` (e.g. `feat/phase-3-coordinator`, `feat/phase-4-protocols`)
     - `fix/<issue-description>`
     - `refactor/<topic>`
2. **Quality Gates Before PR**:
   - Code formatting: `cargo fmt --check`
   - Strict Clippy: `cargo clippy --all-targets --all-features --locked -- -D warnings` (0 warnings)
   - Comprehensive test suite: `cargo test` (all unit and integration tests passing)
   - SPDX headers: `// SPDX-License-Identifier: MIT OR Apache-2.0` and `// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>` on all files.
3. **Commit & PR Submission Process**:
   - Commit locally with `--no-gpg-sign` using conventional commit messages.
   - **Do NOT execute `git push`** (prohibited by repository safety rules).
   - Inform the human user that the branch is ready to be pushed to GitHub (`origin`).
   - After the branch is pushed to `origin`, open a GitHub Pull Request against `master` using `gh pr create` or the GitHub UI.
   - Every Pull Request must include:
     - Clear description of architectural rationale and changes.
     - References to specific tasks in `docs/PLAN.md`.
     - Verification checklist confirming `cargo test`, `cargo clippy`, and `cargo fmt`.

---

## 7. Critical Repository Rules

- **CRITICAL RULE — Never Git Push**: Never execute `git push`. You are strictly forbidden from pushing to any remote repository. Staging and committing locally is permitted, but pushing to origin is exclusively reserved for the human user.
- **CRITICAL RULE — Mandatory GitHub Pull Requests**: All feature, protocol, engine, and documentation work must be merged via GitHub Pull Requests. Direct commits or pushes to `master`/`main` without a reviewed Pull Request are strictly forbidden.
