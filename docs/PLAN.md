# Implementation Plan: Betterh (v0.1.0 MVP)

This document defines the phased, contract-first implementation roadmap for **Betterh**. Every phase has discrete tasks, explicit acceptance criteria, and verifiable checkpoints.

---

## Architecture & Dependency Flow

```
+-------------------------------------------------------------------+
|               Phase 1: Foundation & Domain Contracts              |
|  - Domain Types (Target, Credential, AuthResult, CanaryStatus)    |
|  - ProtocolModule Trait (authenticate + canary_probe) & Mock      |
|  - CLI Parser (URL-first & positional hybrid, clap derive)        |
|  - Hierarchical Config Loader (CLI > Env > config.toml)           |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|               Phase 2: Wordlist Engine (O(1) Memory)              |
|  - AsyncBufReadExt streaming generator                            |
|  - Unix Pipe Stdin streaming (-P - / -L -)                        |
|  - Mangling rules (-e n, -e s, -e r)                              |
|  - Combinations (single, list, cartesian, combos)                 |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|   Phase 3: Concurrency Engine, Evasion, Spraying & Guardrails     |
|  - Target expander (File -M, CIDR ipnet generator)                |
|  - Scope guardrails (--exclude, --exclude-file, public check)     |
|  - Pre-flight canary false-positive detector                      |
|  - Proxy & Evasion hub (SOCKS5/HTTP, list rotation, jitter)       |
|  - Horizontal Password Spraying coordinator & cooldowns           |
|  - Worker pool (Semaphore + JoinSet) & Adaptive Backoff           |
|  - Granular skip rules (--exit-user/host/first) & --on-found hook  |
|  - Runtime Keystroke Listener (Space, p, +, -, c, q)              |
|  - Cooperative cancellation & Checkpointing (POSIX 0600)          |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|      Phase 4: Core Protocol Implementations & Hermetic Mocks      |
|  - 4.1 FTP / Raw TCP (TcpStream + Type-State + in-process mock)   |
|  - 4.2 HTTP (Basic, Form-POST, Bearer + wiremock in-process)      |
|  - 4.3 SSH (russh async sessions + in-process server mock)        |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|              Phase 5: User Interface, UX & Reporting              |
|  - 5.1 JSON / JSONL streaming reporter with 0600 file permissions |
|  - 5.2 Adaptive TUI dashboard with pinned success feed            |
|  - 5.3 Interactive Setup Wizard (inquire prompts)                 |
|  - 5.4 Pre-flight --dry-run combination audit & estimator         |
|  - 5.5 Actionable diagnostics with remediation tips               |
|  - 5.6 Shell autocompletions & man-page generator                 |
+-----------------------------------+-------------------------------+
```

---

## Git Branching & GitHub Pull Request Strategy

- **Feature-Branch Workflow**: Every phase and major task must be developed on a dedicated topic branch (`feat/phase-<N>-<topic>`, `fix/<topic>`, `refactor/<topic>`). Never work directly on `master` or `main`.
- **Mandatory GitHub Pull Requests**: All changes across all phases must be integrated via GitHub Pull Requests against `master`. Direct commits or direct merges to `master` without a reviewed PR are strictly prohibited.
- **Push & PR Procedure**:
  1. Complete local implementation, ensuring `cargo fmt --check`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, `cargo test`, and SPDX headers are 100% clean.
  2. Commit locally with `--no-gpg-sign`.
  3. **Never execute `git push`** (exclusively reserved for the human user).
  4. Notify the user that the branch is ready to be pushed to GitHub (`origin`).
  5. After the branch is pushed by the user, open a GitHub Pull Request using `gh pr create` or the GitHub Web UI, using the template in `.github/pull_request_template.md`.

---

## Phase 1: Foundation & Domain Contracts

**Goal**: Establish core data types, trait contracts, error definitions, CLI parser with URL-first hybrid syntax, and hierarchical configuration loader with full lint gating.

### Tasks
- [x] **Task 1.1: Project Scaffolding & Git Init**
  - **Description**: Initialize local git repository, configure `src/lib.rs` and `src/main.rs`.
  - **Acceptance**: `cargo check` and `cargo test` succeed.
  - **Files**: `src/lib.rs`, `src/main.rs`
  - **Verify**: `cargo check --all-targets`

- [x] **Task 1.2: Core Domain Types**
  - **Description**: Implement `Target`, `Credential`, `AuthResult`, `CanaryStatus`, and `ProtocolError` using `thiserror`. Pass small `Copy` types by value; use borrowed references (`&str`) where applicable.
  - **Acceptance**: All types implement `Debug`, `Clone`, and relevant comparisons. Zero unwrap.
  - **Files**: `src/protocols/types.rs`, `src/protocols/mod.rs`
  - **Verify**: Unit tests verifying serialization, hashing, and display formatting.

- [x] **Task 1.3: `ProtocolModule` Trait & `MockProtocolModule`**
  - **Description**: Define the `#[async_trait] pub trait ProtocolModule` with `authenticate` and `canary_probe`. Implement an in-memory `MockProtocolModule` with configurable latency, success rate, and rate-limiting responses.
  - **Acceptance**: `MockProtocolModule` satisfies the trait and can simulate normal and catch-all behaviors.
  - **Files**: `src/protocols/mod.rs`, `src/protocols/mock.rs`
  - **Verify**: Unit tests asserting `mock.authenticate(...)` and `mock.canary_probe(...)` return configured states.

- [x] **Task 1.4: CLI Argument Parsing & URL-First Hybrid Syntax**
  - **Description**: Implement command-line parser using `clap` derive supporting:
    - URL-first & positional hybrid syntax: Automatically extracts service, host, port, path, and optional embedded user from URLs (`ssh://admin@10.0.0.1:2222`) or positional args (`ssh 10.0.0.1:2222`).
    - Dedicated long flags for modules: `--body`, `--fail-string`, `--success-string`, `-H` / `--header`, `--http-method`, `--cookie`, `--ssh-key`, `--ftp-passive`.
    - Targets & Scope: Single target, target file (`-M`), CIDR range (`192.168.1.0/24`), `--exclude <IP/CIDR>`, `--exclude-file <file>`.
    - Attack modes: Vertical brute-force vs Horizontal spray (`--mode spray`, `--spray-cooldown`).
    - Credentials: Single (`-u`, `-p`), Lists (`-L`, `-P`), Stdin pipe (`-P -`).
    - Mangling rules: `-e n` (empty), `-e s` (same as login), `-e r` (reverse).
    - Success controls & actions: `--exit-user`, `--exit-host`, `--exit-first`, `--on-found <cmd>`, `--bell`.
    - Proxies: `--proxy`, `--proxy-list`, `--delay`, `--jitter`.
    - UX modes: `--dry-run`, `wizard` subcommand, `completions` subcommand, `--format`, `--output`.
    - Empty call: Helpful colored quickstart guide with practical examples.
  - **Acceptance**: Parses all valid URL and positional syntax combinations; produces intuitive errors on conflicting options.
  - **Files**: `src/cli.rs`
  - **Verify**: Unit tests asserting parsing of various URL and flag scenarios.

- [x] **Task 1.5: Hierarchical Configuration Loader**
  - **Description**: Implement configuration layer (`src/config.rs`) reading optional `~/.config/betterh/config.toml` or `./betterh.toml` using `directories` and `toml`. Precedence: CLI Flags > `BETTERH_*` Env Vars > TOML Config > Default values.
  - **Acceptance**: Functions seamlessly with or without a config file on disk.
  - **Files**: `src/config.rs`
  - **Verify**: Unit tests asserting configuration priority and environment variable overrides.

### Phase 1 Checkpoint

Completed (2026-09-25): Tasks 1.1–1.5 are implemented in the isolated worktree
`/home/volker/Sources/betterh-phase-1-foundation`, branch `feat/phase-1-foundation`.
`Cargo.lock` is retained for reproducible locked builds.
Verification passed: `cargo check --all-targets --locked`, `cargo fmt --check`,
strict Clippy with all targets and features, and `cargo test --locked` (30 unit tests and 4 executable integration tests).
Network execution and UI commands remain scheduled for later phases in this worktree.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test
```

---

## Phase 2: Wordlist Engine ($O(1)$ Memory)

**Goal**: Provide a memory-bounded asynchronous stream of credential candidates from files, stdin pipes, or combinatorial generators.

### Tasks
- [x] **Task 2.1: Async Wordlist & Stdin Reader**
  - **Description**: Stream lines lazily using `tokio::io::AsyncBufReadExt`. Handle both regular files and `stdin` (`-P -` / `-L -`) without buffering. Strip `\r` and whitespace cleanly.
  - **Acceptance**: Constant resident memory ($< 15\text{ MB}$) regardless of wordlist or pipe length.
  - **Files**: `src/engine/wordlist.rs`
  - **Verify**: Test streaming a synthetic 1,000,000-line input stream verifying flat memory profile.

- [x] **Task 2.2: Combinatorial & Mangling Generator**
  - **Description**: Implement lazy generation for:
    1. Single user + single password
    2. Single user + password list
    3. User list + single password
    4. Cartesian product ($Users \times Passwords$)
    5. Combo list (`username:password` per line)
    6. Rule modifiers (`-e n` empty pass, `-e s` user as pass, `-e r` reverse user)
  - **Acceptance**: Yields credentials as an asynchronous stream without buffering or duplicating whole wordlists. Per-item allocations are bounded by the documented line limit.
  - **Files**: `src/engine/wordlist.rs`
  - **Verify**: Unit tests checking exact sequence and output for all combinatorial modes and mangling flags.

### Phase 2 Checkpoint

Completed (2026-09-25) on `feat/phase-2-wordlists` in the isolated worktree.
Implemented bounded UTF-8 reads, lazy file/stdin sources, all six combination modes,
and terminal error handling. SPEC section 7.4 defines whitespace handling, ordering,
the 64 KiB line limit, and stdin replay constraints.

Verification: 59 tests passed, including 18 wordlist unit tests, four real-pipe cases,
and Linux process-memory checks for files and stdin. With 1,000,000 synthetic lines,
observed peak RSS was 4,800 KiB for files and 4,792 KiB for stdin (both below 15 MB).
The 10,000-line baselines were 4,784 KiB and 4,796 KiB respectively.
`cargo check --all-targets --locked`, formatting, and strict all-features Clippy passed.

```bash
cargo test engine::wordlist
cargo test --test wordlist_stream
cargo clippy --all-targets -- -D warnings
```

---

## Phase 3: Concurrency Engine, Evasion, Spraying & Guardrails

**Goal**: Implement the core attack execution loop with bounded concurrency, adaptive backoff, target expansion, scope guardrails, canary verification, proxy routing, runtime keybindings, success skip rules, and session checkpointing.

### Tasks
- [x] **Task 3.1: Target Expander & Scope Guardrails**
  - **Description**: Expand targets from single strings, target files (`-M`), and CIDR notations (`192.168.1.0/24`) using `ipnet`. Apply exclusion filters (`--exclude <IP/CIDR>` and `--exclude-file <file>`) in `src/engine/scope.rs`. Stream targets lazily as `Target` items.
  - **Acceptance**: Correctly iterates IPv4/IPv6 CIDR subnets while omitting excluded addresses, without creating large vectors in memory.
  - **Files**: `src/engine/targets.rs`, `src/engine/scope.rs`
  - **Verify**: Unit tests verifying CIDR expansion with individual IP and subnet exclusions.

- [x] **Task 3.2: Pre-Flight Canary & False-Positive Verification**
  - **Description**: Execute `canary_probe` against targets before attacking. If `CanaryStatus::WildcardDetected` is returned, abort immediately with an alert unless `--force` is set.
  - **Acceptance**: Catch-all servers are detected with zero false-positive credentials logged.
  - **Files**: `src/engine/canary.rs`
  - **Verify**: Test simulating a wildcard mock server triggering the canary abort condition.

- [x] **Task 3.3: Proxy Routing & Request Pacing**
  - **Description**: Provide SOCKS5 and HTTP proxy support. Manage a thread-safe round-robin proxy pool (`--proxy-list`). Implement configurable request delays (`--delay`) and random variance (`--jitter`) for load distribution.
  - **Acceptance**: Requests distribute evenly over proxy pool; delays honor jitter specifications.
  - **Files**: `src/engine/proxy.rs`
  - **Verify**: Unit tests asserting proxy rotation order and jitter delay ranges.

- [x] **Task 3.4: Adaptive Rate Limiter & Backoff**
  - **Description**: Leaky bucket rate limiter per target with dynamic backoff when receiving `AuthResult::RateLimited` or repeated timeouts.
  - **Acceptance**: Smoothly adjusts request rate without dropping tasks.
  - **Files**: `src/engine/adaptive.rs`
  - **Verify**: Test simulating throttle signals asserting rate decreases.

- [x] **Task 3.5: Attack Coordinators: Brute-Force & Spraying**
  - **Description**:
    - Integrate scope and canary checks before credential attempts. Check each resolved socket address, connect to that checked address without another DNS lookup, and enforce public-address confirmation or `--force` before network work.
    - DNS Stampede Prevention: Resolve hostnames once per target, validate scope on the resolved `SocketAddr`, and pin the address across worker attempts with original SNI/Host header preserved.
    - Ephemeral Port Management: Bound active socket creations with the concurrency semaphore (`-t`) to prevent local TCP port exhaustion (`TIME_WAIT` saturation).
    - Vertical Brute-Force: Workers pull credentials and test against targets until exhausted.
    - Horizontal Password Spraying (`--mode spray`): Tests candidate password $P_i$ across all target accounts, pauses for `--spray-cooldown`, then proceeds to $P_{i+1}$. Isolates locked accounts (`AuthResult::LockedOut`).
  - **Acceptance**: Concurrency strictly governed by `tokio::sync::Semaphore` and `tokio::task::JoinSet<()>`; zero redundant DNS queries per attempt.
  - **Files**: `src/engine/pool.rs`, `src/engine/spray.rs`
  - **Verify**: Concurrency tests with `MockProtocolModule` verifying both vertical and spray execution flows.

- [x] **Task 3.6: Success Skip Rules & Safe Action Hooks**
  - **Description**:
    - Enforce `--exit-user` (skip remaining passwords for found user), `--exit-host` (skip host on first match), `--exit-first` (stop attack).
    - Asynchronously trigger `--on-found "<cmd>"` passing `BETTERH_TARGET`, `BETTERH_SERVICE`, `BETTERH_USERNAME`, `BETTERH_PASSWORD` securely as environment variables.
    - Sound terminal bell on `--bell`.
  - **Acceptance**: Skip rules accurately skip remaining work; child processes execute safely without shell injection.
  - **Files**: `src/engine/actions.rs`
  - **Verify**: Unit tests asserting user skip behavior and environment variable presence in spawned commands.

- [x] **Task 3.7: Interactive Runtime Key Listener**
  - **Description**: Read raw keyboard events via `crossterm::event::EventStream` in a dedicated background task. Handle:
    - `Space` / `s`: Send status snapshot signal to dashboard.
    - `p` / `P`: Toggle execution pause on worker pool.
    - `+` / `-`: Dynamically add or release semaphore permits to adjust concurrency.
    - `c` / `C`: Request manual checkpoint save.
    - `q` / `Ctrl+C`: Trigger cooperative shutdown.
  - **Acceptance**: Works without blocking the async runtime or corrupting terminal input.
  - **Files**: `src/engine/keys.rs`
  - **Verify**: Unit test asserting keystroke events dispatch expected commands.

- [x] **Task 3.8: Cooperative Cancellation & Secure Checkpointing**
  - **Description**: Handle `SIGINT` and `q` keypress via `CancellationToken`. Atomically serialize session progress to `.betterh-session-<hash>.json` with mode `0600`. Support resuming via `--resume`.
  - **Acceptance**: Session resumes exactly where interrupted; file permissions are strictly `0600`.
  - **Files**: `src/engine/checkpoint.rs`
  - **Verify**: Interruption and resumption test verifying skipped credentials and POSIX permissions.

### Phase 3 Checkpoint

Tasks 3.1 and 3.2 are complete on `feat/phase-3-targets-canary`.
Target expansion streams IPv4/IPv6 ranges and files, skips excluded ranges, and preserves target order.
Scope classification reports unresolved hostnames and addresses requiring confirmation.
The canary gate handles wildcard results, `--force`, deadlines, and cancellation.
Coordinator integration, including DNS address checks and confirmation, remains part of Task 3.5.
Phase 3 tasks 3.1–3.8 are complete.

Verification: 81 tests passed, including 22 new target, scope, and canary tests.
`cargo check --all-targets --locked`, `cargo fmt --check`, and
`cargo clippy --all-targets --all-features --locked -- -D warnings` passed.

```bash
cargo test engine::
cargo clippy --all-targets -- -D warnings
```

---

## Phase 4: Core Protocol Implementations & Hermetic Mocks

**Goal**: Implement the three MVP protocols against real socket and HTTP specs with proxy support, backed by 100% hermetic, offline in-process mock server integration tests.

### Tasks
- [x] **Task 4.1: FTP / Raw TCP Module & In-Process Test Harness**
  - **Description**: Implement `FtpModule` (feature = `ftp`) using Tokio `TcpStream` and Type-State connection pattern. Support SOCKS5 tunneling via `tokio-socks`. Handle FTP RFC 959 banner, `USER`, `PASS`, codes 230/530.
  - **Acceptance**: Authenticates successfully against local in-process FTP mock server (`127.0.0.1:0`).
  - **Files**: `src/protocols/ftp.rs`
  - **Verify**: Integration test with local `tokio::net::TcpListener` simulating FTP dialogues.

- [x] **Task 4.2: HTTP Module & Wiremock Test Harness**
  - **Description**: Implement `HttpModule` (feature = `http`) supporting:
    - HTTP Basic Authentication
    - HTTP Form POST (`application/x-www-form-urlencoded` and JSON) with `{USER}` and `{PASS}` placeholders
    - Success/Failure detection via status code, headers, or body regex/string match
    - Proxy configuration through `reqwest`
  - **Acceptance**: Correctly differentiates successful logins from invalid credentials across status codes and response bodies using `wiremock`.
  - **Files**: `src/protocols/http.rs`
  - **Verify**: Hermetic integration test with local `wiremock::MockServer` testing Basic and Form-POST paths.

- [x] **Task 4.3: SSH Module & In-Process Server Harness**
  - **Description**: Implement `SshModule` (feature = `ssh`) using `russh` client authentication with proxy support. Handle connection timeouts, banner grabs, and password authentication attempts.
  - **Acceptance**: Robustly tests credentials against local in-process `russh::server` without leaking file descriptors or sessions.
  - **Files**: `src/protocols/ssh.rs`
  - **Verify**: Hermetic integration test with local mock SSH server socket on `127.0.0.1:0`.

- [x] **Task 4.4: Resilient Protocol Parsing & Non-Standard Server Tolerances**
  - **Description**: Ensure protocol implementations gracefully handle non-standard, legacy, or slightly malformed server dialogues:
    - FTP: Tolerantly parse multi-line banners (RFC 959 dash continuation), bare LF delimiters, and preliminary status messages.
    - HTTP: Support HTTP/1.0 fallback, parse non-standard headers, and handle missing `Content-Length` on authentication failure bodies. Reuse persistent transport connections (Keep-Alive) where protocol state allows to conserve socket resources.
    - SSH: Broad negotiation support across standard cryptographic algorithms without disconnecting on unexpected server identification string formats.
  - **Acceptance**: Parsers consume non-standard responses without panics, hangs, or premature disconnections.
  - **Files**: `src/protocols/ftp.rs`, `src/protocols/http.rs`, `src/protocols/ssh.rs`
  - **Verify**: Mock tests with non-standard banners, LF linebreaks, and missing header fields.

### Phase 4 Checkpoint
```bash
cargo test protocols::
cargo clippy --all-targets --all-features -- -D warnings
```

---

## Phase 5: User Interface, UX & Reporting

**Goal**: Deliver a polished developer and user experience with live terminal UI, interactive wizard, pre-flight dry-run, and machine-readable output.

### Tasks
- [x] **Task 5.1: Structured JSON / JSONL Output (0600)**
  - **Description**: Stream discovered credentials and audit telemetry as JSONL to `stdout` or a file (`--output <file>`). When creating files, enforce mode `0600`. Detect non-TTY outputs and suppress ANSI codes automatically.
  - **Acceptance**: Valid JSONL format, easily pipeable to `jq`. New files have owner-only permissions. Existing output paths are rejected atomically, including symbolic and hard links, without modifying their contents or permissions.
  - **Files**: `src/report/jsonl.rs`
  - **Verify**: Test JSON deserialization and file permissions. Regression tests preserve existing files and link targets; all session report modes reject existing files. JSON/JSONL dry-run CLI tests verify that `--force` cannot bypass output protection.

- [x] **Task 5.2: Live TUI Progress Dashboard with Pinned Success Feed**
  - **Description**: Implement adaptive dashboard using `indicatif` with:
    - Live multi-progress bars (rate, active targets, concurrency, ETA)
    - Pinned success feed above progress bars (ensures found credentials never scroll away)
    - Live throttling and backoff notices
  - **Acceptance**: Suppressed cleanly when non-interactive (piped) or in quiet mode (`-q`).
  - **Files**: `src/report/tui.rs`
  - **Verify**: Visual check and test ensuring no terminal pollution in `--quiet` or piped mode.

- [x] **Task 5.3: Actionable Diagnostics & Error Formatter**
  - **Description**: Implement structured Cargo-style error formatter for network, TLS, and configuration errors, providing precise context and remediation tips (`src/ui/diagnostics.rs`).
  - **Acceptance**: Replaces raw errors with clear, actionable diagnostics.
  - **Files**: `src/ui/diagnostics.rs`
  - **Verify**: Unit tests formatting mock connection and TLS errors.

- [x] **Task 5.4: Interactive Setup Wizard**
  - **Description**: Implement `betterh wizard` and `--interactive` using `inquire` prompts: guided selection of Service, Target, Wordlists, Concurrency, and Proxies.
  - **Acceptance**: Generates a valid attack configuration from user choices.
  - **Files**: `src/ui/wizard.rs`
  - **Verify**: Test asserting wizard generates equivalent CLI configuration struct.

- [x] **Task 5.5: Pre-Flight `--dry-run` Combination Audit**
  - **Description**: Implement `--dry-run` auditing: validate target reachability, compute total candidate count ($U \times P$), and estimate audit duration at baseline throughput.
  - **Scope enforcement**: Resolve each sampled hostname once and check each socket address before connecting. Exclusions always apply; non-local addresses require `--force`. Report skipped targets separately in text and JSON. Validate all inputs before probing.
  - **Wordlist consistency**: Share rule normalization with the credential generator, and validate/count combo rows through its stream. Repeated rule flags count once; repeated rows and empty passwords remain valid. Invalid rows fail before probes or report output without exposing their contents.
  - **Report output**: Honor `--output` in default text, explicit text, JSON, and JSONL modes, including `--quiet`. Write one JSONL event after a successful audit; reject existing output paths before printing the text summary.
  - **Acceptance**: Outputs comprehensive audit table and exits with code 0 without sending attack packets.
  - **Files**: `src/engine/dryrun.rs`
  - **Verify**: Local listener tests verify that permitted TCP probes send no application bytes, excluded addresses are never connected to, and invalid input prevents probes. Dry-run may perform DNS lookups and TCP handshakes.

- [x] **Task 5.6: Shell Completions & Man-Page Generator**
  - **Description**: Implement `betterh completions <shell>` and `betterh man` using `clap_complete` and `clap_mangen` for immediate tab-completion across bash, zsh, fish, and powershell, plus man-page generation.
  - **Acceptance**: Generates valid completion scripts and roff man-pages.
  - **Files**: `src/ui/completions.rs`
  - **Verify**: Test asserting completion output contains core subcommands and flags.

Completed (2026-09-25) on `feat/phase-5-ui`: Tasks 5.1–5.6 are implemented
(JSONL/TUI session reporter, diagnostics, wizard, dry-run audit, completions/man).
Dry-run combination counts reuse the Phase 2 `Wordlist` reader without materializing
the cartesian product. Live attack orchestration is wired through `engine::runner` (scope, canary, pool/spray, reporter).

### Phase 5 Checkpoint
```bash
cargo test
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Phase 6: Refactoring, Deduplication, Optimization & Licensing

**Goal**: Systematically refactor the codebase to eliminate duplicated logic, streamline async hot paths and memory usage, and ensure compliant SPDX license headers with copyright notice across all source files.

### Tasks
- [x] **Task 6.1: Code Deduplication**
  - **Description**: Audit modules for redundant logic (e.g., file reading, URL/address parsing, stream unfolding patterns, diagnostic rendering). Extract reusable shared utilities into cohesive internal modules without adding unnecessary abstraction layers.
  - **Acceptance**: Duplicate code blocks consolidated; total SLOC reduced without sacrificing readability or type safety.
  - **Files**: `src/engine/*`, `src/protocols/*`, `src/ui/*`, `src/report/*`
  - **Verify**: `cargo test` confirms zero functional regressions across all unit and integration tests.

- [x] **Task 6.2: Performance & Memory Optimization**
  - **Description**: Profile hot paths in target streaming, wordlist decoding, pacer jitter calculations, and event reporting. Eliminate lingering allocations (prefer `Cow<'_, str>`, pass small `Copy` types by value, shrink struct/enum memory layout). Verify persistent transport reuse and DNS address pinning prevent socket churn and resolver overload under peak load.
  - **Acceptance**: Benchmark and test runs maintain RSS flatline $< 15\text{ MB}$; zero allocation in inner loops; zero socket churn on persistent targets.
  - **Files**: `src/engine/wordlist.rs`, `src/engine/targets.rs`, `src/engine/proxy.rs`, `src/report/jsonl.rs`
  - **Verify**: `tests/wordlist_stream.rs` million-line tests continue to verify memory flatline.

- [x] **Task 6.3: SPDX License Headers & Copyright Notice**
  - **Description**: Add standard SPDX header and copyright notice to all existing and new Rust source files (`src/**/*.rs`, `tests/**/*.rs`):
    ```rust
    // SPDX-License-Identifier: MIT OR Apache-2.0
    // Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>
    ```
  - **Acceptance**: Every `.rs` file starts with the required SPDX and copyright notice.
  - **Files**: All `.rs` files across `src/` and `tests/`.
  - **Verify**: `tests/spdx_headers.rs` walks `src/` and `tests/` and asserts each `.rs` file begins with both required header lines.

### Phase 6 Checkpoint
```bash
cargo test
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Phase 7: Repository Hardening & Expansion Prep

**Goal**: Automate the quality gate on GitHub and clear leftover onboarding gaps before adding post-MVP protocols.

### Tasks
- [x] **Task 7.1: GitHub Actions CI Workflow**
  - **Description**: Add `.github/workflows/ci.yml` that runs `cargo fmt --check`, strict Clippy (`-D warnings`), `cargo test --all-features --locked`, and a minimal `--no-default-features --features http` check on pull requests and pushes to `master`.
  - **Acceptance**: Workflow is green on `master`; PR template quality gate matches CI steps.
  - **Files**: `.github/workflows/ci.yml`, `docs/SPEC.md` §17, this PLAN entry
  - **Verify**: Open a PR and confirm all CI jobs pass.

- [x] **Task 7.2: Wizard Plan Output (Non-Attack Path)**
  - **Description**: After guided prompts, print the equivalent CLI argv and exit without launching attacks. Remove the obsolete "execution engine not implemented" stub now that `engine::runner` is live.
  - **Acceptance**: `betterh wizard` / `--interactive` emits a copy-pasteable command line and states that no authentication attempts were sent.
  - **Files**: `src/main.rs`, `src/ui/wizard.rs`, `docs/SPEC.md`
  - **Verify**: Unit test covering the rendered ready message / argv formatting.

- [x] **Task 7.3: Project README**
  - **Description**: Add a root `README.md` covering purpose, authorized-use notice, build/quickstart, development quality gate, pointers to SPEC/PLAN/AGENTS, and dual MIT/Apache-2.0 licensing.
  - **Acceptance**: New contributors can build, dry-run, and orient from the README alone without reading the full SPEC first.
  - **Files**: `README.md`, `docs/SPEC.md` (project tree), this PLAN entry
  - **Verify**: Manual review that README examples match live CLI help / SPEC §11.

## Verification Matrix

| Area | Check | Command |
|---|---|---|
| **Formatting** | Rust standard format | `cargo fmt --check` |
| **Linting** | Pedantic + Perf with zero warnings | `cargo clippy --all-targets --all-features --locked -- -D warnings` |
| **Hermetic Tests** | All modules offline on `127.0.0.1:0` | `cargo test` |
| **Feature Gating** | Build minimal without default features | `cargo check --no-default-features --features http` |
| **Memory Test** | RSS $< 30\text{ MB}$ under large wordlists | Synthetic stream test in `engine::wordlist` |
| **Scope Guardrails**| Verify excluded IPs are omitted | Unit test in `engine::scope` |
| **Skip & Action Rules**| Verify `--exit-user` and `--on-found` hook | Unit test in `engine::actions` |
| **File Permissions**| Mode `0600` on output & checkpoints | Integration test inspecting `std::fs::metadata` permissions |
| **Interactive Keybindings**| Instant pause and concurrency adjustment | Key listener integration test in `engine::keys` |
| **Dry-Run Audit** | Accurate combination count and zero attacks | `betterh <service> <target> -L u.txt -P p.txt --dry-run` |
| **Completions** | Shell completions generation | `betterh completions bash` |
| **SPDX Headers** | Every `src/`/`tests/` `.rs` file has SPDX + copyright | `cargo test --test spdx_headers` |
| **CI** | GitHub Actions quality gate on PR/`master` | `.github/workflows/ci.yml` |
| **Safety** | Zero unwrap in library code | Grep check: `rg 'unwrap\(\)' src/` (excluding tests) |
