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
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|     Phase 7: Repository Hardening, CI & Expansion Prep            |
|  - 7.1 GitHub Actions CI quality gate workflow                    |
|  - 7.2 Wizard plan output (non-attack execution path)             |
|  - 7.3 README, licenses, changelog, and dependabot automation     |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|   Phase 8: Extended Protocols — SMTP, MySQL, and PostgreSQL       |
|  - 8.1 SMTP PLAIN/LOGIN & multiline parsing                       |
|  - 8.2 MySQL 4-byte framing & mysql_native_password               |
|  - 8.3 PostgreSQL 3.0 & MD5 challenge authentication              |
|  - 8.4 Extended protocol CLI wiring & integration tests           |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|           Phase 9: Modern Authentication Hardening                |
|  - 9.1 Shared TLS TransportStream helper (tokio-rustls)           |
|  - 9.2 SMTP STARTTLS (25/587) & implicit SMTPS (465)              |
|  - 9.3 MySQL caching_sha2_password (SHA-256 scramble & fast auth) |
|  - 9.4 PostgreSQL SCRAM-SHA-256 (RFC 5802 / RFC 7677 SASL)        |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|  Phase 10: Extended Infrastructure Protocols (Redis, IMAP, LDAP)  |
|  - 10.1 Redis RESP wire module (inline & ACL AUTH)                |
|  - 10.2 IMAP/IMAPS RFC 3501 tagged dialogue & STARTTLS            |
|  - 10.3 LDAP/LDAPS RFC 4511 ASN.1 BER Simple Bind                 |
|  - 10.4 Protocol CLI & Runner Wiring, Schemas & Tests             |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|     Phase 11: Enterprise Protocol Feasibility (SMB & RDP)         |
|  - 11.1 SMBv2/v3 & NTLMSSP Framing Architectural Feasibility      |
|  - 11.2 RDP / CredSSP / NLA Framing Architectural Feasibility     |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|   Phase 12: Model Context Protocol (MCP) Server Integration       |
|  - 12.1 MCP Stdio Transport & JSON-RPC 2.0 Framing                |
|  - 12.2 MCP Tools (audit_dryrun, audit_execute, validate_scope)   |
|  - 12.3 MCP Resources & Secure Session / Finding Reporting        |
|  - 12.4 CLI Subcommand (betterh mcp) & Hermetic Duplex Tests      |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|     Phase 13: SMB ProtocolModule (NTLMv2 Auth Track)              |
|  - 13.1 SmbModule wire path (NetBIOS / SMB2 NEGOTIATE+SETUP)      |
|  - 13.2 NTLMSSP Type 1/2/3 + NTLMv2 proof & NTSTATUS mapping       |
|  - 13.3 Minimal SPNEGO wrap, SOCKS5, timeout-friendly I/O         |
|  - 13.4 CLI smb:// wiring, hermetic mocks, README / CHANGELOG     |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|   Phase 14: Post-Expansion Refactoring & Deduplication            |
|  - 14.1 Protocol registry / CLI Service / build_module coalesce   |
|  - 14.2 Shared dial, timeout, and line/framed I/O helpers         |
|  - 14.3 Split oversized modules; retire clippy expect debt        |
|  - 14.4 Feasibility↔production share; SPEC/README sync            |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|   Phase 15: Intelligent Wordlist & Mutation Engine (O(1) RAM)     |
|  - 15.1 Hashcat rule interpreter (: c l u $X ^X sXY <N >N)        |
|  - 15.2 Enterprise & seasonal mangling (-e y, -e c, -e l, -e C)   |
|  - 15.3 Wordlist rule-file streaming pipeline (--rules <file>)    |
|  - 15.4 Combination estimator, CLI diagnostics & tests            |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|     Phase 16: RDP ProtocolModule (CredSSP / NLA)                  |
|  - 16.1 TPKT/X.224/RDP_NEG + TLS upgrade path                     |
|  - 16.2 CredSSP TSRequest + NTLMv2 NLA (reuse SMB crypto)         |
|  - 16.3 pubKeyAuth channel binding & TSCredentials encrypt        |
|  - 16.4 CLI rdp://, mocks, safety (no secret logs), docs          |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|   Phase 17: WinRM / HTTP(S) Negotiate (NTLM)                      |
|  - 17.1 WinRM HTTP(S) framing & auth probe                        |
|  - 17.2 Negotiate/NTLM HTTP auth (shared NTLMv2)                  |
|  - 17.3 TLS, --insecure, SOCKS5, Basic fallback policy            |
|  - 17.4 CLI winrm/winrms, hermetic mocks, docs                    |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|     Phase 18: MSSQL TDS Login Module                              |
|  - 18.1 TDS PRELOGIN / LOGIN7 framing                             |
|  - 18.2 SQL auth + TLS encrypt-login / Full encrypt               |
|  - 18.3 Error/token mapping, SOCKS5, timeouts                     |
|  - 18.4 CLI mssql://, mocks, docs                                 |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|     Phase 19: POP3 / POP3S Protocol Module                        |
|  - 19.1 POP3 dialogue USER/PASS (+ optional AUTH PLAIN)           |
|  - 19.2 STARTTLS (110) & implicit POP3S (995)                     |
|  - 19.3 Result mapping, SOCKS5, clean QUIT                        |
|  - 19.4 CLI pop3/pop3s, hermetic mocks, docs                      |
+-------------------------------------------------------------------+
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

- [x] **Task 7.4: Dual-License Text Files**
  - **Description**: Add `LICENSE-MIT` and `LICENSE-APACHE` at the repository root so the Cargo `MIT OR Apache-2.0` declaration is backed by the full license texts.
  - **Acceptance**: Both files are present; README License section points to them.
  - **Files**: `LICENSE-MIT`, `LICENSE-APACHE`, `README.md`, `docs/SPEC.md` (project tree), this PLAN entry
  - **Verify**: Files match the SPDX identifiers used in source headers.

- [x] **Task 7.5: Dependabot Configuration**
  - **Description**: Add `.github/dependabot.yml` for weekly `cargo` and `github-actions` updates so dependency and Actions bumps arrive as reviewable PRs.
  - **Acceptance**: Dependabot config is valid; ecosystems cover Cargo.lock and workflow Actions.
  - **Files**: `.github/dependabot.yml`, `docs/SPEC.md` §17, this PLAN entry
  - **Verify**: File review against GitHub Dependabot schema; CI remains green.

- [x] **Task 7.6: Keep a Changelog**
  - **Description**: Add root `CHANGELOG.md` (Keep a Changelog + SemVer) and require user-visible PRs to update it. Keep all notes under `[Unreleased]` until an actual version is tagged/released.
  - **Acceptance**: `CHANGELOG.md` exists with only an `[Unreleased]` section until the first release; README and SPEC project tree link to it; PLAN documents the maintenance rule.
  - **Files**: `CHANGELOG.md`, `README.md`, `docs/SPEC.md`, this PLAN entry
  - **Verify**: Manual review that merged history appears under `[Unreleased]` only (no premature version section).

---

## Phase 8: Extended Protocols — SMTP, MySQL, and PostgreSQL

**Goal**: Expand protocol coverage to enterprise database and mail services with native wire-level implementations, zero-allocation credential handling, robust error mapping, and hermetic in-process test harnesses.

### Tasks
- [x] **Task 8.1: SMTP Protocol Module & In-Process Test Harness**
  - **Description**: Implement `SmtpModule` (feature = `smtp`, dependency = `base64`) supporting:
    - Default ports: 25 (SMTP/STARTTLS), 587 (Submission), 465 (SMTPS).
    - Type-state connection management (`SmtpClient<Disconnected>` $\to$ `Connected` $\to$ `Greeted`).
    - Handshake greeting (`EHLO betterh.local`) and extension detection from `250-AUTH`.
    - Authentication mechanisms: `AUTH PLAIN` (preferred single-step) and `AUTH LOGIN` (two-step 334 challenge-response).
    - Resilient multiline reply parsing with bare LF and code-dash continuation tolerances.
    - SOCKS5 proxy support.
  - **Acceptance**: Correctly authenticates credentials against local mock SMTP dialogues and maps response codes (235 success, 535 failure, 421/454 rate-limited, 550 locked-out).
  - **Files**: `src/protocols/smtp.rs`, `src/protocols/mod.rs`
  - **Verify**: Mock tests in `src/protocols/smtp.rs` testing multiline banners, PLAIN and LOGIN paths, and error codes.

- [x] **Task 8.2: MySQL Protocol Module & In-Process Test Harness**
  - **Description**: Implement `MysqlModule` (feature = `mysql`, dependency = `sha1`) supporting:
    - Default port: 3306.
    - Native wire-level codec for MySQL 4-byte packet framing (3-byte length + sequence ID).
    - `HandshakeV10` packet decoder: protocol version, server version, connection ID, 8-byte salt part 1, capabilities, and salt part 2.
    - `HandshakeResponse41` encoder with utf8mb4 collation and `mysql_native_password` SHA-1 double-hash scramble:
      $$\text{scramble} = \text{SHA1}(\text{password}) \oplus \text{SHA1}(\text{salt} \parallel \text{SHA1}(\text{SHA1}(\text{password})))$$
    - Server response packet decoding: `0x00` OK, `0xFF` ERR. Error mapping: code 1045 (`ER_ACCESS_DENIED_ERROR`) to `AuthResult::Failure`, code 1129 (`ER_HOST_IS_BLOCKED`) and 1040 (`ER_CON_COUNT_ERROR`) to `AuthResult::RateLimited`.
    - SOCKS5 proxy support.
  - **Acceptance**: Authenticates against simulated MySQL handshake dialogues and accurately parses ERR packets without desynchronization.
  - **Files**: `src/protocols/mysql.rs`, `src/protocols/mod.rs`
  - **Verify**: Hermetic in-process mock server tests in `src/protocols/mysql.rs`.

- [x] **Task 8.3: PostgreSQL Protocol Module & In-Process Test Harness**
  - **Description**: Implement `PostgresModule` (feature = `postgres`, dependency = `md5`) supporting:
    - Default port: 5432.
    - Frontend/Backend Protocol 3.0 message framing (1-byte type + 4-byte big-endian length).
    - `StartupMessage` encoder: length prefix + version `196608` + `user` and `database` parameters.
    - Server `'R'` Authentication Request decoder:
      - Type 0: `AuthenticationOk` $\to$ `AuthResult::Success`.
      - Type 3: `AuthenticationCleartextPassword` $\to$ sends `'p'` password message.
      - Type 5: `AuthenticationMD5Password` with 4-byte salt $\to$ computes MD5 double-hash + salt scramble and sends `'p'` message.
    - Server `'E'` ErrorResponse decoder: parses SQLSTATE fields (`28P01` / `28000` to `AuthResult::Failure`, `53300` to `AuthResult::RateLimited`).
    - SOCKS5 proxy support.
  - **Acceptance**: Completes Frontend/Backend 3.0 handshake with cleartext and MD5 challenges against simulated mock listeners.
  - **Files**: `src/protocols/postgres.rs`, `src/protocols/mod.rs`
  - **Verify**: Hermetic in-process mock server tests in `src/protocols/postgres.rs`.

- [x] **Task 8.4: Extended Protocol Wiring, CLI Options & Integration Tests**
  - **Description**: Wire extended protocols into the application CLI and runner engine:
    - Add `Smtp`, `Smtps`, `Mysql`, `Postgres` to `Service` enum in `src/cli.rs`.
    - Register default ports and URL schemes (`smtp://`, `smtps://`, `mysql://`, `postgres://`, `postgresql://`).
    - Add `--database <NAME>` option to `ModuleOptions` in `src/cli.rs`.
    - Wire `build_module` in `src/engine/runner.rs` to construct the respective module instances.
    - Update `Cargo.toml` features (`smtp`, `mysql`, `postgres`, `default`).
    - Add end-to-end integration tests in `tests/cli_process.rs` verifying CLI validation and dry-run output for the new services.
  - **Acceptance**: `betterh smtp ...`, `betterh mysql ...`, and `betterh postgres ...` parse, validate, and execute cleanly.
  - **Files**: `src/cli.rs`, `src/engine/runner.rs`, `Cargo.toml`, `tests/cli_process.rs`
  - **Verify**: `cargo test`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, `cargo fmt --check`.

### Phase 8 Checkpoint

Completed (2026-09-26) on `feat/phase-8-extended-protocols`: Tasks 8.1–8.4 are implemented
(`SmtpModule` with PLAIN/LOGIN and RFC 5321 multiline parsing, `MysqlModule` with 4-byte wire framing,
`HandshakeV10` parsing and `mysql_native_password` scramble, `PostgresModule` with Frontend/Backend 3.0
and MD5 salted challenges, CLI `--database` option and URL parsing, and runner engine wiring).

Verification: 201 tests passed across unit and integration suites.
`cargo check --no-default-features --features <proto>` verifies clean independent compilation.
`cargo fmt --check` and `cargo clippy --all-targets --all-features --locked -- -D warnings` passed with 0 warnings.

```bash
cargo test protocols::smtp protocols::mysql protocols::postgres
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Phase 9: Modern Authentication Hardening

**Goal**: Upgrade existing database and mail protocol implementations to handle modern production cryptographic baselines: SMTP STARTTLS (25/587) and implicit SMTPS (465), MySQL 8+ `caching_sha2_password`, and PostgreSQL 10+ `SCRAM-SHA-256` (RFC 5802 / RFC 7677 SASL).

### Tasks
- [x] **Task 9.1: Shared TLS TransportStream Helper**
  - **Description**: Implement `TransportStream` enum (`src/protocols/tls.rs`) wrapping `Plain(TcpStream)` and `Tls(TlsStream<TcpStream>)`. Implement Tokio `AsyncRead`, `AsyncWrite`, and `Unpin`. Provide `wrap_tls(stream, host, insecure)` helper configuring Rustls client with SNI and optional certificate verification bypass for `--insecure`.
  - **Acceptance**: Seamlessly upgrades plain streams to TLS without data loss. Reusable across SMTP, MySQL, IMAP, LDAP.
  - **Files**: `src/protocols/tls.rs`, `src/protocols/mod.rs`
  - **Verify**: Unit tests verifying TLS wrap and plain pass-through.

- [x] **Task 9.2: SMTP STARTTLS & Implicit SMTPS Upgrade**
  - **Description**: Add STARTTLS detection from `250-STARTTLS` in `EHLO` response on ports 25 and 587. Send `STARTTLS\r\n`, verify `220` response, upgrade via `TransportStream`, and repeat `EHLO`. For port 465 (implicit TLS) or `target.ssl`, wrap stream immediately on connect before reading initial 220 banner. Respect `--insecure`.
  - **Acceptance**: Successfully performs STARTTLS upgrade and authenticates against mock SMTP server.
  - **Files**: `src/protocols/smtp.rs`
  - **Verify**: Mock tests for STARTTLS handshake, implicit SMTPS, and rejection codes.

- [x] **Task 9.3: MySQL `caching_sha2_password` Authentication**
  - **Description**: Add `caching_sha2_password` auth plugin handling using `sha2`. Compute SHA-256 double-hash scramble:
    $$\text{scramble} = \text{SHA256}(\text{password}) \oplus \text{SHA256}(\text{SHA256}(\text{SHA256}(\text{password})) \parallel \text{salt})$$
    Handle `0x00` OK (fast cache hit), `0x01, 0x03` (cache miss requiring full authentication over TLS or RSA-OAEP public key encryption), and `0xFF` ERR.
  - **Acceptance**: Authenticates with `caching_sha2_password` against both fast-cache and full-auth mock handshakes.
  - **Files**: `src/protocols/mysql.rs`
  - **Verify**: Hermetic mock tests for `caching_sha2_password` in `src/protocols/mysql.rs`.

- [x] **Task 9.4: PostgreSQL `SCRAM-SHA-256` SASL Authentication**
  - **Description**: Implement RFC 5802 / RFC 7677 `SCRAM-SHA-256` SASL mechanism using `sha2`, `hmac`, `pbkdf2`. Intercept `'R'` type 10 (`AuthenticationSASL`), exchange client nonce via `SASLInitialResponse`, parse server nonce, salt, and iteration count from `'R'` type 11 (`AuthenticationSASLContinue`), derive keys via PBKDF2 HMAC-SHA256, compute ClientProof, send `SASLResponse`, and verify `'R'` type 12 (`AuthenticationSASLFinal`) / type 0.
  - **Acceptance**: Completes SASL handshake against mock PostgreSQL listener; accurately computes ClientProof.
  - **Files**: `src/protocols/postgres.rs`
  - **Verify**: Hermetic mock tests for `SCRAM-SHA-256` in `src/protocols/postgres.rs`.

### Phase 9 Checkpoint

```bash
cargo test protocols::smtp protocols::mysql protocols::postgres
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Phase 10: Extended Infrastructure Protocols — Redis, IMAP, and LDAP

**Goal**: Implement native wire-level authentication testing for ubiquitous enterprise infrastructure services: Redis (RESP inline & ACL), IMAP/IMAPS (RFC 3501 tagged dialogue & STARTTLS), and LDAP/LDAPS (RFC 4511 Simple Bind via ASN.1 BER).

### Tasks
- [x] **Task 10.1: Redis Protocol Module & Mock Harness**
  - **Description**: Implement `RedisModule` (feature = `redis`) supporting RESP protocol on port 6379. Pre-flight probe with `PING\r\n`. Authenticate via `AUTH <password>\r\n` (inline) or `AUTH <username> <password>\r\n` (ACL). Map `+OK` to Success, `-WRONGPASS` / `-ERR invalid` to Failure, and connection errors / max clients to RateLimited(5s). SOCKS5 proxy support.
  - **Acceptance**: Authenticates against mock RESP server for both inline and ACL auth.
  - **Files**: `src/protocols/redis.rs`, `src/protocols/mod.rs`
  - **Verify**: Hermetic mock tests in `src/protocols/redis.rs`.

- [x] **Task 10.2: IMAP/IMAPS Protocol Module & Mock Harness**
  - **Description**: Implement `ImapModule` (feature = `imap`, dependency = `tokio-rustls`) supporting ports 143 (plain/STARTTLS) and 993 (implicit IMAPS). Parse greeting `* OK`, negotiate STARTTLS via `TransportStream` on 143 or wrap on 993, send tagged `A001 LOGIN "<username>" "<password>"\r\n`. Map `OK` to Success, `NO` to Failure, `* BYE` to RateLimited(5s). Send clean `LOGOUT`. SOCKS5 proxy support.
  - **Acceptance**: Authenticates against mock IMAP server for plain, STARTTLS, and IMAPS.
  - **Files**: `src/protocols/imap.rs`, `src/protocols/mod.rs`
  - **Verify**: Hermetic mock tests in `src/protocols/imap.rs`.

- [x] **Task 10.3: LDAP/LDAPS Protocol Module & Mock Harness**
  - **Description**: Implement `LdapModule` (feature = `ldap`, dependency = `tokio-rustls`) supporting ports 389 (plain) and 636 (implicit LDAPS). Encode ASN.1 BER `BindRequest` with MessageID, LDAP version 3, Name/DN, and Simple Password. Decode `BindResponse`: map resultCode 0 to Success, 49 to Failure, 53 to LockedOut, 51 to RateLimited. SOCKS5 proxy support.
  - **Acceptance**: Completes Simple Bind against mock LDAP server and handles result codes correctly.
  - **Files**: `src/protocols/ldap.rs`, `src/protocols/mod.rs`
  - **Verify**: Hermetic mock tests in `src/protocols/ldap.rs`.

- [x] **Task 10.4: Extended Protocol Wiring, CLI Options & Integration Tests**
  - **Description**: Wire new protocols into CLI and runner:
    - Add `Redis`, `Imap`, `Imaps`, `Ldap`, `Ldaps` to `Service` enum in `src/cli.rs`.
    - Register default ports and URL schemes (`redis://`, `imap://`, `imaps://`, `ldap://`, `ldaps://`).
    - Wire `build_module` in `src/engine/runner.rs`.
    - Update `Cargo.toml` features (`redis`, `imap`, `ldap`, `default`).
    - Add integration tests in `tests/cli_process.rs` verifying CLI validation and dry-run output.
  - **Acceptance**: CLI accepts, validates, and dry-runs all new protocols.
  - **Files**: `src/cli.rs`, `src/engine/runner.rs`, `Cargo.toml`, `tests/cli_process.rs`
  - **Verify**: `cargo test`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, `cargo fmt --check`.

### Phase 10 Checkpoint

```bash
cargo test protocols::redis protocols::imap protocols::ldap
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Phase 11: Enterprise Protocol Feasibility (SMB & RDP Track)

**Goal**: Conduct architectural feasibility analysis, packet framing prototypes, and credential exchange validation for SMBv2/v3 (SPNEGO/NTLMSSP) and RDP (X.224, CredSSP, NLA) without heavy external C libraries.

### Tasks
- [x] **Task 11.1: SMBv2/v3 Protocol & NTLMSSP Framing Architectural Feasibility**
  - **Description**: Conduct architectural study and write pure Rust wire prototype for SMBv2/v3 NEGOTIATE dialogue, SPNEGO encapsulation, and NTLMSSP Type 1/2/3 authentication. Document wire structures, state machines, and benchmark against zero-allocation guidelines.
  - **Acceptance**: Feasibility document and test harness evaluating native SMB authentication without external C dependencies.
  - **Files**: `docs/SPEC.md` §5.2.D, `docs/PLAN.md`, `src/feasibility/smb.rs`, `Cargo.toml` (`feasibility-smb`)

- [x] **Task 11.2: RDP / CredSSP / NLA Framing Architectural Feasibility**
  - **Description**: Conduct architectural study and write pure Rust wire prototype for RDP X.224 connection request, TLS handshake, CredSSP framing, and NLA authentication token exchange.
  - **Acceptance**: Feasibility document and test harness evaluating native RDP authentication without external C dependencies.
  - **Files**: `docs/SPEC.md` §5.2.D, `docs/PLAN.md`, `src/feasibility/rdp.rs`, `Cargo.toml` (`feasibility-rdp`)

### Phase 11 Checkpoint

```bash
cargo check --all-targets --all-features --locked
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
```

---

## Phase 12: Model Context Protocol (MCP) Server Integration

**Goal**: Expose Betterh capabilities as a standards-compliant Model Context Protocol (MCP) server over `stdio` using JSON-RPC 2.0, enabling AI coding agents (Antigravity, Claude, Cursor) and automated orchestration pipelines to run safe pre-flight audits, dry-runs, scope validations, and targeted authentication testing with strict guardrails.

### Tasks
- [x] **Task 12.1: MCP Protocol Framing & JSON-RPC 2.0 Transport**
  - **Description**: Implement MCP stdio transport (`src/mcp/transport.rs`) over Tokio async stdin/stdout using newline-delimited JSON-RPC 2.0 messages. Support MCP handshake: `initialize` request with client/server capabilities, protocol version negotiation (`2024-11-05`), `notifications/initialized`, `ping`, and clean cancellation. Feature-gated via Cargo feature `mcp`. Zero new external dependencies (uses existing `tokio`, `serde`, `serde_json`).
  - **Acceptance**: Bidirectional async framing passes unit tests; cleanly serializes and deserializes JSON-RPC 2.0 requests, responses, and errors.
  - **Files**: `src/mcp/transport.rs`, `src/mcp/mod.rs`
  - **Verify**: Unit tests verifying framing, serialization, and lifecycle methods.

- [x] **Task 12.2: MCP Tool Definitions & Execution Engine Dispatch**
  - **Description**: Implement `tools/list` and `tools/call` in `src/mcp/tools.rs`:
    - `audit_dryrun`: Validates targets and options, runs non-intrusive reachability and canary probe, returns candidate counts and timing estimates without sending attacks.
    - `audit_execute`: Run controlled authentication testing or password spray with rate limiting and timeout bounds.
    - `validate_scope`: Test IP/CIDR against exclusion lists and detect public internet targets requiring confirmation.
    - `list_protocols`: Return supported protocols, default ports, and feature states.
    - `session_status`: Inspect active or checkpointed audit session.
    Route tool invocations safely into Betterh core (`engine::runner`, `engine::dryrun`, `engine::scope`), respecting all scope guardrails and exit rules.
  - **Acceptance**: Exposes valid JSON Schema for all tools; tool calls execute correctly and return structured JSON results.
  - **Files**: `src/mcp/tools.rs`, `src/mcp/mod.rs`
  - **Verify**: Unit tests for schema validity and simulated tool execution.

- [ ] **Task 12.3: MCP Resources & Secure Session / Finding Reporting**
  - **Description**: Implement `resources/list` and `resources/read` in `src/mcp/resources.rs`:
    - `betterh://protocols`: Static registry metadata of compiled protocol capabilities.
    - `betterh://reports/{hash}`: Finding logs from completed or checkpointed audits.
    - `betterh://session/current`: Live metrics, attempts count, and rate information.
    Enforce POSIX mode `0600` access and path traversal protections when resolving report resources.
  - **Acceptance**: Clients can query resource lists and read report content; invalid URIs return standard MCP error codes (-32602).
  - **Files**: `src/mcp/resources.rs`, `src/mcp/mod.rs`
  - **Verify**: Unit tests for resource discovery, valid URI reads, and path traversal rejection.

- [ ] **Task 12.4: CLI Integration (`betterh mcp`), Subcommand & Hermetic Mock Tests**
  - **Description**: Wire MCP server into CLI and application lifecycle:
    - Add `mcp` subcommand (`betterh mcp [--stdio]`) in `src/cli.rs`.
    - Wire `main.rs` dispatch to initialize the MCP server loop with cooperative cancellation via `CancellationToken` on `SIGINT`.
    - Implement hermetic in-process integration tests (`tests/mcp_server.rs`) using `tokio::io::duplex` simulating an MCP client connecting, exchanging `initialize`, listing tools, executing `audit_dryrun`, and shutting down cleanly.
    - Update `Cargo.toml` features (`mcp`, included in `default`).
  - **Acceptance**: `betterh mcp` launches stdio server; duplex tests pass all JSON-RPC 2.0 and MCP tool interactions.
  - **Files**: `src/cli.rs`, `src/main.rs`, `src/mcp/mod.rs`, `Cargo.toml`, `tests/mcp_server.rs`
  - **Verify**: `cargo test --test mcp_server`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, `cargo fmt --check`.

### Phase 12 Checkpoint

```bash
cargo test mcp::
cargo test --test mcp_server
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Phase 13: SMB ProtocolModule (NTLMv2 Authentication Track)

**Goal**: Promote the Phase 11.1 SMBv2/NTLMSSP feasibility prototype into a production `ProtocolModule` that authenticates against SMB over TCP/445 using `NEGOTIATE` → `SESSION_SETUP` with SPNEGO/NTLMSSP **NTLMv2**, without C bindings (`libsmbclient` / Samba FFI). Auth auditor only — no file/share I/O, Kerberos, or guest-as-primary path. Full SMB 3.1.1 preauth/signing/sealing productization stays out of scope unless required to observe auth success.

### Tasks
- [ ] **Task 13.1: SmbModule Wire Path (NetBIOS / SMB2 NEGOTIATE + SESSION_SETUP)**
  - **Description**: Implement `SmbModule` (feature = `smb`) with NetBIOS session framing, SMB2 header encode/decode, and a type-state dialogue `Disconnected → Negotiated → SessionChallenged → Authenticated`. Promote/reuse codecs from `src/feasibility/smb.rs` into `src/protocols/smb.rs` without leaving duplicate crypto paths (`feasibility-smb` remains an offline codec harness or thin re-export).
  - **Acceptance**: Hermetic encode/decode of NEGOTIATE and SESSION_SETUP request/response frames; illegal state transitions are unrepresentable or rejected.
  - **Files**: `src/protocols/smb.rs`, `src/protocols/mod.rs`, `src/feasibility/smb.rs`, `Cargo.toml` (`smb`)
  - **Verify**: Unit tests in `src/protocols/smb.rs` for framing round-trips.

- [ ] **Task 13.2: NTLMSSP Type 1/2/3 + NTLMv2 Proof & NTSTATUS Mapping**
  - **Description**: Complete the auth path: Type 1 negotiate → Type 2 challenge (server challenge + AV_PAIRs) → Type 3 authenticate with NTLMv2 NT proof. Run MD4/HMAC-MD5 in `tokio::task::spawn_blocking`. Map NTSTATUS to `AuthResult` (`STATUS_SUCCESS` → Success; logon failure codes → Failure; lockout / account restrictions → LockedOut where mappable; busy / insufficient resources → RateLimited).
  - **Acceptance**: Authenticates against a hermetic mock SMB peer for success and failure credentials; crypto matches Phase 11.1 vectors.
  - **Files**: `src/protocols/smb.rs`
  - **Verify**: Hermetic mock listener tests in `src/protocols/smb.rs`.

- [ ] **Task 13.3: Minimal SPNEGO Wrap, SOCKS5 & Timeout-Friendly I/O**
  - **Description**: Wrap NTLMSSP tokens in minimal SPNEGO (or send raw NTLMSSP when the peer accepts it after negotiate). Dial via existing SOCKS5 helper. Bound all reads/writes with the module timeout; keep I/O cooperative with cancellation (no blocking sleeps; no std Mutex across await).
  - **Acceptance**: Mock tests cover SPNEGO-or-raw NTLMSSP SESSION_SETUP; SOCKS5 dial path compiles and is exercised where other modules do.
  - **Files**: `src/protocols/smb.rs`, `src/protocols/socks.rs` (reuse only)
  - **Verify**: Unit/mock tests for security buffer handling and timeout errors → `ProtocolError`.

- [ ] **Task 13.4: CLI Wiring (`smb://`), Hermetic Mocks, README & CHANGELOG**
  - **Description**: Wire production SMB into CLI and runner:
    - Add `Smb` to `Service` enum in `src/cli.rs` (scheme `smb://`, default port 445).
    - Register module in `src/protocols/mod.rs` and `build_module` in `src/engine/runner.rs`.
    - Update `Cargo.toml` features (`smb` with `md4`/`hmac`/`md5-hmac`; include in `default` when ready).
    - Hermetic mock tests plus CLI dry-run coverage in `tests/cli_process.rs`.
    - Update README service list/capabilities and CHANGELOG; keep `feasibility-smb` for offline codec tests without duplicated NTLMv2 implementations.
  - **Acceptance**: `betterh smb ...` / `smb://` parse, validate, and dry-run; `cargo test protocols::smb` and clippy/fmt clean.
  - **Files**: `src/cli.rs`, `src/engine/runner.rs`, `Cargo.toml`, `tests/cli_process.rs`, `README.md`, `CHANGELOG.md`
  - **Verify**: `cargo test protocols::smb`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, `cargo fmt --check`.

### Phase 13 Checkpoint

```bash
cargo test protocols::smb
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Phase 14: Post-Expansion Refactoring & Deduplication

**Goal**: After the protocol expansion (Phases 8–13), systematically remove duplication and structural debt from many near-parallel modules—without speculative abstractions. Prefer extracting only helpers used ≥2 times; keep Apollo/Tokio rules (borrow over clone, no locks across await, bounded spawning). Phase 6 covered the early core; Phase 14 targets post-SMTP/DB/infra/enterprise growth. May run interleaved with Phase 12/13 implementation as modules land.

### Tasks
- [ ] **Task 14.1: Protocol Registry, CLI `Service`, and `build_module` Coalesce**
  - **Description**: Collapse repeated service↔module wiring across `src/cli.rs` (`Service` enum, scheme parse, default ports, SSL/insecure gates) and `src/engine/runner.rs` (`build_module`, feature gates). Introduce a single declarative registry (const table or small match helpers) so adding a protocol touches one place. Remove or shrink `#[expect(clippy::too_many_lines)]` on `build_module` by splitting construction, not by silencing.
  - **Acceptance**: New protocol registration is mechanical (one registry entry + module file); `build_module` / service parse stay under Clippy line limits without broad allows; all existing CLI dry-run and scheme tests pass.
  - **Files**: `src/cli.rs`, `src/engine/runner.rs`, `src/protocols/mod.rs`
  - **Verify**: `cargo test --test cli_process`, `cargo clippy --all-targets --all-features --locked -- -D warnings`

- [ ] **Task 14.2: Shared Dial, Timeout, and Line/Framed I/O Helpers**
  - **Description**: Deduplicate connect/proxy/timeout patterns shared by SMTP, IMAP, LDAP, Redis, MySQL, PostgreSQL (and SMB once present): SOCKS-or-direct dial, `tokio::time::timeout` wrappers, CRLF line readers, and “read until predicate” loops. Extend or complement `socks.rs` / `tls.rs` with minimal helpers in `src/protocols/` (e.g. `io.rs`)—no new dependency, no god-object session type.
  - **Acceptance**: At least the repeated dial+timeout and line-read paths call shared helpers; protocol behavior unchanged (hermetic mocks still green); no std blocking I/O introduced.
  - **Files**: `src/protocols/io.rs` (new, if needed), `src/protocols/socks.rs`, `src/protocols/tls.rs`, `src/protocols/{smtp,imap,ldap,redis,mysql,postgres}.rs`
  - **Verify**: `cargo test protocols::`, `cargo clippy --all-targets --all-features --locked -- -D warnings`

- [ ] **Task 14.3: Split Oversized Modules & Retire Clippy Expect Debt**
  - **Description**: Split the largest protocol/CLI files where cohesion allows (notably `mysql.rs`, `postgres.rs`, and dense sections of `cli.rs`) into focused private submodules (framing vs auth vs tests) without changing public API. Audit `#[expect(clippy::…)]` / documented allows; remove obsolete suppressions; keep only expects with a rationale comment that still holds.
  - **Acceptance**: No module that can be cleanly split remains >~800 LOC without a documented reason; clippy `-D warnings` clean with fewer expects than before Phase 14; public `ProtocolModule` surface unchanged.
  - **Files**: `src/protocols/mysql.rs`, `src/protocols/postgres.rs`, `src/cli.rs`, related `mod.rs` wiring
  - **Verify**: `cargo test`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, `cargo fmt --check`

- [ ] **Task 14.4: Feasibility↔Production Share Paths & Docs Sync**
  - **Description**: Ensure Phase 11 feasibility codecs (`src/feasibility/smb.rs`, later RDP) and production modules (`src/protocols/smb.rs`) do not duplicate NTLMv2/wire crypto—shared helpers or thin re-exports only. Sync `docs/SPEC.md` directory tree / module boundaries and README capability wording with the refactored layout; CHANGELOG entry for user-visible structural notes only if CLI/docs change.
  - **Acceptance**: One implementation of each crypto/framing primitive; SPEC tree matches `src/`; `feasibility-*` tests still pass alongside `protocols::smb` when both features are enabled.
  - **Files**: `src/feasibility/*`, `src/protocols/smb.rs` (when present), `docs/SPEC.md`, `README.md`, `CHANGELOG.md`
  - **Verify**: `cargo test --all-features --locked`, `cargo fmt --check`

### Phase 14 Checkpoint

```bash
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Phase 15: Intelligent Wordlist & Mutation Engine ($O(1)$ Streaming)

**Goal**: Implement an intelligent, high-throughput, memory-bounded ($O(1)$ RAM) password mutation engine supporting Hashcat-compatible rule files (`--rules <file>`), enterprise seasonal and year password pattern generation (`-e y`, `-e c`), and leet-speak / case transformations (`-e l`, `-e C`) while maintaining strict $< 30\text{ MB}$ RSS memory usage.

### Tasks
- [x] **Task 15.1: Rule Mutation Engine & Hashcat Interpreter (`src/engine/mutations.rs`)**
  - **Description**: Implement a streaming Hashcat/John-compatible rule interpreter supporting core operators: `:`, `l`, `u`, `c`, `C`, `t`, `r`, `d`, `f`, `$X`, `^X`, `sXY`, `[`, `]`, `{`, `}`, `<N`, `>N`. Parse rule files line-by-line, rejecting invalid syntax before attack execution. Provide `RuleSet` with zero-allocation in-place string transforms where possible.
  - **Acceptance**: Correct transformation of test vectors matching Hashcat canonical outputs; unit tests for all operators and rejection rules.
  - **Files**: `src/engine/mutations.rs`, `src/engine/mod.rs`
  - **Verify**: `cargo test engine::mutations`

- [x] **Task 15.2: Enterprise & Seasonal Mangling Rules (`-e y`, `-e c`, `-e l`, `-e C`)**
  - **Description**: Extend `ManglingRule` enum in `src/cli.rs` and candidate generator in `src/engine/mutations.rs`. Add current/previous year appending (`-e y`), enterprise seasonal patterns (`-e c`: `Winter2026!`, `Sommer2026#`), leet substitutions (`-e l`), and initial capitalization (`-e C`). Integrate with optional `--rule-year <YEAR>` parameter (defaults to current system year in UTC). Wire into `mangled()` user prelude stream.
  - **Acceptance**: Correctly generates expected seasonal and year candidate strings in deterministic order.
  - **Files**: `src/cli.rs`, `src/engine/wordlist.rs`, `src/engine/mutations.rs`
  - **Verify**: Unit tests in `src/engine/wordlist.rs` asserting candidate output sequences.

- [x] **Task 15.3: Wordlist Rule-File Streaming Pipeline (`--rules <file>`)**
  - **Description**: Add `--rules <file>` flag to CLI. Integrate `RuleSet` into the asynchronous wordlist streaming pipeline in `src/engine/wordlist.rs`. Apply rules lazily to each password streamed from files or stdin (`-P -`).
  - **Acceptance**: Wordlist stream yields mutated passwords in $O(1)$ memory; RSS memory remains strictly $< 30\text{ MB}$ under a 1,000,000-candidate test run.
  - **Files**: `src/cli.rs`, `src/engine/wordlist.rs`, `src/engine/runner.rs`
  - **Verify**: Memory flatline test in `tests/wordlist_stream.rs`.

- [x] **Task 15.4: Combination Estimator, CLI Diagnostics & Integration Tests**
  - **Description**: Update combination counter in `src/engine/dryrun.rs` to compute accurate combination counts ($Users \times (Passwords \times Rules + Mangling)$). Add end-to-end integration tests in `tests/cli_process.rs` verifying CLI validation, dry-run tables, and execution.
  - **Acceptance**: `betterh --dry-run` accurately predicts combination count with active `--rules` and `-e` flags; reject invalid rule files with helpful diagnostics.
  - **Files**: `src/engine/dryrun.rs`, `tests/cli_process.rs`
  - **Verify**: `cargo test --test cli_process`, `cargo test --test wordlist_stream`.

### Phase 15 Checkpoint

Completed (2026-09-26) on `feat/phase-15-mutation-engine`: Tasks 15.1–15.4 are implemented
(`RuleSet` Hashcat interpreter supporting `:`, `l`, `u`, `c`, `C`, `t`, `r`, `d`, `f`, `$X`, `^X`, `sXY`, `[`, `]`, `{`, `}`, `<N`, `>N`,
enterprise seasonal patterns `-e c`, year patterns `-e y` with `--rule-year`, leet mutations `-e l`, capitalize `-e C`,
$O(1)$ streaming password mutation pipeline via `credentials_with_mutations`, dry-run combination estimator,
fail-fast admission control for rule syntax errors, and isolated-process memory test verifying $< 30\text{ MB}$ RSS across 1,000,000 candidates).

Verification: 254 tests passed across all unit, integration, and streaming memory suites.
`cargo fmt --check` and `cargo clippy --all-targets --all-features --locked -- -D warnings` passed with 0 warnings.

```bash
cargo test engine::mutations engine::wordlist engine::dryrun
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Phase 16: RDP ProtocolModule (CredSSP / NLA)

**Goal**: Promote the Phase 11.2 RDP/CredSSP feasibility prototype into a production `ProtocolModule` that authenticates via NLA (CredSSP + NTLMv2) on TCP/3389, reusing shared NTLMv2 helpers from the SMB track. Auth-only — no remote desktop graphics, clipboard, or drive redirection. Security bar: TLS via existing `TransportStream`/rustls; credentials never logged; `--insecure` only bypasses cert verification; crypto in `spawn_blocking`; hermetic mocks only in CI.

**Depends on**: Phase 13 SMB NTLMv2 helpers (or equivalent shared crypto from Phase 14.4); Phase 9 `TransportStream`.

### Tasks
- [ ] **Task 16.1: TPKT / X.224 / `RDP_NEG` Wire Path & TLS Upgrade**
  - **Description**: Implement `RdpModule` (feature = `rdp`) with TPKT + X.224 Connection Request (cookie + `RDP_NEG_REQ` requesting `PROTOCOL_SSL|HYBRID|HYBRID_EX`), parse `RDP_NEG_RSP`/`FAILURE`, then upgrade the same TCP socket with TLS when Hybrid/SSL is selected. Promote framing from `src/feasibility/rdp.rs` into `src/protocols/rdp.rs` without duplicating codecs. NLA-only: reject or hard-error legacy `PROTOCOL_RDP` without TLS for auth audits.
  - **Acceptance**: Hermetic mock completes negotiate → TLS-ready state; clear error if peer forces non-NLA-only legacy security.
  - **Files**: `src/protocols/rdp.rs`, `src/protocols/mod.rs`, `src/feasibility/rdp.rs`, `Cargo.toml` (`rdp`)
  - **Verify**: Unit/mock tests for TPKT/X.224/`RDP_NEG` round-trips and TLS wrap.

- [ ] **Task 16.2: CredSSP `TSRequest` + NTLMv2 NLA**
  - **Description**: On the TLS stream, exchange CredSSP `TSRequest` negoTokens carrying SPNEGO/NTLMSSP Type 1→2→3 using shared NTLMv2 proofs. Map auth outcomes to `AuthResult`. Timeouts on every read/write; cooperative cancellation; SOCKS5 dial via existing helper.
  - **Acceptance**: Mock CredSSP peer: success and wrong-password paths; no password/NT hash in `tracing`/`Display` of errors.
  - **Files**: `src/protocols/rdp.rs`, shared NTLM helpers
  - **Verify**: Hermetic mock listener tests in `src/protocols/rdp.rs`.

- [ ] **Task 16.3: `pubKeyAuth` Channel Binding & `TSCredentials` Encryption**
  - **Description**: Implement CredSSP server public-key binding (`pubKeyAuth`) and encrypted `TSCredentials` as required for real Windows NLA peers. Fail closed on binding mismatch. Document Extended CredSSP (`PROTOCOL_HYBRID_EX`) nonce handling support level; Kerberos mech remains out of scope.
  - **Acceptance**: Mock or recorded-vector tests cover binding success/failure; wrong binding → Failure (not Success); clippy/fmt clean.
  - **Files**: `src/protocols/rdp.rs`, `docs/SPEC.md` §D.2 production notes
  - **Verify**: Dedicated unit tests for binding and credential blob encode/decode.

- [ ] **Task 16.4: CLI Wiring (`rdp://`), Safety Review, Docs**
  - **Description**: Add `Service::Rdp` (port 3389, `rdp://`); register module; CLI dry-run; README/CHANGELOG. Safety checklist: no secret logging, `--insecure` gated, explicit decision whether `rdp` is in Cargo `default`.
  - **Acceptance**: `betterh rdp ...` parses/validates/dry-runs; `cargo test protocols::rdp` green; SPEC tree lists `protocols/rdp.rs`.
  - **Files**: `src/cli.rs`, `src/engine/runner.rs`, `Cargo.toml`, `tests/cli_process.rs`, `README.md`, `CHANGELOG.md`, `docs/SPEC.md`
  - **Verify**: `cargo test protocols::rdp`, clippy `-D warnings`, `cargo fmt --check`.

### Phase 16 Checkpoint

```bash
cargo test protocols::rdp
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Phase 17: WinRM / HTTP(S) Negotiate (NTLM)

**Goal**: Add WinRM authentication auditing over HTTP(S) using Negotiate/NTLMSSP (NTLMv2), reusing shared NTLM crypto and existing HTTP/TLS stacks where practical. Auth-only (no command execution / shell). Security bar: HTTPS by default for `winrms`; cleartext HTTP only for explicit `winrm`; never log Authorization headers or NTLM blobs; `--insecure` only for TLS verify bypass; **no silent Basic fallback**.

**Depends on**: Shared NTLMv2 helpers (Phase 13/14); `http` + `tls` features.

### Tasks
- [ ] **Task 17.1: WinRM HTTP(S) Framing & Auth Probe**
  - **Description**: Implement `WinrmModule` (feature = `winrm`) targeting typical endpoints (e.g. `/wsman`). Probe with an unauthenticated request; detect `WWW-Authenticate: Negotiate` / `NTLM`. Ports: 5985 (HTTP), 5986 (HTTPS).
  - **Acceptance**: Hermetic mock returns 401 with Negotiate; module selects Negotiate path; missing Negotiate → clear `ProtocolError` (no silent Basic).
  - **Files**: `src/protocols/winrm.rs`, `src/protocols/mod.rs`, `Cargo.toml`
  - **Verify**: Mock HTTP server tests for probe behaviour.

- [ ] **Task 17.2: HTTP Negotiate / NTLM Type 1–3 Exchange**
  - **Description**: Implement multi-leg HTTP auth: send Type 1, parse Type 2 from `WWW-Authenticate`, send Type 3 with NTLMv2 via shared helpers (`spawn_blocking`). Map HTTP success vs auth failure (and WinRM SOAP faults that mean auth failure) to `AuthResult`.
  - **Acceptance**: Success and failure credentials against mock; NTLM tokens never written to logs at info/debug without redaction.
  - **Files**: `src/protocols/winrm.rs`, shared NTLM helpers
  - **Verify**: Hermetic multi-request mock tests.

- [ ] **Task 17.3: TLS, `--insecure`, SOCKS5 & Basic Policy**
  - **Description**: Wire HTTPS via rustls/`TransportStream` or reqwest rustls path consistently with other modules. SOCKS5 support. Policy: do not fall back to Basic unless an explicit future opt-in flag is added (default off — document in SPEC).
  - **Acceptance**: `winrms` + `--insecure` works in mock TLS; Basic fallback absent by default; timeouts enforced.
  - **Files**: `src/protocols/winrm.rs`, `docs/SPEC.md`
  - **Verify**: TLS and proxy unit/mock coverage aligned with HTTP module patterns.

- [ ] **Task 17.4: CLI Wiring (`winrm` / `winrms`), Mocks, Docs**
  - **Description**: `Service::Winrm` / `Winrms`, schemes `winrm://` / `winrms://`, runner registry, CLI tests, README/CHANGELOG.
  - **Acceptance**: Dry-run and validation green; feature-gated build works `--features winrm`.
  - **Files**: `src/cli.rs`, `src/engine/runner.rs`, `Cargo.toml`, `tests/cli_process.rs`, `README.md`, `CHANGELOG.md`
  - **Verify**: `cargo test protocols::winrm`, clippy, fmt.

### Phase 17 Checkpoint

```bash
cargo test protocols::winrm
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Phase 18: MSSQL TDS Login Module

**Goal**: Native TDS authentication module for Microsoft SQL Server (SQL authentication LOGIN7), with TLS encrypt-login / full encryption as required by modern servers. Auth-only — no query execution. Security bar: respect encrypt flags; no password in logs; `--insecure` only for cert verify; never send LOGIN7 secret material in clear when the server requires encryption.

**Depends on**: Phase 9 TLS helper; optional registry cleanup from Phase 14.1.

### Tasks
- [ ] **Task 18.1: TDS PRELOGIN & Packet Framing**
  - **Description**: Implement `MssqlModule` (feature = `mssql`) with TDS packet header (type, status, length, SPID, packet ID), PRELOGIN option tokens (VERSION, ENCRYPTION, INSTOPT, THREADID, MARS). Default port 1433.
  - **Acceptance**: Hermetic mock PRELOGIN round-trip; clear errors on truncated/invalid packets.
  - **Files**: `src/protocols/mssql.rs`, `src/protocols/mod.rs`, `Cargo.toml`
  - **Verify**: Framing unit tests in `src/protocols/mssql.rs`.

- [ ] **Task 18.2: LOGIN7 SQL Auth + TLS Encrypt Modes**
  - **Description**: Build LOGIN7 for username/password SQL auth. Honour PRELOGIN encryption: encrypt-login and full encrypt via `TransportStream`. Reject sending plaintext LOGIN7 when server demands encryption. Windows/SSPI/Integrated auth and Azure AD out of scope (document in SPEC).
  - **Acceptance**: Mock success/failure login; encrypt-required path never sends password in clear; optional `--database` if aligned with MySQL/Postgres CLI.
  - **Files**: `src/protocols/mssql.rs`, `src/protocols/tls.rs`
  - **Verify**: Hermetic mock tests for encrypt-login and failure tokens.

- [ ] **Task 18.3: Token/Error Mapping, SOCKS5, Timeouts**
  - **Description**: Map LOGINACK → Success; error tokens (e.g. 18456 login failed) → Failure; lockout-like messages → LockedOut when identifiable; resource limits → RateLimited. SOCKS5 dial; bounded timeouts; no unwrap in paths.
  - **Acceptance**: Mapped results covered by mocks; proxy path compiles like other DB modules.
  - **Files**: `src/protocols/mssql.rs`
  - **Verify**: Mock error-token tests.

- [ ] **Task 18.4: CLI Wiring (`mssql://`), Docs**
  - **Description**: `Service::Mssql`, scheme `mssql://`, port 1433, runner, CLI tests, README/CHANGELOG/SPEC tree.
  - **Acceptance**: Dry-run works; `cargo test protocols::mssql` green.
  - **Files**: `src/cli.rs`, `src/engine/runner.rs`, `Cargo.toml`, `tests/cli_process.rs`, `README.md`, `CHANGELOG.md`, `docs/SPEC.md`
  - **Verify**: clippy `-D warnings`, fmt.

### Phase 18 Checkpoint

```bash
cargo test protocols::mssql
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Phase 19: POP3 / POP3S Protocol Module

**Goal**: POP3 authentication module mirroring IMAP patterns: `USER`/`PASS` (and optional `AUTH PLAIN` if advertised), STARTTLS on 110, implicit TLS on 995 (`pop3s`). Security bar: STARTTLS before PASS when offered/required; `--insecure` only for cert verify; no credentials in logs; clean `QUIT`.

**Depends on**: Phase 9 `TransportStream`; Phase 14.2 line I/O helpers if landed (otherwise local CRLF reader, then dedupe in 14.2).

### Tasks
- [ ] **Task 19.1: POP3 Dialogue (`USER` / `PASS`, Optional `AUTH PLAIN`)**
  - **Description**: Implement `Pop3Module` (feature = `pop3`). Parse `+OK`/`-ERR` greeting; `USER`/`PASS`; if `CAPA` lists SASL `PLAIN`, allow `AUTH PLAIN` as alternate path (default: USER/PASS first — document).
  - **Acceptance**: Hermetic mock success/failure; unknown capa ignored safely.
  - **Files**: `src/protocols/pop3.rs`, `src/protocols/mod.rs`, `Cargo.toml`
  - **Verify**: Mock tests in `src/protocols/pop3.rs`.

- [ ] **Task 19.2: STARTTLS (110) & Implicit POP3S (995)**
  - **Description**: On port 110, if `STLS` in capa (or policy always-try), issue `STLS`, upgrade via `TransportStream`, then auth. On 995/`pop3s`/`ssl`, wrap TLS before greeting as required (document order). Honour `--insecure`.
  - **Acceptance**: Plain, STARTTLS, and POP3S mocks pass; do not send plaintext PASS when TLS was required and STLS failed.
  - **Files**: `src/protocols/pop3.rs`, `src/protocols/tls.rs`
  - **Verify**: Three-path hermetic tests.

- [ ] **Task 19.3: Result Mapping, SOCKS5, `QUIT`**
  - **Description**: `+OK` after PASS → Success; `-ERR` auth fail → Failure; temporary errors → RateLimited where applicable. Always attempt `QUIT`. SOCKS5 support.
  - **Acceptance**: Mapping tests + quit-on-success/failure; timeouts enforced.
  - **Files**: `src/protocols/pop3.rs`
  - **Verify**: Unit/mock tests.

- [ ] **Task 19.4: CLI Wiring (`pop3` / `pop3s`), Docs**
  - **Description**: Services/schemes `pop3://` / `pop3s://`, ports 110/995, runner, CLI tests, README/CHANGELOG/SPEC.
  - **Acceptance**: Dry-run green; feature `pop3` builds cleanly.
  - **Files**: `src/cli.rs`, `src/engine/runner.rs`, `Cargo.toml`, `tests/cli_process.rs`, `README.md`, `CHANGELOG.md`, `docs/SPEC.md`
  - **Verify**: `cargo test protocols::pop3`, clippy, fmt.

### Phase 19 Checkpoint

```bash
cargo test protocols::pop3
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

>>>>>>> origin/master
## Verification Matrix

| Area | Check | Command |
|---|---|---|
| **Formatting** | Rust standard format | `cargo fmt --check` |
| **Linting** | Pedantic + Perf with zero warnings | `cargo clippy --all-targets --all-features --locked -- -D warnings` |
| **Hermetic Tests** | All modules offline on `127.0.0.1:0` | `cargo test` |
| **Feature Gating** | Build minimal without default features | `cargo check --no-default-features --features http` |
| **Protocol Gating** | Build individual protocols | `cargo check --no-default-features --features <proto>` |
| **MCP Server** | Hermetic duplex JSON-RPC 2.0 tests | `cargo test --test mcp_server` |
| **SMB Auth Module** | Hermetic NetBIOS/SMB2/NTLMv2 mocks | `cargo test protocols::smb` |
| **Mutation Engine**| Rule mutation & seasonal candidate tests | `cargo test engine::mutations` |
| **RDP Auth Module** | Hermetic CredSSP/NLA mocks | `cargo test protocols::rdp` |
| **WinRM Auth Module** | Hermetic HTTP Negotiate mocks | `cargo test protocols::winrm` |
| **MSSQL Auth Module** | Hermetic TDS LOGIN7 mocks | `cargo test protocols::mssql` |
| **POP3 Auth Module** | Hermetic POP3/POP3S mocks | `cargo test protocols::pop3` |
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
