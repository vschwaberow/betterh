# Technical Specification: Betterh (v0.1.0 MVP)

## 1. Objective

**Betterh** is a modern, memory-safe, high-concurrency network authentication testing and brute-force tool written in Rust.

### Core Goals
- **Memory Safety & Reliability**: Eliminate the memory corruption, buffer overflow, and segfault risks present in legacy C tools.
- **Asynchronous Concurrency**: Built on the Tokio runtime for high-throughput, non-blocking network I/O with fine-grained rate limiting.
- **Dual Attack Modes**: Support both classical vertical brute-forcing and horizontal password spraying across multiple hosts/accounts to evade account lockouts.
- **Multi-Target, CIDR & Scope Guardrails**: Native processing of single targets, target files (`-M targets.txt`), CIDR subnet expansion (`192.168.1.0/24`), and strict exclusion lists (`--exclude`, `--exclude-file`).
- **Proxy & Evasion Subsystem**: SOCKS5 and HTTP proxy support with round-robin list rotation, configurable request delays, and jitter.
- **Zero-Allocation Wordlist & Pipe Streaming**: $O(1)$ memory consumption regardless of wordlist size, with first-class UNIX pipe (`-P -`) integration.
- **Pre-Flight Canary Probing**: Automatic false-positive and catch-all detection before launching attacks.
- **Adaptive Network Engine**: Automatic detection and handling of network tarpits, rate limits (e.g., HTTP 429), and lockouts with configurable backoff.
- **Granular Success Controls & Skip Rules**: Smart auto-skip per user (`--exit-user`, default), per host (`--exit-host`), or immediate global stop (`--exit-first`).
- **Safe Post-Finding Actions**: Shell-injection-safe command execution (`--on-found "<cmd>"` via environment variables) and terminal bell (`--bell`).
- **Session Checkpointing**: Interruptible and resumable audit sessions written with strict file permissions (`0600`).
- **Feature-Gated Protocol Modularity**: Compile only what you need via Cargo features (`ftp`, `http`, `ssh`).
- **Hermetic Testing Strategy**: 100% in-process mock server testing (`127.0.0.1:0`) without Docker or internet dependencies.
- **Ergonomic CLI & Configuration**:
  - URL-First & Positional Hybrid syntax (`betterh ssh://user@host:port` or `betterh ssh host:port`).
  - Clean, dedicated long flags (e.g., `--body`, `--fail-string`, `-H`) instead of opaque module option strings.
  - Hierarchical configuration: CLI Flags > `BETTERH_*` Env Vars > `~/.config/betterh/config.toml` (100% Zero-Config capable).
  - Built-in shell completions generator (`betterh completions <shell>`) and manpage generator.
- **Modern User Experience (UX) & Interface (UI)**:
  - Adaptive hybrid rendering: Pinned live dashboard with sticky success feed for terminals; clean unbuffered JSONL for pipes/CI.
  - Interactive runtime keybindings (`Space` status snapshot, `p` pause/resume, `+`/`-` dynamic threads, `c` checkpoint, `q` exit).
  - Pre-flight `--dry-run` combination audit and optional interactive wizard (`betterh wizard`).
  - Actionable Cargo-style diagnostics with remediation tips.

---

## 2. Design Principles (Karpathy Guidelines Alignment)

1. **Think Before Coding**: Clarify protocol handshakes, error states, and edge cases prior to implementation.
2. **Simplicity First**: Minimal viable code. No speculative plugin architectures or dynamic scripting layers in MVP; pure Rust traits compiled directly into the binary.
3. **Surgical Changes**: Every module is self-contained. Changes to one protocol or engine component must not bleed into adjacent code.
4. **Goal-Driven Execution**: Every protocol module and engine feature must be backed by isolated unit or integration tests against local mock services.

---

## 3. Tech Stack, Dependencies & Feature Flags

- **Language**: Rust (Edition 2024 / latest stable)
- **Async Runtime**: `tokio` (features = `["full"]`)
- **Concurrency Utilities**: `tokio-util` (features = `["rt"]`), `futures`
- **Target URL Parsing & Canary IDs**: `url`, `percent-encoding`, `uuid` (feature `v4`).
- **Networking, CIDR & Proxies**: `ipnet`, `tokio-socks`
- **CLI Framework**: `clap` (features = `["derive", "env"]`), `clap_complete`, `clap_mangen`
- **Configuration & Directories**: `directories`, `toml`
- **Terminal UI & Progress**: `indicatif`, `console`
- **Interactive TUI & Wizard**: `crossterm` (raw mode & `event-stream` key events), `inquire` (prompts)
- **Serialization & Formats**: `serde`, `serde_json`
- **Error Handling**: `thiserror` (domain errors), `anyhow` (application level)
- **Logging & Tracing**: `tracing`, `tracing-subscriber`

### Protocol Feature Flags
```toml
[features]
default = ["ftp", "http", "ssh"]
ftp = []
http = ["dep:reqwest"]
ssh = ["dep:russh"]
```

### Dev Dependencies (Hermetic Testing)
- `tokio-test = "0.4"`
- `wiremock = "0.6"`

---

## 4. Architectural Overview

```
                                  +---------------------------+
                                  |       CLI / Config        |
                                  | (clap, targets, wizard)   |
                                  +-------------+-------------+
                                                |
                                                v
                                  +---------------------------+
                                  | Target & Scope Expander   |
                                  | (CIDR, File -M, Excludes) |
                                  +-------------+-------------+
                                                |
                                                v
                                  +---------------------------+
                                  |    Pre-Flight Canary      |
                                  |  (False-Positive Probe)   |
                                  +-------------+-------------+
                                                |
                                                v
                                  +---------------------------+
                                  |       Attack Engine       | <---+ (Runtime Key Listener)
                                  |  (Brute-Force vs Spray)   |     | (p, +, -, Space, q)
                                  +------+-------------+------+     |
                                         |             |            |
           +-----------------------------+             +------------+----------------+
           |                                                                         |
           v                                                                         v
+-----------------------+                                                 +-----------------------+
|  Streaming Wordlist   |                                                 |  Proxy & Evasion Hub  |
|  (O(1) BufReader / -) |                                                 |  (SOCKS5/HTTP/Jitter) |
+-----------------------+                                                 +-----------------------+
           |                                                                         |
           +-----------------------------+             +-----------------------------+
                                         |             |
                                         v             v
                                  +---------------------------+
                                  |      ProtocolModule       |
                                  |          (Trait)          |
                                  +------+-------------+------+
                                         |
                +------------------------+------------------------+
                |                        |                        |
                v                        v                        v
       +------------------+     +------------------+     +------------------+
       |    SshModule     |     |    HttpModule    |     |    FtpModule     |
       +------------------+     +------------------+     +------------------+
                |                        |                        |
                +------------------------+------------------------+
                                         |
                                         v
                           +---------------------------+
                           |  Action & Success Engine  |
                           | (--exit-*, --on-found)    |
                           +-------------+-------------+
                                         |
                                         v
                           +---------------------------+
                           |    Adaptive UI / Stream   |
                           | (Live Dashboard / JSONL)  |
                           +---------------------------+
```

---

## 5. Core Trait: `ProtocolModule`

All protocol handlers implement a unified asynchronous trait.

```rust
use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub ssl: bool,
    pub path: Option<String>,
    /// Optional resolved address pinned after DNS/scope checks (Phase 3.5).
    /// When set, workers connect to this IP without a second DNS lookup while
    /// preserving `host` for SNI / Host headers.
    pub ip: Option<std::net::IpAddr>,
}

`Target::dial_addr()` returns the pinned `ip:port` (or `host:port`) for TCP dials.
`Target::host_port()` always formats the logical hostname for display and skip keys.


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub username: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Success,
    Failure,
    LockedOut,
    RateLimited(Duration),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryStatus {
    Normal,
    WildcardDetected(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("Connection failed: {0}")]
    ConnectionError(String),
    #[error("Timeout while communicating with target")]
    Timeout,
    #[error("Protocol handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("Proxy error: {0}")]
    ProxyError(String),
    #[error("Internal module error: {0}")]
    Internal(String),
}

#[async_trait]
pub trait ProtocolModule: Send + Sync {
    /// Service identifier (e.g. "ssh", "http-post", "ftp")
    fn name(&self) -> &'static str;

    /// Default TCP/UDP port for this service
    fn default_port(&self) -> u16;

    /// Optional protocol pre-flight check or banner grab
    async fn probe(&self, target: &Target) -> Result<(), ProtocolError> {
        Ok(())
    }

    /// Pre-flight Canary test with intentionally invalid credentials
    /// to detect catch-all or wildcard false-positive responses.
    async fn canary_probe(&self, target: &Target) -> Result<CanaryStatus, ProtocolError> {
        let dummy = Credential {
            username: format!("__canary_{}__", uuid::Uuid::new_v4().simple()),
            password: Some(format!("__canary_{}__", uuid::Uuid::new_v4().simple())),
        };
        match self.authenticate(target, &dummy, Duration::from_secs(5)).await? {
            AuthResult::Success => Ok(CanaryStatus::WildcardDetected(
                "Target authenticated random canary credentials; catch-all suspected".into()
            )),
            AuthResult::Failure => Ok(CanaryStatus::Normal),
            _ => Err(ProtocolError::Internal("Canary probe was inconclusive".into())),
        }
    }

    /// Single attempt to authenticate against the target
    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout: Duration,
    ) -> Result<AuthResult, ProtocolError>;
}
```

---

### 5.1 Foundation Contracts

- Domain types support Serde serialization and equality. `Target` also supports hashing and displays its host, port, and optional path. IPv6 addresses use brackets.
- `Credential` debug output redacts the password. Explicit serialization preserves it for checkpoint and reporting use.
- The mock uses a deterministic success percentage (0–100), configurable latency, an optional rate-limit response, and a catch-all mode. Rate limits take precedence over success. Latency must respect the authentication timeout.
- The default canary accepts only `Failure` as evidence of normal authentication. Lockouts, rate limits, and module error results produce an inconclusive-probe error; transport errors propagate.

## 6. Idiomatic Rust Architecture & Patterns

Betterh follows the Apollo GraphQL Rust Best Practices Handbook and Tokio concurrency patterns:

### 6.1 Type-State Pattern for Protocol Connections
Illegal state transitions (e.g., attempting authentication on an unestablished TCP stream) are prevented at compile time rather than checked via runtime flags.

```rust
use std::marker::PhantomData;
use tokio::net::TcpStream;

pub struct Disconnected;
pub struct Connected;
pub struct Handshaked;

pub struct ProtocolClient<State> {
    stream: Option<TcpStream>,
    _state: PhantomData<State>,
}

impl ProtocolClient<Disconnected> {
    pub fn new() -> Self {
        Self { stream: None, _state: PhantomData }
    }

    pub async fn connect(self, addr: &str) -> Result<ProtocolClient<Connected>, std::io::Error> {
        let stream = TcpStream::connect(addr).await?;
        Ok(ProtocolClient {
            stream: Some(stream),
            _state: PhantomData,
        })
    }
}

impl ProtocolClient<Connected> {
    pub async fn handshake(mut self) -> Result<ProtocolClient<Handshaked>, std::io::Error> {
        // Perform protocol-specific banner negotiation
        Ok(ProtocolClient {
            stream: self.stream.take(),
            _state: PhantomData,
        })
    }
}
```

### 6.2 Zero-Allocation Wordlist Pipeline ($O(1)$ Memory)
- **Wordlist Streaming**: Uses `tokio::io::AsyncBufReadExt::lines` to stream credentials lazily.
- **Pipe-First**: When `-P -` or `-L -` is passed, credentials are read from `tokio::io::stdin()` without buffering.
- **Borrowed Slices & Cow**: Credentials within the inner pipeline are referenced as `&str` or `Cow<'_, str>` to prevent memory allocation during validation, regex matching, and payload encoding.
- **Memory Guarantee**: The RSS memory footprint remains $< 30\text{ MB}$ even with a 50GB wordlist.

### 6.3 Tokio Concurrency & Actor Architecture
- **Worker Management**: Workers are coordinated via `tokio::task::JoinSet<()>`.
- **Bounded Spawning**: Task execution concurrency is governed by a `tokio::sync::Semaphore`. No unbounded `tokio::spawn` loops.
- **Message Passing**: Credential batches are transferred between the wordlist streaming generator and worker tasks using bounded `tokio::sync::mpsc` channels.
- **Cooperative Cancellation**: An atomic `CancellationToken` is monitored in all loops and select blocks to guarantee prompt, clean shutdown on `SIGINT` with complete checkpoint serialization.

### 6.4 Secret & File Permission Hardening
- **Console Display**: Successful logins are displayed clearly in real time on the console (`[SUCCESS] host:port - user:pass`).
- **POSIX 0600 Permissions**: New `--output` files request mode `0600` at creation (the process umask can further restrict it). Report creation atomically rejects any existing output entry, including regular files, hard links, and symbolic links with existing or missing targets. It must not truncate existing data or change its permissions. The operator must choose an unused output path; `--force` does not bypass this rule. Checkpoint files retain their atomic replacement workflow and mode `0600`.

---

## 7. Attack Engine, Strategies & Evasion

### 7.1 Attack Strategies: Brute-Force vs. Password Spraying
1. **Vertical Brute-Force (Default)**:
   - For each target and user, iterate through all passwords sequentially or concurrently.
   - Ideal for single accounts or targets without aggressive lockout thresholds.
2. **Horizontal Password Spraying (`--mode spray`)**:
   - For a given candidate password $P_i$, test $P_i$ across *all* target users/hosts.
   - Once all targets are tested with $P_i$, the engine sleeps for a user-configured cooldown period (`--spray-cooldown 15m`) before advancing to $P_{i+1}$.
   - Prevents triggering account lockout thresholds (e.g., 3 failed attempts in 15 minutes).

### 7.2 Target Expansion & Scope Guardrails
- **Single Target**: `192.168.1.50:22` or `http://target.local:8080/login`.
- **Target File (`-M <file>`)**: Line-delimited file containing IPs, hostnames, or URLs.
- **CIDR Expansion**: Subnets such as `192.168.1.0/24` parsed via `ipnet` and streamed as individual `Target` instances without pre-allocating large IP vectors.
- **Scope Guardrails (Exclusions)**:
  - `--exclude <IP/CIDR>` (can repeat): Excludes specific IP addresses or subnets from testing.
  - `--exclude-file <file>`: Reads exclusion targets from a file.
  - **Public Net Warning**: When scanning target ranges containing public IP addresses alongside private subnets, Betterh prompts for confirmation unless `--force` is supplied.

#### Target and Scope Streaming Contract (Tasks 3.1–3.2)

- Target expansion returns a lazy stream of `Target` values. CIDRs use host semantics: IPv4 prefixes shorter than /31 omit network and broadcast addresses; /31 and /32 retain all addresses. IPv6 includes the entire prefix. Host bits in CIDR input are normalized.
- Target files accept hostnames, IPs, host:port pairs, CIDRs, and URLs. One invocation selects one protocol family; HTTP and HTTPS may coexist. Embedded credentials in target-file URLs are rejected: use the invocation's credential options. Ports, TLS, and HTTP paths/queries are preserved.
- Target and exclusion files reuse the bounded UTF-8 wordlist reader. Blank lines and surrounding whitespace are ignored; full-line `#` comments are allowed. Invalid entries terminate processing, without including their contents in errors. Files must be regular files; `-M -` and `--exclude-file -` are not stdin inputs.
- Exclusions combine CLI IP/CIDR values with an optional exclusion file. Only exclusion networks are retained in memory. A matching excluded prefix is skipped as a range, including for IPv6; targets are never collected into a vector. Duplicates retain input order.
- Literal IPs are filtered during expansion. IPv4-mapped IPv6 literals also match IPv4 exclusions; exclusions inside the mapped IPv6 /96 also match their IPv4 equivalents. General IPv6 prefixes remain separate from IPv4. Hostnames remain unresolved to preserve the name required for HTTP and TLS. `Scope::classify` explicitly reports that DNS checking is still required; the Phase 3.5 coordinator must check each resolved socket address, store it in `Target.ip`, and connect to that pinned address without resolving again while preserving `host` for SNI/Host.
- Scope classification distinguishes exclusions, local addresses, addresses requiring confirmation, and unresolved names. Local means private/loopback/link-local IPv4 or loopback/unique-local/link-local IPv6. Other addresses conservatively require confirmation. The Phase 3.5 coordinator will enforce confirmation (or `--force`) before network work; expansion itself performs no DNS lookup or connection.
- The canary gate calls the protocol's `canary_probe` under an overall timeout and cancellation token. Normal results pass. Wildcard results fail unless forced; forced wildcard results remain explicitly marked as wildcard and produce a warning. Force never suppresses transport errors, inconclusive results, cancellation, or timeouts. Canary results cannot become credential findings.

### 7.3 Proxy Routing & Traffic Shaping Subsystem
- **Single Proxy (`--proxy <url>`)**: Supports `socks5://127.0.0.1:9050` (Tor) or `http://127.0.0.1:8080` (Burp/ZAP).
- **Proxy Rotation (`--proxy-list <file>`)**: Loads a list of proxies and distributes requests in a thread-safe round-robin fashion. If a proxy drops connection, the worker rotates to the next healthy proxy.
- **Jitter & Delays**: Configurable inter-request delay (`--delay 200ms`) and randomized variance (`--jitter 50ms`) to avoid server request spikes and distribute network load evenly.

### 7.4 Adaptive Rate Limiting & Backoff
- Each target maintains a **leaky-bucket** limiter (`src/engine/adaptive.rs`) with a configurable baseline request rate (default derived from concurrency).
- Tokens refill continuously at the current rate; `acquire` waits until a token is available and any active backoff window has elapsed. Waiting never drops or cancels queued work.
- On `AuthResult::RateLimited(duration)`, the limiter:
  1. Enters a backoff window of at least `duration` (server hint), and
  2. Halves the current refill rate (floored at a small minimum) so subsequent attempts slow down.
- On consecutive transport timeouts, the limiter similarly reduces rate and applies an exponential backoff window (`base * 2^(n-1)`, capped).
- Successful (or ordinary failure) responses gradually restore the rate toward the baseline (additive recovery). Lockouts are reported to skip rules and do not by themselves change the bucket rate.

### 7.5 Wordlist Mangling Rules
- Built-in flag modifiers:
  - `-e n`: Test empty/null password.
  - `-e s`: Test password identical to username.
  - `-e r`: Test password as reversed username.
- Unix Pipe: Combine with external tools (`hashcat --stdout -r rules.txt wordlist.txt | betterh ssh 10.0.0.1 -u admin -P -`).

#### Phase 2 Streaming Contract

- `engine::wordlist` exposes a bounded asynchronous line reader and a `Stream<Item = Result<Credential, WordlistError>>`. Files open only when the stream is polled; consumers control backpressure. No producer tasks or input-sized collections are used.
- Sources are literal values, regular UTF-8 files, or stdin (`-`). Lists trim surrounding Unicode whitespace and skip blank lines, including CRLF-only lines. Literal CLI values remain unchanged. A final line without a newline is accepted. Invalid UTF-8 and I/O failures stop the stream with a typed error.
- Each physical input line is limited to 64 KiB, excluding its LF delimiter but including any CR. Longer lines fail before an input-sized allocation. Memory is bounded by the line limit, fixed I/O buffers, and the current credential, not by input length. Owned `Credential` strings require bounded per-item allocations; whole lists are never duplicated.
- File products iterate users first, then passwords. The password file is reopened for each user. With password stdin and a user file, passwords are the outer loop and the user file is reopened for each password. Two stdin sources are rejected before reading. Input files must remain unchanged during iteration; named pipes are not replayable file sources and must be passed through stdin.
- Mangling rules run in fixed `n`, `s`, `r` order before the supplied passwords for each user. Repeated rule flags are collapsed. `n` yields `Some("")`; `r` reverses Unicode scalar values. With password stdin, rules run once over the user source before consuming the password stream. No supplied password source is required when rules are present.
- Combo input splits at the first colon; remaining colons belong to the password. Both fields are trimmed; an empty password is valid, while an empty username or missing colon is an error. Rules run before each combo row's original credential. Repeated input rows and candidates are retained; global deduplication would require input-sized state.
- Generator errors are terminal. Dropping the stream releases its resources without background producer tasks. [Tokio stdin](https://docs.rs/tokio/latest/tokio/io/struct.Stdin.html) itself uses a blocking OS read internally, so a pending stdin read cannot guarantee immediate process shutdown; cancellable terminal input belongs to the runtime-input work in Phase 3.
- Phase 2 supplies the reader and generator library APIs. Dispatch to protocol workers remains Phase 3 work.

### 7.6 Pre-Flight Canary & False-Positive Prevention
- Prior to launching worker tasks, `betterh` issues a canary probe with a randomized pseudo-unique credential pair.
- If the service responds with `AuthResult::Success`, the engine warns the operator that the target is a catch-all or authentication bypass simulator and requires `--force` to proceed.
- If an account reports `AuthResult::LockedOut`, the engine marks that user as quarantined, avoiding wasted attempts.

### 7.7 Granular Success & Termination Rules
- `--exit-user` (*Default behavior*): As soon as a valid password is found for user $U$, all remaining password candidates for $U$ are cancelled and the engine advances to the next user.
- `--exit-host`: As soon as any valid account is found on host $H$, all remaining attempts against $H$ are stopped, and the engine advances to the next host.
- `--exit-first`: Immediately terminates the entire attack run upon discovering the first valid credential across all targets.

### 7.8 Safe Post-Finding Actions & Alerting
- `--on-found "<command>"`: Spawns an asynchronous command via `tokio::process::Command` upon each verified discovery. Values are passed strictly via environment variables (never shell string interpolation) to completely eliminate shell injection vulnerabilities:
  - `BETTERH_TARGET`: Target host and port.
  - `BETTERH_SERVICE`: Protocol identifier (e.g. `ssh`, `http`).
  - `BETTERH_USERNAME`: Successfully authenticated username.
  - `BETTERH_PASSWORD`: Discovered password.
- `--bell`: Emits an ASCII terminal bell (`\x07`) upon each successful discovery.

### 7.9 Network Transport Resilience & Socket Hygiene

#### A. Ephemeral Port Preservation & TCP Handshake Reuse
- High-concurrency operations can rapidly deplete the host operating system's ephemeral port range if discrete sockets are repeatedly opened and torn down, leaving tens of thousands of sockets in the kernel `TIME_WAIT` state (persisting 60–120 seconds).
- Protocols supporting persistent transport connections (e.g., HTTP/1.1 Keep-Alive) must reuse open connections across authentication attempts where protocol state permits, rather than issuing a raw TCP handshake per attempt.
- For protocols requiring discrete connections per attempt (e.g., SSH, FTP), connection rates are strictly governed by the concurrency semaphore (`-t`), and connections are cleanly terminated to avoid local port exhaustion (`EADDRNOTAVAIL`).

#### B. DNS Stampede Prevention & Socket Address Pinning
- When targets are specified as hostnames, DNS resolution occurs exactly once during target admission and scope validation.
- The resolved `SocketAddr` is checked against scope exclusion filters and pinned for all subsequent connection attempts to that target.
- Workers connect directly to the pinned IP address while retaining the original hostname for TLS SNI negotiation, certificate validation, and HTTP `Host` headers.
- Re-resolving hostnames per credential attempt is prohibited to avoid local resolver saturation and network DNS stampedes.

#### C. Tolerant Parsing of Non-Standard Server Responses
- Production network targets often deviate from strict RFC specifications (e.g., legacy embedded systems, custom banners, non-standard CRLF/LF line endings, or missing header fields).
- Protocol parsers must adopt a resilient, permissive consumption model:
  - **FTP**: Parse multi-line banners (RFC 959 code-dash continuations) tolerantly; accept both CRLF and bare LF delimiters; gracefully consume preliminary informational messages before authenticating.
  - **HTTP**: Leniently handle non-standard status lines, absent `Content-Length` headers on rejection responses, and HTTP/1.0 fallbacks.
  - **SSH**: Support broad negotiation across standard cryptographic algorithms without disconnecting on unexpected identification string formatting.
  - **Transport Resilience**: Distinguish transient transport resets from explicit protocol rejections; never drop connection state on transient TCP resets without attempting recovery.

---

## 8. User Experience (UX) & Terminal User Interface (UI)

### 8.1 Adaptive Hybrid Rendering
Betterh inspects whether `stdout` is an interactive TTY (`std::io::stdout().is_terminal()`):
- **Interactive TTY**:
  - Live progress dashboard via `indicatif`: Multi-bar displaying overall progress, rate (req/s), active target count, current concurrency level, and estimated time to completion (ETA).
  - **Pinned Success Feed**: Discovered credentials (`[SUCCESS] host:port - user:pass`) are emitted via a pinned log section above the progress bar so they are immediately visible and never lost in scrolling terminal output.
  - **Status & Throttling Alerts**: Live warnings when a target is rate-limiting (`[WARN] Target 192.168.1.100 returned 429; throttling back for 4.2s...`).
- **Piped / Non-TTY / CI (`--format jsonl` or piped output)**:
  - Automatic suppression of all ANSI escape sequences, spinner animations, and progress bars.
  - Emits clean, unbuffered, line-delimited JSON objects to `stdout` for downstream parsing (`jq`, logs, SIEM).

### 8.2 Interactive Runtime Keybindings
While an attack is in progress, a background Tokio task monitors terminal keystrokes using `crossterm::event::EventStream`:
- `Space` or `s`: **Live Status Snapshot** — Prints an immediate one-line summary (attempts completed, current req/s, active targets, found count, elapsed time).
- `p` or `P`: **Pause / Resume** — Temporarily suspends all worker tasks; pressing again resumes execution instantly.
- `+` / `-`: **Dynamic Concurrency Control** — Dynamically increments or decrements the active task semaphore capacity by 1 (or 5 with Shift) without restarting the attack.
- `c` or `C`: **Checkpoint Now** — Immediately persists current session state to `.betterh-session-<hash>.json`.
- `q` or `Ctrl+C`: **Graceful Exit** — Aborts worker tasks, saves the checkpoint atomically, and prints the final report.

### 8.3 Session Checkpoint Schema
Checkpoint files are JSON documents named `.betterh-session-<hash>.json` (mode `0600`), written atomically (temp file + rename). The document contains:
- `version` (u32, currently `1`)
- `hash` (string session identity)
- `service` (string)
- `completed` (array of `{ target, username, password }` already attempted)
- `findings` (array of successful `{ target, username, password }`)
- `next_index` (u64 cursor into the credential stream when resumable)

`--resume <path>` loads this document and skips `completed` entries before continuing.

### 8.4 Pre-Attack & Onboarding Experience
- **`--dry-run` Pre-Flight Audit**:
  - Validates targets and performs a non-intrusive connectivity probe.
  - Calculates total credential candidate combinations ($Users \times Passwords$).
  - Estimates total duration based on concurrency and network latency.
  - Prints a clean summary table without transmitting authentication attempts.
  - `--output <path>` writes one JSONL audit event in every display format, including the default text mode. Text mode also prints the summary table unless `--quiet` is set. Quiet mode does not suppress an explicitly requested report file. Output files are created only after a successful audit and follow the file protection rules in §6.4. A file creation error fails the command before printing a success summary.
- **Interactive Setup Wizard (`betterh wizard` or `--interactive`)**:
  - For operators who prefer guided setup, prompts interactively for: Service, Target(s), User/Password files, Concurrency, and Proxy settings via `inquire`.
  - On completion, prints the equivalent CLI argv for the operator to copy or re-run, then exits without launching attacks (wizard remains a non-attack path).
- **Empty Invocation (`betterh`)**:
  - When invoked without arguments, displays a rich, color-highlighted quickstart help with real-world examples and common commands rather than an unhelpful error.

### 8.5 Actionable Diagnostics & Error Reporting
Errors are formatted following modern Rust compiler conventions (problem statement, context, and actionable remediation hint):
```
error: connection to 192.168.1.50:22 failed
  --> target: 192.168.1.50:22 (SSH)
  = cause: Connection refused (os error 111)
  = tip: Verify that the SSH service is running and not blocked by a local firewall.
         Try: nc -zv 192.168.1.50 22
```
```
error: TLS handshake failed for https://10.0.0.5:8443/login
  --> target: https://10.0.0.5:8443
  = cause: Invalid certificate authority (self-signed certificate)
  = tip: Use `--insecure` or `-k` to bypass TLS certificate validation for testing.
```

---

## 9. CLI Grammar & Configuration System

### 9.1 URL-First & Positional Hybrid Syntax
Betterh automatically parses both target URLs and positional service/target arguments:
```bash
# URL syntax: Extracts service (ssh), target (192.168.1.10), port (2222), and embedded user (admin)
betterh ssh://admin@192.168.1.10:2222 -P passwords.txt

# Positional syntax: Equivalent invocation
betterh ssh 192.168.1.10:2222 -u admin -P passwords.txt

# Web target with full path
betterh https://target.local:8443/api/v1/auth -m post-form -L users.txt -P passwords.txt
```

### 9.2 Ergonomic Module-Specific Flags
Module parameters use clear, dedicated long flags:

| Flag | Service | Description | Example |
|---|---|---|---|
| `--body <str>` | HTTP | POST payload template | `--body "user={USER}&pass={PASS}"` |
| `--fail-string <str>` | HTTP | Substring indicating failed login | `--fail-string "Bad username/password"` |
| `--success-string <str>`| HTTP | Substring indicating successful login| `--success-string "Welcome back"` |
| `--header <str>` / `-H` | HTTP | Custom HTTP header (can repeat) | `-H "X-CSRF-Token: abcd"` |
| `--cookie <str>` | HTTP | Custom cookie string | `--cookie "session=abc123"` |
| `--http-method <str>` | HTTP | Request method (`GET`, `POST`, `PUT`) | `--http-method POST` |
| `--ssh-key <path>` | SSH | Private key file for key authentication | `--ssh-key ~/.ssh/id_ed25519` |
| `--ftp-passive` | FTP | Force passive mode (PASV) | `--ftp-passive` |

### 9.3 Hierarchical Configuration
Betterh applies configuration in the following order of precedence:
1. **CLI Flags**: Highest priority (overrides all defaults).
2. **Environment Variables**: Prefixed with `BETTERH_` (e.g., `BETTERH_CONCURRENCY=32`, `BETTERH_PROXY=socks5://127.0.0.1:9050`).
3. **Configuration File**: Evaluated from `./betterh.toml` or `~/.config/betterh/config.toml` (or custom path via `--config <path>`).

```toml
# Example ~/.config/betterh/config.toml
concurrency = 16
timeout_secs = 5
request_interval_ms = 1000
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
default_proxy = "socks5://127.0.0.1:9050"
wordlist_paths = ["/usr/share/wordlists/rockyou.txt"]
```

#### Foundation Parsing and Configuration Rules

- The CLI entrypoint (`main.rs`) validates invocations, runs `--dry-run` audits, and dispatches live attacks through `engine::runner` (scope → canary → `prepare_target` → brute/spray pool → session reporter). Wizard/completions/man remain non-attack paths: the wizard only prints the equivalent CLI argv and confirms that no authentication attempts were sent.
- Services are `ftp`, `ssh`, `http`, and `https`; HTTP authentication selects `-m basic`, `-m post-form`, or `-m bearer` (default `basic`). Cargo protocol features control later implementations, not parsing.
- URL usernames are percent-decoded. `-u` overrides the embedded user; `-L` replaces it with a list. Embedded passwords and URL fragments are rejected. HTTP paths retain the query string. IPv6 positional addresses require brackets when a port is supplied.
- `-C` accepts a combo list and conflicts with separate username/password sources. Both lists cannot consume stdin simultaneously. CIDR expansion and target-file reading belong to Phase 3.
- Duration flags accept whole numbers with `ms`, `s`, `m`, or `h` suffixes. Concurrency, timeout, and request interval must be positive.
- Configurable defaults are `concurrency` (16), `timeout_secs` (5), `request_interval_ms` (1000), `user_agent` (`betterh/0.1.0`), `default_proxy` (none), and `wordlist_paths` (empty). CLI flags are `--concurrency`, `--timeout-secs`, `--request-interval-ms`, `--user-agent`, `--proxy`, and repeatable `--wordlist-path`.
- Environment equivalents are `BETTERH_CONCURRENCY`, `BETTERH_TIMEOUT_SECS`, `BETTERH_REQUEST_INTERVAL_MS`, `BETTERH_USER_AGENT`, `BETTERH_PROXY`, and `BETTERH_WORDLIST_PATHS`. The last uses the platform path-list separator.
- Select one config file: explicit `--config`, otherwise local `betterh.toml`, otherwise the user config. Missing implicit files use defaults; a missing explicit file, unreadable file, unknown key, or malformed value is an error.
- Settings merge per field in CLI > environment > selected TOML > defaults order. Invalid values in a selected source are errors. Wordlist search paths do not implicitly select a credential file.

### 9.4 Shell Autocompletions & Man Pages
```bash
# Generate shell autocompletions on the fly
betterh completions zsh > ~/.zfunc/_betterh
eval "$(betterh completions bash)"

# Generate Unix roff man-page
betterh man > /usr/share/man/man1/betterh.1
```

---

## 10. Project Structure

```
betterh/
├── Cargo.toml
├── LICENSE-MIT               # MIT license text
├── LICENSE-APACHE            # Apache-2.0 license text
├── README.md                 # Quickstart, build, authorized-use notice
├── AGENTS.md                 # Agent guidelines, rules, and workflows
├── .github/
│   ├── dependabot.yml        # Weekly cargo + Actions update PRs
│   └── workflows/
│       └── ci.yml            # fmt / clippy / test / feature-gate CI
├── docs/
│   ├── SPEC.md               # Architecture and technical specification (this file)
│   └── PLAN.md               # Implementation roadmap and task list
└── src/
    ├── main.rs               # Entrypoint & CLI bootstrap
    ├── lib.rs                # Library root
    ├── cli.rs                # Clap arguments, URL parsing & hybrid dispatch
    ├── config.rs             # Hierarchical config loader (CLI > Env > TOML)
    ├── fsutil.rs             # Owner-only (0600) file create/chmod helpers
    ├── engine/               # Concurrency, worker pool, and attack coordinator
    │   ├── mod.rs
    │   ├── actions.rs        # Post-finding hooks (--on-found, --bell, skip rules)
    │   ├── adaptive.rs       # Backoff and rate-limiting
    │   ├── canary.rs         # Pre-flight false positive verification
    │   ├── checkpoint.rs     # Session serialization and resuming (0600)
    │   ├── dryrun.rs         # Pre-flight audit & combination calculator
    │   ├── keys.rs           # Crossterm interactive keystroke listener
    │   ├── pool.rs           # Tokio task coordination & semaphores
    │   ├── proxy.rs          # SOCKS5/HTTP routing & proxy pool
    │   ├── request_guard.rs  # Target pacing and terminal stop guard
    │   ├── runner.rs         # Live attack orchestration (main entry)
    │   ├── scope.rs          # Target exclusions and RoE guardrails
    │   ├── spray.rs          # Horizontal password spraying coordinator
    │   ├── targets.rs        # Target file and CIDR expansion
    │   └── wordlist.rs       # Streaming wordlist generator (O(1) RAM / -)
    ├── protocols/            # ProtocolModule trait and implementations
    │   ├── mod.rs            # ProtocolModule trait and registry
    │   ├── mock.rs           # MockProtocolModule for deterministic unit tests
    │   ├── ftp.rs            # FTP raw TCP module (feature = "ftp")
    │   ├── http.rs           # HTTP module (feature = "http")
    │   ├── socks.rs          # Shared SOCKS5 dial helper
    │   └── ssh.rs            # SSH module (feature = "ssh")
    ├── report/               # Reporting & formatters
    │   ├── mod.rs
    │   ├── jsonl.rs          # JSON / JSONL streaming output (0600)
    │   └── tui.rs            # Indicatif live dashboard with pinned success feed
    └── ui/                   # UX components & interactive wizard
        ├── mod.rs
        ├── completions.rs    # Shell completion & manpage generators
        ├── diagnostics.rs    # Actionable Cargo-style error formatting
        └── wizard.rs         # Inquire interactive CLI setup wizard
```

---

## 11. CLI Command Syntax

```bash
# General invocation (URL or Positional)
betterh <SERVICE> <TARGET> [OPTIONS]
betterh <URL> [OPTIONS]

# Interactive guided wizard
betterh wizard

# Shell autocompletion setup
eval "$(betterh completions zsh)"

# Pre-flight dry-run check with target exclusions
betterh ssh 192.168.1.0/24 -L users.txt -P passwords.txt \
  --exclude 192.168.1.1 \
  --exclude 192.168.1.254 \
  --dry-run

# Password spraying with alert hook and acoustic bell
betterh ssh 192.168.1.0/24 -L domain_users.txt -p 'Spring2026!' \
  --mode spray \
  --spray-cooldown 15m \
  --on-found "./notify.sh" \
  --bell \
  --exit-host

# HTTP POST form brute-force reading wordlist from stdin pipe
cat generated_passwords.txt | betterh http 192.168.1.100:8080/login \
  -u admin \
  -P - \
  --body "user={USER}&pass={PASS}" \
  --fail-string "Invalid credentials" \
  --format jsonl \
  --output results.jsonl

# Multi-target list with rotating proxies and exclusion list
betterh ftp -M internal_servers.txt --exclude-file excluded.txt -u root -P rockyou.txt \
  --proxy-list proxies.txt \
  -e ns

# Resuming an interrupted session
betterh --resume .betterh-session-a1b2c3.json
```

---

## 12. Testing Strategy & Mock Harness

Betterh enforces a **100% Hermetic In-Process Testing Strategy**:
- **Zero External Dependencies**: Tests run offline without Docker, third-party containers, or external internet connections.
- **Ephemeral Port Binding (`127.0.0.1:0`)**: All protocol tests bind to ephemeral ports on loopback to prevent port collisions during parallel test runs (`cargo test`).
- **Protocol Test Harness**:
  - **FTP**: An in-process Tokio `TcpListener` that speaks RFC 959 (`USER`, `PASS`, `220`, `331`, `230`, `530`) to verify positive/negative login, passive connections, and timeouts.
  - **HTTP**: `wiremock::MockServer` verifying Basic Auth, Form-POST body templates, JSON endpoints, and custom response status/bodies.
  - **SSH**: An in-process `russh::server` testing public key negotiation, password authentication, and session cleanup.
  - **Engine**: `MockProtocolModule` with programmable latency, rate-limiting, and error injection for testing backoff and cancellation under load.

---

## 13. Development & Verification Commands

```bash
# Build with default features
cargo build

# Build minimal (e.g. HTTP only)
cargo build --no-default-features --features http

# Release build
cargo build --release

# Format verification
cargo fmt --check

# Strict linting (must pass with zero warnings, pedantic + perf enabled)
cargo clippy --all-targets --all-features --locked -- -D warnings

# Run all unit and integration tests (hermetic, offline)
cargo test

# Run tests with logging enabled
RUST_LOG=debug cargo test -- --nocapture
```

---

## 14. Boundaries

### Always
- Verify all code with `cargo test` and `cargo clippy --all-targets --all-features --locked -- -D warnings`.
- Stream wordlists lazily; never load complete lists into memory.
- Enforce mode `0600` on any files containing discovered credentials or session state.
- Run canary pre-flight checks before full attack execution.
- Respect scope exclusions (`--exclude`, `--exclude-file`) unconditionally.
- Pass `--on-found` hook parameters via environment variables (never shell string formatting).
- Provide clean cancellation handling on `SIGINT` / `Ctrl+C` or `q` keypress that saves a session checkpoint.
- Use actionable error diagnostics with remediation hints.

### Ask First
- Adding external crates outside the approved tech stack.
- Modifying the public `ProtocolModule` trait interface.
- Changing checkpoint file schemas.

### Never
- Never use `unwrap()` or `expect()` in production protocol or engine code.
- Never write blocking I/O calls inside Tokio async contexts.
- Never buffer unbounded network streams or wordlists into RAM.
- Never write session files with world-readable permissions.
- Never execute `git push` (pushing is strictly reserved for the user).

---

## 15. Success Criteria

1. **Compilation & Quality**: Project compiles without warnings under `cargo clippy -- -D warnings` with `pedantic` and `perf` lint groups active across all feature combinations.
2. **Streaming Verification**: A 5GB wordlist runs with resident set size (RSS) memory consumption staying strictly under 30 MB. Stdin streaming (`-P -`) functions without buffering.
3. **CIDR & Scope Guardrails**: A `/24` subnet expands into active targets while strictly omitting any `--exclude` IPs/ranges.
4. **Hermetic Test Harness**: Complete `cargo test` suite executes offline in $< 10\text{ seconds}$ without Docker.
5. **False Positive Prevention**: A mock server configured to return 200 OK for all requests triggers the canary abort alert.
6. **Spray Strategy**: Password spraying mode tests a single password across all targets, triggers cooldown, and records zero account lockout events.
7. **Skip & Termination Rules**: `--exit-user` successfully skips remaining passwords for a found user; `--exit-first` stops the attack immediately upon the first hit.
8. **Safe Execution Hooks**: `--on-found` executes child processes passing credentials safely via `BETTERH_*` environment variables.
9. **CLI & URL Flexibility**: Accepts both `betterh ssh://user@10.0.0.1:22` and `betterh ssh 10.0.0.1:22 -u user`.
10. **Interactive UX**:
   - Pressing `Space` during an attack prints an instant status line.
   - Pressing `p` pauses/resumes task execution.
   - Pressing `+`/`-` updates concurrency dynamically.
   - Discovered credentials remain pinned at the top and are never lost in scrollback.
11. **Pre-Flight `--dry-run`**: Correctly validates options, counts combinations, and checks target connectivity without launching attacks.
12. **Actionable Diagnostics**: Connection and TLS errors print helpful remediation tips.
13. **Permission Security**: Created checkpoint and output files have POSIX mode `0600`.
14. **Licensing & Attribution**: All source files begin with the compliant dual MIT/Apache-2.0 SPDX identifier and copyright notice `(c) 2026 by Volker Schwaberow <volker@schwaberow.de>`.

---

## 16. Code Quality, Refactoring & SPDX Licensing

### 16.1 SPDX License Headers
Every Rust source file (`src/**/*.rs`, `tests/**/*.rs`) MUST begin with the standardized header:
```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>
```
Compliance is enforced by the hermetic integration test `tests/spdx_headers.rs`, which walks both trees and fails if any `.rs` file is missing either line as its first two source lines.

### 16.2 Refactoring & Code Deduplication Guidelines
- Consolidate repeated patterns (file reading, socket parsing, duration estimation, diagnostics formatting).
- Reusable utilities belong in cohesive internal modules rather than duplicate local helper functions.
- Keep abstraction minimal: never introduce trait abstractions for single implementations.

### 16.3 Optimization Standards
- Maintain $O(1)$ memory consumption ($< 15\text{ MB}$ RSS) across all streaming and processing pipelines.
- Pass small `Copy` types by value ($\le 24$ bytes).
- Prefer `Cow<'_, str>` when strings can be borrowed without allocation.
- Zero allocation in tight iteration loops.

---

## 17. Continuous Integration

Pull requests and pushes to `master` run a GitHub Actions workflow (`.github/workflows/ci.yml`) that enforces the same quality gate agents use locally:

1. `cargo fmt --check`
2. `cargo clippy --all-targets --all-features --locked -- -D warnings`
3. `cargo test --all-features --locked`
4. `cargo check --no-default-features --features http --locked` (feature-gating smoke)

The workflow uses the latest stable Rust toolchain with `rustfmt` and `clippy` components and caches Cargo artifacts for speed. It must remain hermetic: no network services beyond crates.io.

Dependency and GitHub Actions updates are proposed weekly by Dependabot (`.github/dependabot.yml`) as pull requests against `master`.
