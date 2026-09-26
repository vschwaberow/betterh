# Betterh

Betterh is a memory-safe, high-concurrency network authentication auditor written in Rust. It streams credentials with constant memory, respects scope exclusions, probes for false positives before a run, and speaks FTP, HTTP/HTTPS, and SSH behind optional Cargo features.

**Authorized use only.** Use Betterh only on systems you own or are explicitly allowed to test.

## Install

Requires a recent stable Rust toolchain (Edition 2024).

```bash
git clone https://github.com/vschwaberow/betterh.git
cd betterh
cargo build --release
```

HTTP-only binary:

```bash
cargo build --release --no-default-features --features http
```

The release binary is `target/release/betterh`.

## Usage

```bash
betterh                                  # quickstart help
betterh wizard                           # guided setup (prints CLI; does not attack)
betterh <SERVICE> <TARGET> [OPTIONS]
betterh <URL> [OPTIONS]
```

### Examples

```bash
# Audit combinations without sending credentials
betterh ssh 192.168.1.0/24 -L users.txt -P passwords.txt \
  --exclude 192.168.1.1 --dry-run

# URL form with embedded user
betterh ssh://admin@127.0.0.1:2222 -P passwords.txt

# Form POST; passwords from stdin
cat passwords.txt | betterh http 127.0.0.1:8080/login \
  -u admin -P - \
  --body 'user={USER}&pass={PASS}' \
  --fail-string 'Invalid credentials' \
  --format jsonl --output findings.jsonl

# Completions and man page
eval "$(betterh completions bash)"
betterh man > betterh.1
```

Settings resolve in order: CLI flags, then `BETTERH_*` environment variables, then `./betterh.toml` or `~/.config/betterh/config.toml`.

## Capabilities

| Area | What you get |
| --- | --- |
| Protocols | FTP, HTTP/HTTPS (Basic / form POST / Bearer), SSH (password or key) |
| Modes | Vertical brute-force, horizontal password spray with cooldowns |
| Targets | Host, URL, `-M` file, CIDR, `--exclude` / `--exclude-file` |
| Network | SOCKS5 / HTTP proxies, pacing, jitter, adaptive backoff |
| Controls | Canary abort, `--exit-user` / `--exit-host` / `--exit-first`, `--on-found`, checkpoints on interrupt |
| Output | TTY dashboard, JSON / JSONL (files created mode `0600`) |

## Develop

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

- Architecture: [`docs/SPEC.md`](docs/SPEC.md)
- Roadmap: [`docs/PLAN.md`](docs/PLAN.md)
- Agent rules: [`AGENTS.md`](AGENTS.md)

## License

Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE). Every Rust source file starts with:

```text
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>
```
