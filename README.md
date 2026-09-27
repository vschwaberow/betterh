# Betterh

Betterh is a memory-safe, high-concurrency network authentication auditor written in Rust. It streams credentials with constant memory, respects scope exclusions, probes for false positives before a run, and speaks FTP, HTTP/HTTPS, SSH, SMTP/SMTPS, MySQL, PostgreSQL, Redis, IMAP/IMAPS, LDAP/LDAPS, SMB, and RDP behind optional Cargo features.

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
betterh mcp                              # Model Context Protocol server (stdio JSON-RPC)
betterh <SERVICE> <TARGET> [OPTIONS]
betterh <URL> [OPTIONS]
```

Services: `ftp`, `ssh`, `http`, `https`, `smtp`, `smtps`, `mysql`, `postgres` (alias `postgresql`), `redis`, `imap`, `imaps`, `ldap`, `ldaps`, `smb`, `rdp`.

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

# SMTP AUTH and database logins
betterh smtp 127.0.0.1:587 -u alice -P passwords.txt
betterh mysql://127.0.0.1:3306 -u root -P passwords.txt --database app
betterh postgres 127.0.0.1:5432 -u alice -P passwords.txt --database app

# Redis, IMAP, LDAP, SMB, RDP
betterh redis 127.0.0.1:6379 -P passwords.txt
betterh imaps 127.0.0.1:993 -u alice -P passwords.txt --insecure
betterh ldap://127.0.0.1:389 -u 'cn=alice,dc=example,dc=com' -P passwords.txt
betterh smb://127.0.0.1 -u 'DOMAIN\alice' -P passwords.txt
betterh rdp://127.0.0.1 -u alice -P passwords.txt --insecure

# Wordlist rules and seasonal mangling
betterh ssh 127.0.0.1 -L users.txt -P passwords.txt --rules rules.txt -e y,c --rule-year 2026

# Completions and man page
eval "$(betterh completions bash)"
betterh man > betterh.1

# MCP server for agent tooling (initialize / tools / resources over stdio)
betterh mcp --stdio
```

Settings resolve in order: CLI flags, then `BETTERH_*` environment variables, then `./betterh.toml` or `~/.config/betterh/config.toml`.

## Capabilities

| Area | What you get |
| --- | --- |
| Protocols | FTP; HTTP/HTTPS (Basic / form POST / Bearer); SSH (password or key); SMTP/SMTPS (`AUTH PLAIN` / `LOGIN`, STARTTLS); MySQL (`mysql_native_password`, `caching_sha2_password`); PostgreSQL (cleartext / MD5 / `SCRAM-SHA-256`); Redis (RESP `AUTH` inline / ACL); IMAP/IMAPS (`LOGIN`, STARTTLS); LDAP/LDAPS (Simple Bind); SMB (SMBv2 NTLMv2 `SESSION_SETUP`); RDP (CredSSP/NLA `NTLMv2`) |
| Wordlists | $O(1)$ streaming wordlists; Hashcat rules (`--rules`); mangling (`-e n,s,r,y,c,l,C`); year overrides (`--rule-year`) |
| Modes | Vertical brute-force, horizontal password spray with cooldowns |
| Targets | Host, URL, `-M` file, CIDR, `--exclude` / `--exclude-file` |
| Network | SOCKS5 / HTTP proxies, pacing, jitter, adaptive backoff |
| Controls | Canary abort, `--exit-user` / `--exit-host` / `--exit-first`, `--on-found`, checkpoints on interrupt |
| Output | TTY dashboard, JSON / JSONL (files created mode `0600`) |
| MCP | `betterh mcp` stdio server: `audit_dryrun`, `audit_execute` (confirm-gated), `validate_scope`, `list_protocols`, `session_status`; resources `betterh://protocols`, `betterh://session/current`, `betterh://reports/{hash}` |

## Develop

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

Production SMB / RDP modules (feasibility features re-export codecs):

```bash
cargo test --features smb protocols::smb
cargo test --features rdp protocols::rdp
cargo test --features feasibility-rdp feasibility::rdp
```

`feasibility-smb` / `feasibility-rdp` re-export production codecs (`smb` / `rdp`).

- Architecture: [`docs/SPEC.md`](docs/SPEC.md)
- Roadmap: [`docs/PLAN.md`](docs/PLAN.md)
- Changelog: [`CHANGELOG.md`](CHANGELOG.md)
- Agent rules: [`AGENTS.md`](AGENTS.md)

## License

Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE). Every Rust source file starts with:

```text
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>
```
