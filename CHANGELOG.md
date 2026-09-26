# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Update this file in the same pull request as user-visible changes.

## [Unreleased]

### Added

- Intelligent wordlist & mutation engine (`--rules <file>`, `-e y,c,l,C`, `--rule-year <YEAR>`) with Hashcat rule interpreter, seasonal/enterprise generators, and $O(1)$ memory streaming pipeline (< 30 MB RSS across 1M candidates)

- RDP/CredSSP feasibility prototype (`feasibility-rdp`) and SPEC §5.2.D.2 wire analysis
- SMBv2/NTLMSSP feasibility prototype (`feasibility-smb`) and SPEC §5.2.D.1 wire analysis
- CLI schemes and dry-run wiring for `redis`, `imap`/`imaps`, and `ldap`/`ldaps`
- LDAP/LDAPS Simple Bind (RFC 4511 BER) with implicit TLS on port 636
- IMAP/IMAPS LOGIN with STARTTLS and implicit TLS via shared `TransportStream`
- Redis RESP `AUTH` module (inline password and ACL username/password) with hermetic mocks
- PostgreSQL `SCRAM-SHA-256` SASL authentication (RFC 5802 / RFC 7677)
- MySQL `caching_sha2_password` fast-cache and RSA-OAEP full authentication
- SMTP STARTTLS upgrade and implicit SMTPS via shared `TransportStream`
- Shared TLS `TransportStream` helper (`src/protocols/tls.rs`) with optional certificate bypass for `--insecure`
- Extended protocols: native wire-level implementations for SMTP (RFC 5321, `AUTH PLAIN`/`LOGIN`), MySQL (`HandshakeV10`, `mysql_native_password` SHA-1 scramble), and PostgreSQL (Frontend/Backend Protocol 3.0, cleartext and salted MD5 challenges)
- CLI support for `smtp`, `smtps`, `mysql`, `postgres`, and `postgresql` service schemes with `--database` option and SOCKS5 proxy tunneling
- Project changelog (`CHANGELOG.md`, Keep a Changelog) (#5)
- Dual-license text files (`LICENSE-MIT`, `LICENSE-APACHE`) (#1)
- Weekly Dependabot updates for Cargo and GitHub Actions (`.github/dependabot.yml`) (#2)
- Initial tree: FTP / HTTP / SSH protocols, concurrency engine (scope, canary, spray, pacing, checkpoints), CLI, dry-run, wizard, reporters, hermetic tests, and GitHub Actions CI

### Changed

- PLAN/SPEC add Phase 14 post-expansion refactoring roadmap (registry, I/O helpers, module splits)
- PLAN/SPEC add Phase 13 SMB `ProtocolModule` production roadmap (NTLMv2 auth on TCP/445)
- README documents Redis, IMAP/IMAPS, LDAP/LDAPS, updated MySQL/PostgreSQL auth, and Phase 11 feasibility feature flags
- README documents SMTP/SMTPS, MySQL, and PostgreSQL alongside the original protocols
- CI checkout Action bumped to `actions/checkout@v7` (#3)
- Dependency refresh: `indicatif` 0.18, `crossterm` 0.29, `inquire` 0.9, `directories` 6, `toml` 1.1 (#4)
