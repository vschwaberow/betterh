# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Update this file in the same pull request as user-visible changes.

## [Unreleased]

### Added

- SMTP STARTTLS upgrade and implicit SMTPS via shared `TransportStream`
- Shared TLS `TransportStream` helper (`src/protocols/tls.rs`) with optional certificate bypass for `--insecure`
- Extended protocols: native wire-level implementations for SMTP (RFC 5321, `AUTH PLAIN`/`LOGIN`), MySQL (`HandshakeV10`, `mysql_native_password` SHA-1 scramble), and PostgreSQL (Frontend/Backend Protocol 3.0, cleartext and salted MD5 challenges)
- CLI support for `smtp`, `smtps`, `mysql`, `postgres`, and `postgresql` service schemes with `--database` option and SOCKS5 proxy tunneling
- Project changelog (`CHANGELOG.md`, Keep a Changelog) (#5)
- Dual-license text files (`LICENSE-MIT`, `LICENSE-APACHE`) (#1)
- Weekly Dependabot updates for Cargo and GitHub Actions (`.github/dependabot.yml`) (#2)
- Initial tree: FTP / HTTP / SSH protocols, concurrency engine (scope, canary, spray, pacing, checkpoints), CLI, dry-run, wizard, reporters, hermetic tests, and GitHub Actions CI

### Changed

- README documents SMTP/SMTPS, MySQL, and PostgreSQL alongside the original protocols
- CI checkout Action bumped to `actions/checkout@v7` (#3)
- Dependency refresh: `indicatif` 0.18, `crossterm` 0.29, `inquire` 0.9, `directories` 6, `toml` 1.1 (#4)
