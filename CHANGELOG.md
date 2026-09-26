# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Update this file in the same pull request as user-visible changes.

## [Unreleased]

### Added

- Project changelog (`CHANGELOG.md`, Keep a Changelog)
- Dual-license text files (`LICENSE-MIT`, `LICENSE-APACHE`) (#1)
- Weekly Dependabot updates for Cargo and GitHub Actions (`.github/dependabot.yml`) (#2)

### Changed

- CI checkout Action bumped to `actions/checkout@v7` (#3)
- Dependency refresh: `indicatif` 0.18, `crossterm` 0.29, `inquire` 0.9, `directories` 6, `toml` 1.1 (#4)

## [0.1.0] - 2026-09-26

### Added

- Initial tree: FTP / HTTP / SSH protocols, concurrency engine (scope, canary, spray, pacing, checkpoints), CLI, dry-run, wizard, reporters, hermetic tests, and GitHub Actions CI

[Unreleased]: https://github.com/vschwaberow/betterh/compare/ba7e0e8...HEAD
[0.1.0]: https://github.com/vschwaberow/betterh/releases/tag/v0.1.0
