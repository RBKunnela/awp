# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Versioning policy

- **npm SemVer** (`0.2.0` …) tracks the **code** axis: verifier fixes, additive schema, tooling.
- **`/vN` in `predicateType` and schema `$id`** tracks the **wire-format** axis. `/v1` is frozen at first public publish. Removing a claim-class is a wire break → `/v2`.

## [0.2.0] — 2026-06-29

### Added

- Permanent protocol namespace: `https://awp.dev/witness-record/v1` (predicateType + schema `$id`).
- GitHub Actions CI on `main` (lint → typecheck → build → test) with Node 20.
- `SECURITY.md` — supported versions, disclosure path, honesty boundary for verification claims.
- `NOTICE` — copyright and dual-license attribution (code Apache-2.0; spec CC-BY-4.0).
- `CONTRIBUTING.md` — build/test/PR expectations and conventional commits.
- Release hygiene: package `repository` / `homepage` / `bugs` / `author` metadata; `prepublishOnly` runs build + test.

### Changed

- Package version bumped to **0.2.0** for first public-release hygiene (namespace finalization is a breaking wire-identity change from placeholder).
- `.gitignore` excludes large video assets under `docs/videos/` (hosted on YouTube).

### Security

- Documented that `awp verify` proves **integrity-since-witness only** — not authenticity-at-origin, completeness, or identity. Verification is best-effort cryptographic re-performance.

## [0.1.1] — prior

Internal / pre-public development line (schema, DSSE + in-toto envelope, RFC 9162 log, anchors, CLI).

[0.2.0]: https://github.com/RBKunnela/awp/compare/v0.1.1...v0.2.0
