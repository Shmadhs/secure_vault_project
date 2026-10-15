# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-10-15

A complete rewrite after a security audit of v1. **v1 vaults (`vault.db`) are
not readable by v2.** v1 could not reliably open its own vaults across versions
either, because its KDF parameters were not stored.

### Added

- `.svault` single-file format: Argon2id → KEK → random vault key → AES-256-GCM
  payload, with the header authenticated as AAD ([spec](docs/FORMAT.md)).
- Per-machine Argon2id calibration (≈1 s, up to 1 GiB) with a policy floor and
  ceiling enforced before the KDF runs.
- Optional keyfile second factor through Argon2id's `secret` input.
- Commands: `init`, `add`, `get`, `show`, `list`, `search`, `edit`, `rm`, `gen`,
  `totp`, `audit`, `passwd`, `import`, `export`, `backups`, `restore`, `info`,
  `keyfile`, `shell`.
- Interactive shell with idle auto-lock.
- Clipboard auto-clear through a detached helper that only clears its own
  value, plus Windows clipboard-history and cloud-sync exclusion.
- EFF-wordlist passphrases, rejection-sampled passwords, strength estimate.
- RFC 6238 TOTP, password history, a health audit (reused/weak/stale).
- CSV import from Bitwarden, KeePassXC, Chrome/Edge and Firefox; CSV/JSON export.
- Crash-safe atomic saves, rotating encrypted backups, verified restore,
  cross-process conflict detection.
- Linux process hardening (no core dumps, `PR_SET_DUMPABLE=0`).
- 240+ tests, strict typing, CI on Windows/Linux/macOS, CodeQL, attested release builds.

### Fixed (v1 defects)

- Hardcoded pepper in source code.
- Lockout when KDF parameters changed between versions.
- Site names and usernames stored in plaintext.
- Encrypted rows not bound to their context (swappable, silently deletable).
- Master password echoed to the terminal.
- ~39-bit "strong" master-password generator.
- Clipboard timer mismatch, clobbering of user clipboard data, and clipboard history leaks.
- Unverifiable binary committed to the repository.

## [1.0] - 2026-03-30

- Initial SQLite-based CLI prototype.
