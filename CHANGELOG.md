# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.1.0] - 2026-11-08

### Added

- Optional desktop app, `svault-gui` (`pip install "securevault[gui]"`, PySide6-Essentials).
  It is a thin layer over the same core as the CLI and reads as a password manager first:
  a welcome screen on first run that asks only for a master password (location, keyfile
  and unlock time under "Advanced"), then an empty vault with "Add your first password";
  afterwards a login screen with just the master password (the keyfile field appears only
  when the vault requires one). Unlock failures get distinct messages (wrong password,
  missing keyfile, integrity failure, sub-floor KDF, not a vault). Entry list with search
  and tag filter, detail pane with a masked password and live TOTP, add/edit/delete
  (exact-title confirmation), generator with entropy, password-health audit,
  master-password change (re-authenticates first), encrypted backups and verified
  restore, reachable from the login screen too.
- GUI locking: idle auto-lock, lock on minimize and on exit. A lock closes every dialog,
  empties every view and clears the last copied value from the clipboard if unchanged.
- GUI hardening: all vault text is plain text (no HTML rendering) and escaped like the
  CLI's output; secret fields cannot be copied out through the system clipboard; URLs are
  never opened; on Windows, GUI windows are excluded from screen capture.
- 67 GUI tests (pytest-qt, headless) and 4 tests that keep the GUI optional, a
  cross-platform `gui` CI job, and a core test job that runs without Qt installed.

### Changed

- The README leads with what SecureVault does as a password manager; the cryptography
  moved to "Under the hood" and the security design section.
- `cli.create_keyfile` and `cli.split_tags` are public (renamed from `_create_keyfile` and
  `_split_tags`) so the GUI reuses them. No behavior change.

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
