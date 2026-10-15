# Threat model

SecureVault is an **offline, single-user** password manager. This document
states what it defends against, how, and where its protection ends. A security
tool that overstates its guarantees is worse than one that states its limits.

## Assets

| Asset | Where it lives |
|---|---|
| Stored credentials (passwords, TOTP secrets, notes) | Vault file (encrypted), process memory while unlocked |
| Metadata (which sites, usernames, how many entries) | Inside the same ciphertext |
| Master password | The user's head; process memory briefly during unlock |
| Keyfile (optional) | A file the user controls |

## Adversaries and verdicts

| # | Adversary | In scope? | Defense |
|---|---|---|---|
| A1 | Steals the vault file (backup, cloud sync, lost laptop, stolen disk) | ✅ **Primary** | Argon2id with 64 MiB–1 GiB memory hardness. AES-256-GCM over *all* data. Random 256-bit vault key. Optional keyfile as a second factor. |
| A2 | Modifies the vault file (malware without memory access, sync conflicts, bit rot) | ✅ | AEAD over the payload with the full header as AAD. Strict pre-authentication parsing. Integrity failures are reported distinctly and restorable from verified backups. |
| A3 | Replaces the vault with one they built (to harvest the master password) | ✅ | KDF floor checked *before* the KDF runs; see [FORMAT.md](FORMAT.md#kdf-policy-checked-before-running-argon2). |
| A4 | Observes the screen or terminal (shoulder surfing, screen sharing, scrollback) | ✅ | Echo-free prompts. Secrets never printed unless `--reveal`/`--print` is asked for. Passwords masked by default. |
| A5 | Reads clipboard history or cloud clipboard sync | ✅ Windows / ⚠️ Linux | Windows: history and cloud-sync exclusion formats. Everywhere: auto-clear that only removes our own value. Linux clipboard managers may still record it (see residual risks). |
| A6 | Another local user on a shared Linux machine | ✅ | Vault 0600 in a 0700 directory. Secrets never in argv (passwords, TOTP). `PR_SET_DUMPABLE=0` blocks same-user ptrace on Linux. |
| A7 | Plants malicious data via an imported CSV (terminal escape injection) | ✅ | All displayed fields pass through `term_safe()`, which neutralizes C0/C1 controls and bidi overrides, including OSC 52 clipboard writes. |
| A8 | Plants files in the working directory to hijack imports | ✅ | The clipboard helper runs from the package directory, never from the cwd. |
| A9 | Malware running as the user while the vault is unlocked | ❌ **Out of scope** | No user-space password manager can defend against this (keyloggers, memory reads). Auto-lock limits the window. |
| A10 | Root / administrator / physical access to a running, unlocked machine | ❌ Out of scope | |
| A11 | Rollback to an older genuine vault | ❌ Not detectable offline | See residual risks. |

## STRIDE per component

| Component | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| **Vault file at rest** | n/a | AEAD + header-as-AAD | n/a (single user) | Full encryption, size padding | KDF ceiling, header/file size limits | n/a |
| **Header parser** (pre-auth) | Vault substitution → KDF floor | Strict canonical JSON, duplicate-key rejection | – | Header contains no secrets | Bounded sizes, recursion caught | Plain JSON only; no code-executing deserializers |
| **Process memory** | – | – | – | Key in `bytearray` and zeroized on lock; auto-lock; no core dumps; no ptrace (Linux) | – | – |
| **Clipboard** | – | – | – | History/cloud exclusion (Windows); clear-if-unchanged | – | Helper spawned without a shell, from a trusted cwd |
| **Terminal I/O** | – | Escape-sequence neutralization | – | Echo-off prompts; masked output; prompts on stderr | – | – |
| **Backups** | – | Each backup is a full AEAD vault; restore verifies before overwriting | – | Purged on master-password change (they hold the old key) | Rotated (newest 5) | – |
| **Keyfile** | Second factor | – | – | Hashed with domain separation before entering Argon2 | Size-bounded (32 B – 1 MiB) | – |

## Residual risks, stated honestly

1. **Python cannot reliably erase memory.** `str` objects are immutable, the
   runtime may copy them, and `cryptography` keeps its own key copy. Decrypted
   entries live in memory while the vault is unlocked and may be swapped to
   disk by the OS. Mitigations: short unlock windows, auto-lock, disabled core
   dumps. A Rust or C core with `mlock` would do better.
2. **Linux clipboard managers** (Klipper, GNOME extensions, CopyQ) may store
   copied passwords. There is no portable opt-out for `xclip`/`wl-copy`
   equivalent to Windows' exclusion formats. Use `get --print` piped elsewhere,
   or configure your manager to ignore it.
3. **Rollback.** Replacing the vault with an older genuine copy, even one of its
   own backups, cannot be detected without external state.
4. **SSDs and copy-on-write filesystems** keep old blocks. Old ciphertext may
   persist after a password change or delete. It stays encrypted, but under the
   *old* key, which is why changing the password after a suspected compromise
   also purges backups.
5. **Windows ACLs on custom paths.** The default location is protected by the
   per-user profile ACL. A vault you place in a shared folder inherits that
   folder's permissions.
6. **Stored TOTP secrets** turn two factors into one for anyone who opens the
   vault. This is a convenience trade-off.
7. **Plaintext exports** are plaintext. The CLI demands typed confirmation and
   writes them with `0600`/`O_EXCL`, but what happens to the file afterwards is
   up to the user.

## Lessons from the v1 audit

The rewrite was driven by these defects in v1:

| v1 defect | v2 answer |
|---|---|
| Hardcoded "pepper" in a public repository | Keyfile support through Argon2's real `secret` input |
| KDF parameters not stored, so changing them locked users out | Parameters in the authenticated header, with a policy floor |
| Site names and usernames stored in plaintext | Everything inside one ciphertext |
| Per-row encryption without AAD (rows swappable, deletable) | One AEAD payload with the header as AAD |
| Master password typed with `input()` (echoed) | `getpass`, with a refusal on non-terminals |
| ~39-bit "master password generator" (30-word list) | EFF 7776-word list, 77.5 bits for six words, integrity-pinned |
| Clipboard: wrong timeout, clobbered user data, Win+V history | Exclusion formats + clear-only-if-unchanged + detached helper |
| `VACUUM` presented as forensic deletion | Removed. Honest residual-risk statement instead. |
| Unverifiable `password.exe` committed to git | Reproducible CI builds with SHA-256 sums and build provenance |
