# Design decisions

Short records of the non-obvious choices: what was decided, what was rejected,
and why. Each one closes a question a reviewer would otherwise ask.

---

### 1. One encrypted file, not SQLite

**Decision.** The vault is one file: a small authenticated header plus a
single AES-256-GCM payload containing all entries as JSON.

**Rejected.** SQLite with per-column encryption (v1's approach) leaks
structure: row count, per-row sizes, which rows changed, and any column left in
plaintext. v1 left site names and usernames in plaintext. SQLCipher fixes that
but adds a C dependency that is painful to build on Windows.

**Why it is fine.** A personal vault holds hundreds to a few thousand entries.
Re-encrypting a few hundred kilobytes on every save takes microseconds. It is
also the model KeePass (KDBX) has used for two decades.

### 2. A random vault key wrapped by a password-derived key

**Decision.** Argon2id(password) gives a KEK that unwraps a random 256-bit
vault key, and the vault key encrypts the payload.

**Why.** Key slots make room for more ways to unlock (keyfile today, recovery
key or hardware token later) without re-encrypting the data per method.

### 3. Changing the master password rotates the vault key anyway

**Decision.** `passwd` generates a *new* vault key and re-encrypts the payload,
not just a re-wrapped old key. It also deletes backups.

**Why.** Suppose the old password leaked. If only the wrapping changed, anyone
with an *old copy of the file* plus the old password could unwrap the unchanged
vault key and read every *future* version of the vault. Rotation closes that.
The test `test_old_password_plus_old_file_cannot_decrypt_new_file` proves it.

### 4. KDF parameters in the header, with a floor and a ceiling

**Decision.** Argon2id parameters are calibrated per machine at `init`
(target ≈ 1 s, memory up to 1 GiB) and stored in the header. Before running the
KDF, a policy check rejects parameters below RFC 9106's second recommendation
(64 MiB × 3 passes) or absurdly high.

**Why.** v1 hardcoded parameters, so changing them in code locked every
existing vault. The floor stops a substituted vault from getting your password
processed with trivially cheap settings. The ceiling stops a hostile file from
exhausting memory.

### 5. The keyfile goes into Argon2's `secret` input

**Decision.** Keyfile contents are hashed (domain-separated SHA-256) and passed
as Argon2id's `secret` parameter (RFC 9106 §3.1, "K").

**Rejected.** A "pepper" constant in source code (v1). Once the code is public,
a pepper is just a public constant.

### 6. Strict, bounded parsing before authentication

**Decision.** Duplicate JSON keys, unknown fields, `NaN`, booleans posing as
integers, oversized headers and non-zero padding are all errors.

**Why.** The header is parsed before anything is authenticated. A lenient
parser lets two implementations, or two code paths, disagree about what a file
means. That gap is where parser-differential attacks live.

### 7. Unicode NFC for passwords, UTF-8 for every stream

**Decision.** Passwords are NFC-normalized before the KDF, and redirected
stdin/stdout are forced to UTF-8.

**Why.** Found while testing with Greek input. The same visible password can be
typed as different code-point sequences, and Windows pipes default to cp1252.
Either one silently derives a *different key*, which is a lockout bug,
not a display bug.

### 8. Secrets never go through argv

**Decision.** Passwords and TOTP secrets are only ever prompted for with echo
off (or `--password-stdin` for scripts).

**Why.** Command-line arguments are visible to other users through the process
list (`ps`, `/proc/<pid>/cmdline`) and are saved in shell history.

### 9. The clipboard is cleared by a detached helper, only if unchanged

**Decision.** After copying, a detached process waits and then clears the
clipboard, but only if it still holds our value (compared by SHA-256). On
Windows the copy carries the formats that exclude it from clipboard history and
cloud sync.

**Why.** One-shot CLI commands exit immediately, so a timer thread would die
with them. Blindly clearing would destroy whatever the user copied next. The
helper runs from the package directory so a malicious `securevault/` folder in
the current directory cannot be imported in its place.

### 10. Crash-safe saves and optimistic concurrency

**Decision.** Write to a temp file, fsync it, `os.replace` it (atomic on
Windows and POSIX), then fsync the directory. Before writing, compare the
on-disk hash with the one read at open time.

**Why.** A crash mid-save must never leave a half-written vault. A long-running
`svault shell` and a one-off command must not silently overwrite each other.

### 11. Terminal output is sanitized

**Decision.** Every displayed field passes through `term_safe()`, which
escapes C0/C1 control characters and Unicode bidi overrides.

**Why.** Entries can come from imported CSVs. An escape sequence in a title
could rewrite the terminal, or on terminals that honor OSC 52, write to the
clipboard. The same review found literal bidi characters in our own source,
which `ruff` (PLE2502) now blocks in CI.

### 12. One runtime dependency

**Decision.** `cryptography` (≥ 44, for Argon2id) is the only runtime
dependency. TOTP, CSV, the clipboard and the wordlist are implemented with the
standard library.

**Why.** Every dependency is supply-chain attack surface, and a password manager
is a high-value target for exactly that.

### 13. The GUI is an optional, thin layer over the same core

**Decision.** `svault-gui` lives in `securevault/gui/`, installs only with the
`gui` extra (PySide6-Essentials), and imports Qt lazily. It calls `Vault`,
`model`, `generator`, `totp`, `audit` and `clipboard` exactly as the CLI does,
and never touches `crypto.py`, `vault_format.py` or the file format.

**Rejected.** The full `PySide6` package. It adds the Addons wheel, including
QtWebEngine (a bundled Chromium), which is size and attack surface a password
manager does not use. Also rejected: a second implementation of any vault logic
in the GUI.

**Why.** One core means one place to audit. The core test job runs without Qt
installed, so the GUI cannot quietly become a dependency of the CLI.

### 14. GUI threads and locking

**Decision.** Argon2id (unlock, re-key, restore, calibration) runs on a worker
thread while a local event loop keeps the window painting but ignores input.
Everything else, including every save, runs on the GUI thread. The idle lock is
a `QTimer`, which fires on that same thread.

**Why.** The CLI shell's timer is a separate thread, which is why `Vault.lock()`
takes a mutex. A `QTimer` cannot interrupt a save on its own thread at all. The
one save that runs elsewhere (`passwd`) is protected twice: locking is deferred
until the worker finishes, and the vault's mutex still applies. A lock also
drops every reference the GUI holds (list model, detail pane, TOTP secret, open
dialogs) and clears the clipboard if it still holds our last value.

**Rollback.** When the CLI fails to save, the process exits and the change dies
with it. The GUI keeps running, so a failed save restores the previous entries
in memory. On a cross-process conflict it also locks, so the next unlock loads
the file as it is now instead of overwriting another process's change.

### 15. GUI display and clipboard rules

**Decision.** Every label and message box shows vault text as plain text, after
the same `term_safe()` escaping as the terminal. Editors hold the *raw* values,
warn when a field contains control or bidi characters, and write back only the
fields that changed. Secret fields cannot be copied, cut or dragged out, even
when revealed; copying goes through the core clipboard (auto-clear, Windows
history exclusion). URLs are copied, never opened. On Windows every window is
excluded from screen capture.

**Why.** Qt labels and message boxes guess whether text is HTML, so an imported
title like `<img src=...>` would otherwise render as markup. Showing escaped text
in an editor would corrupt the entry on the next save. Opening a URL such as
`\\host\share` on Windows sends the user's NTLM credentials to that host.

### 16. The GUI leads with the password manager, not the file

**Decision.** With no vault yet, the GUI opens a welcome screen that asks only
for a master password; where the vault is saved, a keyfile and the unlock time
are folded under "Advanced". With a vault, the login screen is one password
field; the keyfile field appears only when the vault's header says a keyfile is
required. While locked, the vault's actions are hidden, not shown disabled. An
empty vault shows "Add your first password".

**Rejected.** The first design: a lock screen with vault-file, password and
keyfile fields, and a disabled "New entry" button in the toolbar. On a first run
there was nothing to unlock, so the visible "New entry" never became usable and
the screen read like a file-encryption tool.

**Why it is safe.** Whether a keyfile is required is already public: the header
is plaintext and documented as such in [FORMAT.md](FORMAT.md). Reading it before
the key derivation reveals nothing new and saves a pointless Argon2id run.
