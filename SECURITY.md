# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 2.x | ✅ |
| 1.x (SQLite-based) | ❌ Known-insecure; see the v1 lessons in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#lessons-from-the-v1-audit). Do not use. |

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:
**Security → Report a vulnerability** on this repository (private vulnerability
reporting).

Include:

* the version (`svault --version`) and OS;
* what an attacker needs (file access, local user, a crafted CSV...) and what
  they gain;
* a proof of concept if you have one. Please use test vaults, never real data.

Expected timeline: acknowledgement within 7 days, an assessment within 30, and
coordinated public disclosure once a fix is released, or after 90 days.

## Scope

In scope: anything that weakens the guarantees in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). That includes the file format,
key derivation, parsing of untrusted vault or CSV files, clipboard handling,
secrets reaching logs/argv/stdout/disk, and the release build pipeline.

Out of scope (documented limitations): malware running as the user while the
vault is unlocked, root/administrator access to a running machine, rollback to
an older genuine vault, and memory-erasure guarantees beyond what Python can
provide.

## Verifying releases

Release binaries are built by GitHub Actions from tagged commits. Each release
carries `SHA256SUMS` and a signed build-provenance attestation:

```bash
sha256sum -c SHA256SUMS
gh attestation verify <binary> --repo Shmadhs/secure_vault_project
```
