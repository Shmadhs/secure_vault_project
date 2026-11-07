# SecureVault file format, version 1

This document specifies the `.svault` file format precisely enough for an
independent implementation. The reference implementation is
[`src/securevault/vault_format.py`](../src/securevault/vault_format.py) and
[`src/securevault/vault.py`](../src/securevault/vault.py).

## Goals

1. **Everything sensitive is encrypted.** Titles, usernames, URLs, notes and the
   number of entries are all inside one ciphertext. The only plaintext is what
   is needed to derive the key.
2. **Every byte is authenticated.** Changing, truncating or splicing any part of
   the file is detected.
3. **Parameters travel with the file.** KDF settings live in the header, so they
   can be strengthened over time without locking anyone out.
4. **Parsing is strict and bounded** because it happens before authentication.

## Layout

All integers are big-endian.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `magic` | ASCII `SVLT` |
| 4 | 2 | `version` | `1`. Readers MUST reject larger values. |
| 6 | 4 | `header_len` | Length of `header`. MUST be ≤ 65 536. |
| 10 | `header_len` | `header` | Canonical JSON, ASCII (see below) |
| 10 + `header_len` | rest | `payload` | `nonce (12) ‖ ciphertext ‖ tag (16)` |

The first `10 + header_len` bytes are the **header block**. They are used
verbatim as the AAD of the payload. The whole file MUST be at most 64 MiB.

## Header

Canonical JSON: keys sorted, separators `,` and `:` with no whitespace, ASCII
only. Byte strings are standard base64 with padding.

```json
{
  "cipher": "aes-256-gcm",
  "slots": [
    {
      "kdf": {
        "iterations": 2,
        "lanes": 4,
        "memory_kib": 1048576,
        "name": "argon2id",
        "salt": "<32 bytes, base64>",
        "version": 19
      },
      "keyfile": false,
      "wrapped_key": "<60 bytes, base64: nonce(12) ‖ ct(32) ‖ tag(16)>"
    }
  ],
  "vault_id": "<32 lowercase hex chars, random>"
}
```

Readers MUST reject:

* duplicate object keys, unknown or missing keys, `NaN`/`Infinity`;
* booleans where integers are expected (`true` is not `1`);
* a `cipher` other than `aes-256-gcm`, a KDF other than Argon2id v1.3 (`19`);
* zero or more than 8 slots, or a `wrapped_key` that is not exactly 60 bytes.

### KDF policy (checked before running Argon2)

| Parameter | Allowed | Why |
|---|---|---|
| salt | 16–64 bytes | RFC 9106 recommends ≥ 16 |
| lanes | 1–16 | |
| iterations | 1–64 | ceiling prevents CPU denial of service |
| memory_kib | ≤ 4 GiB, ≥ 8 × lanes | ceiling prevents memory denial of service |
| memory_kib | ≥ 65 536 (64 MiB) | **security floor** |
| memory_kib × iterations | ≥ 196 608 | **security floor** (RFC 9106 option 2: 64 MiB × 3) |

A header below the floor is rejected **without running the KDF**. A genuine
vault never has such parameters, so this indicates a substituted file built to
make the master password cheap to crack.

## Key derivation

```
password_bytes = UTF-8( NFC( master_password ) )
secret         = SHA-256( "securevault/keyfile/v1" ‖ 0x00 ‖ keyfile_bytes )   if keyfile
KEK            = Argon2id(password_bytes, salt, t=iterations, m=memory_kib, p=lanes,
                          secret=secret or absent, length=32)
```

NFC normalization makes the same visible password derive the same key on every
OS and keyboard layout. It matters for Greek and other accented scripts.

## Key slot

```
slot_aad    = "securevault/slot/v1" ‖ 0x00 ‖
              canonical_json({"vault_id": vault_id, "kdf": <kdf object>, "keyfile": <bool>})
wrapped_key = nonce ‖ AES-256-GCM(KEK, nonce, vault_key, aad=slot_aad)
```

The 32-byte `vault_key` is random. Readers try each slot in order. A slot
whose KDF fails the policy aborts the open. A slot that needs a keyfile is
skipped when none was supplied.

## Payload

```
plaintext = u32_be(len(json)) ‖ json ‖ 0x00 × pad
payload   = nonce ‖ AES-256-GCM(vault_key, nonce, plaintext, aad=header_block)
```

* `json` is UTF-8, keys sorted, no whitespace.
* `pad` brings the plaintext to a multiple of 1024 bytes, so the file size
  reveals only roughly how much is stored. Readers MUST reject non-zero padding.
* A fresh random 96-bit nonce is used on every save.

Payload JSON (schema 1):

```json
{
  "schema": 1,
  "entries": [
    {
      "id": "<32 hex>", "title": "GitHub", "username": "...", "password": "...",
      "url": "...", "notes": "...", "tags": ["dev"], "totp": "<otpauth URI or base32>",
      "created": "2026-10-15T08:00:00+00:00", "modified": "...",
      "history": [{"password": "...", "changed": "..."}]
    }
  ]
}
```

Unknown keys at the top level and inside entries MUST be preserved on save.
That lets older versions edit vaults written by newer ones without losing data.

## Error semantics

| Condition | Meaning | Reference exit code |
|---|---|---|
| Structure or policy check fails | Not a valid vault (`VaultFormatError`) | 1 |
| No slot unwraps | Wrong password or keyfile (`AuthenticationError`) | 3 |
| Slot unwraps but payload fails | **File modified or damaged** (`IntegrityError`) | 4 |

## Known limitation: rollback

An attacker with write access can replace the vault with an *older, genuine*
version (for example one of the automatic backups). Without state stored
outside the file, no offline format can detect this. The threat model covers
it in more detail.
