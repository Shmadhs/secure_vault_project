"""On-disk vault format, version 1. The normative spec is docs/FORMAT.md.

Layout::

    +--------+---------+------------+------------------+---------------------------+
    | "SVLT" | version | header_len |   header (JSON)  | payload (AES-256-GCM blob)|
    | 4 B    | u16 BE  | u32 BE     |   header_len B   | nonce || ciphertext || tag|
    +--------+---------+------------+------------------+---------------------------+
    \\______________ header block = payload AAD _______/

* The header is plaintext so the KDF parameters can be read before unlocking.
  It is authenticated, because the whole header block is the payload's
  associated data. Any change to it is detected after unlock.
* Each key slot wraps the random vault key under a KEK derived from the master
  password (plus an optional keyfile). The slot's AAD binds the wrapped key to
  its own KDF parameters and to the vault id.
* The payload is length-prefixed JSON, zero-padded to a 1 KiB boundary, so the
  file size reveals only roughly how much is stored.

Parsing is deliberately strict: duplicate JSON keys, unknown fields, NaN, and
non-canonical types are all rejected. This keeps any two parsers from
disagreeing about what a file means, and the header is read before anything is
authenticated.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import struct
from dataclasses import dataclass
from typing import Any

from .crypto import NONCE_SIZE, TAG_SIZE, KdfParams
from .errors import UnsupportedVersionError, VaultFormatError

MAGIC = b"SVLT"
FORMAT_VERSION = 1
CIPHER = "aes-256-gcm"
KDF_NAME = "argon2id"
ARGON2_VERSION = 0x13

PREAMBLE = struct.Struct(">4sHI")
MAX_HEADER_SIZE = 64 * 1024
MAX_VAULT_SIZE = 64 * 1024 * 1024
MAX_SLOTS = 8
PAD_BLOCK = 1024
_LENGTH_PREFIX = struct.Struct(">I")
_VAULT_ID_RE = re.compile(r"[0-9a-f]{32}")
_SLOT_AAD_DOMAIN = b"securevault/slot/v1\x00"


# --------------------------------------------------------------------------- JSON


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VaultFormatError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> None:
    raise VaultFormatError(f"invalid JSON constant: {name}")


def strict_json_loads(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise VaultFormatError("malformed JSON") from exc


def canonical_json(obj: Any) -> bytes:
    """Deterministic ASCII JSON, so equal values always serialize to equal bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(value: Any, what: str) -> bytes:
    if not isinstance(value, str):
        raise VaultFormatError(f"{what} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise VaultFormatError(f"{what} is not valid base64") from exc


def _int(value: Any, what: str) -> int:
    # bool is a subclass of int in Python. Exclude it explicitly.
    if type(value) is not int:
        raise VaultFormatError(f"{what} must be an integer")
    return value


def _exact_keys(obj: Any, keys: set[str], what: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise VaultFormatError(f"{what} must be an object")
    if set(obj) != keys:
        raise VaultFormatError(f"{what} has missing or unexpected fields")
    return obj


# --------------------------------------------------------------------------- header


def kdf_to_dict(params: KdfParams) -> dict[str, Any]:
    return {
        "name": KDF_NAME,
        "version": ARGON2_VERSION,
        "salt": _b64e(params.salt),
        "memory_kib": params.memory_kib,
        "iterations": params.iterations,
        "lanes": params.lanes,
    }


def kdf_from_dict(obj: Any) -> KdfParams:
    d = _exact_keys(obj, {"name", "version", "salt", "memory_kib", "iterations", "lanes"}, "kdf")
    if d["name"] != KDF_NAME or _int(d["version"], "kdf.version") != ARGON2_VERSION:
        raise VaultFormatError("unsupported KDF")
    return KdfParams(
        salt=_b64d(d["salt"], "kdf.salt"),
        memory_kib=_int(d["memory_kib"], "kdf.memory_kib"),
        iterations=_int(d["iterations"], "kdf.iterations"),
        lanes=_int(d["lanes"], "kdf.lanes"),
    )


@dataclass(frozen=True)
class KeySlot:
    """One way to unlock the vault: a KDF configuration plus the wrapped vault key."""

    kdf: KdfParams
    keyfile: bool
    wrapped_key: bytes

    def aad(self, vault_id: str) -> bytes:
        """Associated data binding the wrapped key to its KDF settings and vault."""
        return _SLOT_AAD_DOMAIN + canonical_json(
            {"vault_id": vault_id, "kdf": kdf_to_dict(self.kdf), "keyfile": self.keyfile}
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kdf": kdf_to_dict(self.kdf),
            "keyfile": self.keyfile,
            "wrapped_key": _b64e(self.wrapped_key),
        }

    @classmethod
    def from_dict(cls, obj: Any) -> KeySlot:
        d = _exact_keys(obj, {"kdf", "keyfile", "wrapped_key"}, "slot")
        if not isinstance(d["keyfile"], bool):
            raise VaultFormatError("slot.keyfile must be a boolean")
        wrapped = _b64d(d["wrapped_key"], "slot.wrapped_key")
        if len(wrapped) != NONCE_SIZE + 32 + TAG_SIZE:
            raise VaultFormatError("slot.wrapped_key has the wrong length")
        return cls(kdf=kdf_from_dict(d["kdf"]), keyfile=d["keyfile"], wrapped_key=wrapped)


@dataclass(frozen=True)
class Header:
    vault_id: str
    slots: tuple[KeySlot, ...]

    def encode(self) -> bytes:
        return canonical_json(
            {
                "cipher": CIPHER,
                "vault_id": self.vault_id,
                "slots": [slot.to_dict() for slot in self.slots],
            }
        )

    @classmethod
    def decode(cls, raw: bytes) -> Header:
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise VaultFormatError("header is not ASCII") from exc
        d = _exact_keys(strict_json_loads(text), {"cipher", "vault_id", "slots"}, "header")
        if d["cipher"] != CIPHER:
            raise VaultFormatError("unsupported cipher")
        vault_id = d["vault_id"]
        if not isinstance(vault_id, str) or not _VAULT_ID_RE.fullmatch(vault_id):
            raise VaultFormatError("invalid vault id")
        slots = d["slots"]
        if not isinstance(slots, list) or not 1 <= len(slots) <= MAX_SLOTS:
            raise VaultFormatError("invalid key slot list")
        return cls(vault_id=vault_id, slots=tuple(KeySlot.from_dict(s) for s in slots))

    def block(self) -> bytes:
        """Preamble plus header bytes: the exact bytes used as the payload AAD."""
        raw = self.encode()
        if len(raw) > MAX_HEADER_SIZE:
            raise VaultFormatError("header too large")
        return PREAMBLE.pack(MAGIC, FORMAT_VERSION, len(raw)) + raw


@dataclass(frozen=True)
class ParsedFile:
    header: Header
    header_block: bytes
    payload: bytes


def parse_file(data: bytes) -> ParsedFile:
    """Split and validate a vault file's structure. No cryptography happens here."""
    if len(data) > MAX_VAULT_SIZE:
        raise VaultFormatError("file is too large to be a vault")
    if len(data) < PREAMBLE.size:
        raise VaultFormatError("file is too short to be a vault")
    magic, version, header_len = PREAMBLE.unpack_from(data)
    if magic != MAGIC:
        raise VaultFormatError("not a SecureVault file")
    if version > FORMAT_VERSION:
        raise UnsupportedVersionError(
            f"vault format v{version} is newer than this program supports (v{FORMAT_VERSION}); upgrade SecureVault"
        )
    if version < 1:
        raise VaultFormatError("invalid format version")
    end = PREAMBLE.size + header_len
    if header_len > MAX_HEADER_SIZE or end > len(data):
        raise VaultFormatError("invalid header length")
    header = Header.decode(data[PREAMBLE.size : end])
    payload = data[end:]
    if len(payload) < NONCE_SIZE + TAG_SIZE:
        raise VaultFormatError("payload is truncated")
    return ParsedFile(header=header, header_block=data[:end], payload=payload)


# --------------------------------------------------------------------------- payload


def encode_payload(obj: dict[str, Any]) -> bytes:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    framed = _LENGTH_PREFIX.pack(len(raw)) + raw
    return framed + bytes(-len(framed) % PAD_BLOCK)


def decode_payload(data: bytes) -> dict[str, Any]:
    if len(data) < _LENGTH_PREFIX.size:
        raise VaultFormatError("payload too short")
    (length,) = _LENGTH_PREFIX.unpack_from(data)
    end = _LENGTH_PREFIX.size + length
    if end > len(data) or any(data[end:]):
        raise VaultFormatError("invalid payload framing")
    try:
        text = data[_LENGTH_PREFIX.size : end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VaultFormatError("payload is not UTF-8") from exc
    obj = strict_json_loads(text)
    if not isinstance(obj, dict):
        raise VaultFormatError("payload must be a JSON object")
    return obj
