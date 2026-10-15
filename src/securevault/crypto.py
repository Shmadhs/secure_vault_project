"""Cryptographic core.

This is the only module that imports from ``cryptography``. Everything else
handles opaque byte strings, which keeps the code an auditor must read short.

* **Argon2id** (RFC 9106) derives a key-encryption key (KEK) from the master
  password and, optionally, a keyfile.
* **AES-256-GCM** (NIST SP 800-38D) wraps the random vault key under the KEK and
  encrypts the payload under the vault key. Every call uses a fresh random
  96-bit nonce. A vault performs a handful of encryptions per save, far below
  the 2^32 limit for random nonces under one key.

Memory hygiene caveat: Python cannot guarantee that secrets are erased.
``str`` and ``bytes`` are immutable and may be copied by the runtime, and
``cryptography`` keeps its own copy of key material. We hold the keys we
control in ``bytearray`` and overwrite them on lock. That narrows the exposure
window but does not close it. See docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import hashlib
import math
import os
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from . import osutil
from .errors import VaultError, VaultFormatError, WeakKdfError

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
SALT_SIZE = 32

MIB_IN_KIB = 1024
MIN_KEYFILE_SIZE = 32
MAX_KEYFILE_SIZE = 1 << 20
_KEYFILE_DOMAIN = b"securevault/keyfile/v1\x00"

DEFAULT_LANES = 4
DEFAULT_UNLOCK_SECONDS = 1.0
_MAX_CALIBRATED_ITERATIONS = 10


class DecryptionFailed(Exception):
    """AEAD authentication failed. Internal: callers translate it into a VaultError."""


@dataclass(frozen=True)
class KdfParams:
    """Argon2id parameters.

    They are stored in the vault header, so they can change from vault to vault
    and be raised later without locking anyone out (v1's bug).
    """

    salt: bytes
    memory_kib: int
    iterations: int
    lanes: int

    @property
    def memory_mib(self) -> float:
        return self.memory_kib / MIB_IN_KIB


@dataclass(frozen=True)
class KdfPolicy:
    """Bounds a header's KDF parameters must satisfy before the KDF runs.

    The floor stops a substituted vault with deliberately cheap parameters from
    getting the master password processed into an easily cracked form. The
    ceiling stops a malicious header from exhausting memory or CPU. The floor
    follows RFC 9106's second recommended option (64 MiB, t=3).
    """

    min_memory_kib: int = 64 * MIB_IN_KIB
    min_work: int = 3 * 64 * MIB_IN_KIB  # memory_kib * iterations
    max_memory_kib: int = 4 * 1024 * MIB_IN_KIB
    max_iterations: int = 64
    max_lanes: int = 16
    min_salt_size: int = 16
    max_salt_size: int = 64


DEFAULT_POLICY = KdfPolicy()


def check_kdf_params(params: KdfParams, policy: KdfPolicy = DEFAULT_POLICY) -> None:
    """Raise unless ``params`` is within ``policy``. Call this before deriving."""
    if not policy.min_salt_size <= len(params.salt) <= policy.max_salt_size:
        raise VaultFormatError("KDF salt has an invalid length")
    if not 1 <= params.lanes <= policy.max_lanes:
        raise VaultFormatError("KDF parallelism is out of range")
    if not 1 <= params.iterations <= policy.max_iterations:
        raise VaultFormatError("KDF iteration count is out of range")
    if params.memory_kib > policy.max_memory_kib:
        raise VaultFormatError("KDF memory cost exceeds the supported maximum")
    if params.memory_kib < 8 * params.lanes:
        raise VaultFormatError("KDF memory cost is below the Argon2 minimum (8 KiB per lane)")
    if params.memory_kib < policy.min_memory_kib or params.memory_kib * params.iterations < policy.min_work:
        raise WeakKdfError(
            "the vault header requests KDF parameters below the security floor; "
            "refusing to process the master password with them"
        )


def normalize_password(password: str) -> bytes:
    """Encode a password to bytes deterministically across platforms.

    Unicode NFC normalization matters for non-ASCII passwords. Greek accented
    letters can be typed as one precomposed code point or as base letter plus
    combining accent, depending on the OS and keyboard layout. Without
    normalization the same visible password would derive a different key on
    another machine.
    """
    return unicodedata.normalize("NFC", password).encode("utf-8")


def keyfile_secret(path: Path) -> bytes:
    """Read a keyfile and reduce it to the 32-byte secret fed to Argon2id.

    Any file of 32 bytes to 1 MiB works. Hashing with a domain-separation prefix
    means the raw contents never reach the KDF and arbitrary files are usable.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise VaultError(f"cannot read keyfile: {exc.strerror or exc}") from exc
    if size < MIN_KEYFILE_SIZE:
        raise VaultError(f"keyfile is too small (minimum {MIN_KEYFILE_SIZE} bytes)")
    if size > MAX_KEYFILE_SIZE:
        raise VaultError("keyfile is too large (maximum 1 MiB)")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise VaultError(f"cannot read keyfile: {exc.strerror or exc}") from exc
    return hashlib.sha256(_KEYFILE_DOMAIN + data).digest()


def generate_keyfile_bytes() -> bytes:
    return os.urandom(64)


def derive_kek(password: str, params: KdfParams, keyfile: bytes | None = None) -> bytearray:
    """Run Argon2id. The keyfile secret goes in Argon2's dedicated ``secret`` input."""
    try:
        kdf = Argon2id(
            salt=params.salt,
            length=KEY_SIZE,
            iterations=params.iterations,
            lanes=params.lanes,
            memory_cost=params.memory_kib,
            secret=keyfile,
        )
        return bytearray(kdf.derive(normalize_password(password)))
    except UnsupportedAlgorithm as exc:
        raise VaultError(
            "Argon2id is unavailable in this build of 'cryptography' "
            "(it needs OpenSSL 3.2+); install the official wheel: pip install -U cryptography"
        ) from exc
    except MemoryError as exc:
        raise VaultError(f"not enough memory to derive the key ({params.memory_mib:.0f} MiB required)") from exc


def random_key() -> bytearray:
    return bytearray(os.urandom(KEY_SIZE))


def new_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def encrypt(key: bytes | bytearray, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM. Returns ``nonce || ciphertext || tag``."""
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes | bytearray, blob: bytes, aad: bytes) -> bytes:
    """Inverse of :func:`encrypt`. Raises :class:`DecryptionFailed` on any mismatch."""
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise DecryptionFailed
    try:
        return AESGCM(bytes(key)).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad)
    except InvalidTag as exc:
        raise DecryptionFailed from exc


def zeroize(buffer: bytearray) -> None:
    """Overwrite a mutable buffer in place (best effort; see module docstring)."""
    buffer[:] = bytes(len(buffer))


def default_memory_kib() -> int:
    """Pick Argon2 memory: a quarter of available RAM, clamped to [64 MiB, 1 GiB].

    The result is rounded down to a power of two so the stored values look
    deliberate and are reproducible.
    """
    floor, ceiling = 64 * MIB_IN_KIB, 1024 * MIB_IN_KIB
    available = osutil.available_memory_bytes()
    target = available // 4 // 1024 if available else 256 * MIB_IN_KIB
    target = max(floor, min(ceiling, target))
    return 1 << (target.bit_length() - 1)


def calibrate_kdf(
    target_seconds: float = DEFAULT_UNLOCK_SECONDS,
    *,
    memory_kib: int | None = None,
    lanes: int = DEFAULT_LANES,
    policy: KdfPolicy = DEFAULT_POLICY,
) -> KdfParams:
    """Choose iterations so that unlocking takes about ``target_seconds`` here.

    Memory hardness is what hurts GPU and ASIC attackers, so memory is fixed
    first and time is tuned with iterations. The result never drops below the
    policy floor.
    """
    memory = memory_kib if memory_kib is not None else default_memory_kib()
    probe = KdfParams(new_salt(), memory, 1, lanes)
    start = time.perf_counter()
    derive_kek("calibration-probe", probe)
    elapsed = max(time.perf_counter() - start, 1e-3)
    min_iterations = max(1, math.ceil(policy.min_work / memory))
    iterations = round(target_seconds / elapsed)
    iterations = max(min_iterations, min(_MAX_CALIBRATED_ITERATIONS, iterations))
    params = KdfParams(new_salt(), memory, iterations, lanes)
    check_kdf_params(params, policy)
    return params
