from __future__ import annotations

import hashlib
import unicodedata
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from securevault import crypto
from securevault.crypto import DEFAULT_POLICY, KdfParams, KdfPolicy, check_kdf_params
from securevault.errors import VaultError, VaultFormatError, WeakKdfError


def test_argon2id_rfc9106_known_answer() -> None:
    """RFC 9106 section 5.3: proves the installed OpenSSL backend computes real Argon2id."""
    kdf = Argon2id(
        salt=b"\x02" * 16,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=32,
        ad=b"\x04" * 12,
        secret=b"\x03" * 8,
    )
    expected = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    assert kdf.derive(b"\x01" * 32).hex() == expected


def test_derive_kek_matches_raw_argon2id_with_secret() -> None:
    params = KdfParams(b"s" * 16, memory_kib=64, iterations=1, lanes=1)
    raw = Argon2id(salt=params.salt, length=32, iterations=1, lanes=1, memory_cost=64, secret=b"k" * 32)
    assert bytes(crypto.derive_kek("pw", params, b"k" * 32)) == raw.derive(b"pw")


def test_keyfile_changes_the_key() -> None:
    params = KdfParams(b"s" * 16, memory_kib=64, iterations=1, lanes=1)
    assert crypto.derive_kek("pw", params) != crypto.derive_kek("pw", params, b"k" * 32)


def test_password_is_nfc_normalized() -> None:
    params = KdfParams(b"s" * 16, memory_kib=64, iterations=1, lanes=1)
    composed = "Κωδικός-άλφα"
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed
    assert crypto.derive_kek(composed, params) == crypto.derive_kek(decomposed, params)


def test_aead_roundtrip_and_tamper_detection() -> None:
    key = crypto.random_key()
    blob = crypto.encrypt(key, b"secret", b"aad")
    assert crypto.decrypt(key, blob, b"aad") == b"secret"
    with pytest.raises(crypto.DecryptionFailed):
        crypto.decrypt(key, blob, b"other aad")
    with pytest.raises(crypto.DecryptionFailed):
        crypto.decrypt(crypto.random_key(), blob, b"aad")
    for i in range(len(blob)):
        flipped = bytearray(blob)
        flipped[i] ^= 0x01
        with pytest.raises(crypto.DecryptionFailed):
            crypto.decrypt(key, bytes(flipped), b"aad")
    with pytest.raises(crypto.DecryptionFailed):
        crypto.decrypt(key, blob[:20], b"aad")


def test_nonces_are_fresh() -> None:
    key = crypto.random_key()
    nonces = {crypto.encrypt(key, b"x", b"")[: crypto.NONCE_SIZE] for _ in range(200)}
    assert len(nonces) == 200


def test_zeroize() -> None:
    buf = bytearray(b"secret-key-material")
    crypto.zeroize(buf)
    assert buf == bytearray(len(b"secret-key-material"))


@pytest.mark.parametrize(
    ("params", "error"),
    [
        (KdfParams(b"s" * 8, 65536, 3, 4), VaultFormatError),  # salt too short
        (KdfParams(b"s" * 16, 65536, 3, 0), VaultFormatError),  # no lanes
        (KdfParams(b"s" * 16, 65536, 3, 17), VaultFormatError),  # too many lanes
        (KdfParams(b"s" * 16, 65536, 0, 4), VaultFormatError),  # zero iterations
        (KdfParams(b"s" * 16, 65536, 65, 4), VaultFormatError),  # absurd iterations (DoS)
        (KdfParams(b"s" * 16, 8 * 1024 * 1024, 1, 4), VaultFormatError),  # 8 GiB (DoS)
        (KdfParams(b"s" * 16, 32 * 1024, 3, 4), WeakKdfError),  # below memory floor
        (KdfParams(b"s" * 16, 65536, 2, 4), WeakKdfError),  # below work floor
    ],
)
def test_kdf_policy_rejects(params: KdfParams, error: type[Exception]) -> None:
    with pytest.raises(error):
        check_kdf_params(params, DEFAULT_POLICY)


@pytest.mark.parametrize(
    "params",
    [
        KdfParams(b"s" * 16, 65536, 3, 4),  # RFC 9106 second recommendation
        KdfParams(b"s" * 32, 1024 * 1024, 1, 4),  # 1 GiB, one pass
        KdfParams(b"s" * 32, 2 * 1024 * 1024, 1, 4),  # RFC 9106 first recommendation
    ],
)
def test_kdf_policy_accepts_rfc_recommendations(params: KdfParams) -> None:
    check_kdf_params(params, DEFAULT_POLICY)


def test_calibration_respects_floor() -> None:
    params = crypto.calibrate_kdf(0.01, memory_kib=64 * 1024, lanes=1)
    check_kdf_params(params, DEFAULT_POLICY)
    assert params.iterations >= 3
    assert len(params.salt) == crypto.SALT_SIZE


def test_calibration_gives_fresh_salt() -> None:
    policy = KdfPolicy(min_memory_kib=8, min_work=8)
    a = crypto.calibrate_kdf(0.01, memory_kib=64, lanes=1, policy=policy)
    b = crypto.calibrate_kdf(0.01, memory_kib=64, lanes=1, policy=policy)
    assert a.salt != b.salt


def test_default_memory_is_power_of_two_in_range() -> None:
    kib = crypto.default_memory_kib()
    assert 64 * 1024 <= kib <= 1024 * 1024
    assert kib & (kib - 1) == 0


def test_keyfile_secret(tmp_path: Path) -> None:
    keyfile = tmp_path / "key"
    keyfile.write_bytes(b"x" * 64)
    secret = crypto.keyfile_secret(keyfile)
    assert len(secret) == 32
    # Domain separated: the KDF never sees a plain hash of the file.
    assert secret != hashlib.sha256(b"x" * 64).digest()


@pytest.mark.parametrize("size", [0, 31, (1 << 20) + 1])
def test_keyfile_size_limits(tmp_path: Path, size: int) -> None:
    keyfile = tmp_path / "key"
    keyfile.write_bytes(b"x" * size)
    with pytest.raises(VaultError):
        crypto.keyfile_secret(keyfile)


def test_missing_keyfile(tmp_path: Path) -> None:
    with pytest.raises(VaultError, match="cannot read keyfile"):
        crypto.keyfile_secret(tmp_path / "missing")
