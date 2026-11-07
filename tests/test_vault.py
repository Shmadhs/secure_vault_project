from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from securevault import storage
from securevault.crypto import KdfParams
from securevault.errors import (
    AuthenticationError,
    IntegrityError,
    VaultConflictError,
    VaultError,
    VaultExistsError,
    WeakKdfError,
)
from securevault.model import Entry
from securevault.vault import Vault, read_header
from securevault.vault_format import Header, parse_file

from .conftest import FAST_POLICY, PASSWORD


def _make(path: Path, kdf: KdfParams, keyfile: bytes | None = None) -> Vault:
    vault = Vault.create(path, PASSWORD, kdf=kdf, keyfile=keyfile, policy=FAST_POLICY)
    vault.add(Entry("GitHub", username="kostas", password="gh-secret", tags=["dev"]))
    vault.add(Entry("Τράπεζα", username="κώστας", password="πάσσγουορντ", notes="PIN στο χαρτί"))
    vault.save()
    return vault


def _open(path: Path, password: str = PASSWORD, keyfile: bytes | None = None) -> Vault:
    return Vault.open(path, password, keyfile=keyfile, policy=FAST_POLICY)


def test_roundtrip(vault_path: Path, fast_kdf: KdfParams) -> None:
    _make(vault_path, fast_kdf).lock()
    vault = _open(vault_path)
    assert [e.title for e in vault.contents] == ["GitHub", "Τράπεζα"]
    assert vault.find("τράπεζα").password == "πάσσγουορντ"
    assert vault.find("github").tags == ["dev"]


def test_nothing_secret_in_plaintext(vault_path: Path, fast_kdf: KdfParams) -> None:
    _make(vault_path, fast_kdf)
    raw = vault_path.read_bytes()
    for needle in ("GitHub", "kostas", "gh-secret", "Τράπεζα"):
        assert needle.encode("utf-8") not in raw


def test_unknown_fields_survive_a_save(vault_path: Path, fast_kdf: KdfParams) -> None:
    vault = _make(vault_path, fast_kdf)
    vault.find("GitHub").extra["future_field"] = {"x": 1}
    vault.contents.extra["future_top"] = [1, 2]
    vault.save()
    reopened = _open(vault_path)
    assert reopened.find("GitHub").extra == {"future_field": {"x": 1}}
    assert reopened.contents.extra == {"future_top": [1, 2]}


def test_wrong_password(vault_path: Path, fast_kdf: KdfParams) -> None:
    _make(vault_path, fast_kdf)
    with pytest.raises(AuthenticationError):
        _open(vault_path, "wrong")


def test_create_refuses_to_overwrite(vault_path: Path, fast_kdf: KdfParams) -> None:
    _make(vault_path, fast_kdf)
    with pytest.raises(VaultExistsError):
        Vault.create(vault_path, PASSWORD, kdf=fast_kdf, policy=FAST_POLICY)


def test_empty_master_password_rejected(vault_path: Path, fast_kdf: KdfParams) -> None:
    with pytest.raises(VaultError):
        Vault.create(vault_path, "", kdf=fast_kdf, policy=FAST_POLICY)


def test_production_policy_rejects_cheap_vault(vault_path: Path, fast_kdf: KdfParams) -> None:
    """A substituted vault with cheap KDF settings is refused before the KDF runs."""
    _make(vault_path, fast_kdf)
    with pytest.raises(WeakKdfError):
        Vault.open(vault_path, PASSWORD)


def test_keyfile_required(vault_path: Path, fast_kdf: KdfParams) -> None:
    keyfile = os.urandom(32)
    _make(vault_path, fast_kdf, keyfile=keyfile).lock()
    with pytest.raises(AuthenticationError, match="requires a keyfile"):
        _open(vault_path)
    with pytest.raises(AuthenticationError):
        _open(vault_path, keyfile=os.urandom(32))
    with pytest.raises(AuthenticationError):
        _open(vault_path, "wrong", keyfile=keyfile)
    assert _open(vault_path, keyfile=keyfile).uses_keyfile


def test_payload_tamper_is_integrity_error(vault_path: Path, fast_kdf: KdfParams) -> None:
    _make(vault_path, fast_kdf)
    data = bytearray(vault_path.read_bytes())
    data[-1] ^= 0x80
    vault_path.write_bytes(bytes(data))
    with pytest.raises(IntegrityError):
        _open(vault_path)


def test_header_from_another_vault_is_rejected(tmp_path: Path, fast_kdf: KdfParams) -> None:
    a, b = tmp_path / "a.svault", tmp_path / "b.svault"
    _make(a, fast_kdf)
    _make(b, KdfParams(os.urandom(32), 256, 1, 1))
    pa, pb = parse_file(a.read_bytes()), parse_file(b.read_bytes())
    # B's header (which unwraps fine) on A's payload: payload authentication fails.
    (tmp_path / "mixed.svault").write_bytes(pb.header_block + pa.payload)
    with pytest.raises(IntegrityError):
        _open(tmp_path / "mixed.svault")


def test_slot_cannot_be_moved_to_another_vault_id(vault_path: Path, fast_kdf: KdfParams) -> None:
    _make(vault_path, fast_kdf)
    parsed = parse_file(vault_path.read_bytes())
    forged = Header(vault_id="f" * 32, slots=parsed.header.slots)
    vault_path.write_bytes(forged.block() + parsed.payload)
    with pytest.raises(AuthenticationError):
        _open(vault_path)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.data())
def test_any_single_bit_flip_is_detected(tmp_path: Path, data: st.DataObject) -> None:
    """Property: corrupting any bit anywhere makes opening fail, never return data."""
    path = tmp_path / "flip.svault"
    if not path.exists():
        _make(path, KdfParams(b"\x07" * 32, 256, 1, 1)).lock()
    original = path.read_bytes()
    index = data.draw(st.integers(0, len(original) - 1))
    bit = data.draw(st.integers(0, 7))
    corrupted = bytearray(original)
    corrupted[index] ^= 1 << bit
    target = tmp_path / "corrupted.svault"
    target.write_bytes(bytes(corrupted))
    with pytest.raises(VaultError):
        _open(target)


def test_every_truncation_is_detected(vault_path: Path, fast_kdf: KdfParams) -> None:
    _make(vault_path, fast_kdf)
    original = vault_path.read_bytes()
    target = vault_path.with_name("cut.svault")
    for size in range(0, len(original), 37):
        target.write_bytes(original[:size])
        with pytest.raises(VaultError):
            _open(target)


def test_concurrent_modification_detected(vault_path: Path, fast_kdf: KdfParams) -> None:
    _make(vault_path, fast_kdf).lock()
    first, second = _open(vault_path), _open(vault_path)
    first.add(Entry("A"))
    first.save()
    second.add(Entry("B"))
    with pytest.raises(VaultConflictError):
        second.save()
    assert [e.title for e in _open(vault_path).contents] == ["A", "GitHub", "Τράπεζα"]


def test_change_master_password_rotates_key(vault_path: Path, fast_kdf: KdfParams) -> None:
    vault = _make(vault_path, fast_kdf)
    vault.save()  # creates a backup
    assert storage.list_backups(vault_path)
    before = parse_file(vault_path.read_bytes())
    removed = vault.change_master_password("new password", keyfile=None)
    after = parse_file(vault_path.read_bytes())
    assert removed >= 1
    assert storage.list_backups(vault_path) == []
    assert before.header.vault_id == after.header.vault_id
    assert before.header.slots[0].kdf.salt != after.header.slots[0].kdf.salt
    with pytest.raises(AuthenticationError):
        _open(vault_path)
    reopened = _open(vault_path, "new password")
    assert reopened.find("GitHub").password == "gh-secret"


def test_old_password_plus_old_file_cannot_decrypt_new_file(vault_path: Path, fast_kdf: KdfParams) -> None:
    """After a password change, the old vault key no longer decrypts the new payload."""
    vault = _make(vault_path, fast_kdf)
    old_copy = vault_path.read_bytes()
    vault.change_master_password("new password", keyfile=None)
    old, new = parse_file(old_copy), parse_file(vault_path.read_bytes())
    mixed = vault_path.with_name("mixed.svault")
    mixed.write_bytes(old.header_block + new.payload)
    with pytest.raises(IntegrityError):
        _open(mixed)


def test_change_password_can_add_and_remove_keyfile(vault_path: Path, fast_kdf: KdfParams) -> None:
    vault = _make(vault_path, fast_kdf)
    keyfile = os.urandom(32)
    vault.change_master_password("with keyfile", keyfile=keyfile)
    assert read_header(vault_path).slots[0].keyfile
    vault = _open(vault_path, "with keyfile", keyfile=keyfile)
    vault.change_master_password("no keyfile", keyfile=None)
    assert not read_header(vault_path).slots[0].keyfile
    assert _open(vault_path, "no keyfile").find("GitHub")


def test_failed_rekey_keeps_old_state(vault_path: Path, fast_kdf: KdfParams, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = _make(vault_path, fast_kdf)

    def boom(*_: object, **__: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(storage, "atomic_write", boom)
    with pytest.raises(OSError, match="disk full"):
        vault.change_master_password("new", keyfile=None)
    monkeypatch.undo()
    assert _open(vault_path).find("GitHub")
    vault.save()  # in-memory state still uses the old, valid key
    assert _open(vault_path).find("GitHub")


def test_crash_during_write_leaves_original(
    vault_path: Path, fast_kdf: KdfParams, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _make(vault_path, fast_kdf)
    original = vault_path.read_bytes()

    def fail_replace(*_: object) -> None:
        raise OSError("power loss")

    monkeypatch.setattr(os, "replace", fail_replace)
    vault.add(Entry("New"))
    with pytest.raises(OSError, match="power loss"):
        vault.save(backups=0)
    monkeypatch.undo()
    assert vault_path.read_bytes() == original
    assert not list(vault_path.parent.glob("*.tmp"))


def test_backups_are_rotated(vault_path: Path, fast_kdf: KdfParams) -> None:
    vault = _make(vault_path, fast_kdf)
    for i in range(6):
        vault.add(Entry(f"E{i}"))
        vault.save(backups=3)
    backups = storage.list_backups(vault_path)
    assert len(backups) == 3
    # Backups are complete encrypted vaults that open with the same password.
    assert len(_open(backups[0]).contents) == 7


def test_lock_wipes_key(vault_path: Path, fast_kdf: KdfParams) -> None:
    vault = _make(vault_path, fast_kdf)
    key = vault._key
    assert key is not None
    vault.lock()
    assert key == bytearray(len(key))
    assert vault.locked
    with pytest.raises(VaultError, match="locked"):
        _ = vault.contents
    with pytest.raises(VaultError, match="locked"):
        vault.save()


def test_context_manager_locks(vault_path: Path, fast_kdf: KdfParams) -> None:
    with _make(vault_path, fast_kdf) as vault:
        assert not vault.locked
    assert vault.locked


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(VaultError, match="no vault"):
        _open(tmp_path / "nope.svault")
