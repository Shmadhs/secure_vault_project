"""The unlocked vault: ties the format, cryptography and storage together.

Key hierarchy::

    master password --+
                      +--> Argon2id --> KEK --unwraps--> vault key --decrypts--> payload
    keyfile (opt.) ---+   (salt, m, t, p from header)  (random 256-bit)

The vault key is random, not derived from the password. Changing the password
still rotates it (see :meth:`Vault.change_master_password`). The indirection is
what makes multiple key slots possible: a recovery key or a hardware token can
each wrap the same vault key.
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from dataclasses import replace
from pathlib import Path

from . import crypto, storage
from .crypto import DEFAULT_POLICY, KdfParams, KdfPolicy
from .errors import (
    AuthenticationError,
    IntegrityError,
    VaultConflictError,
    VaultError,
    VaultExistsError,
)
from .model import Entry, VaultContents
from .vault_format import MAX_VAULT_SIZE, Header, KeySlot, decode_payload, encode_payload, parse_file


def _wrap_vault_key(
    vault_id: str, vault_key: bytearray, password: str, kdf: KdfParams, keyfile: bytes | None
) -> KeySlot:
    slot = KeySlot(kdf=kdf, keyfile=keyfile is not None, wrapped_key=b"")
    kek = crypto.derive_kek(password, kdf, keyfile)
    try:
        wrapped = crypto.encrypt(kek, bytes(vault_key), slot.aad(vault_id))
    finally:
        crypto.zeroize(kek)
    return replace(slot, wrapped_key=wrapped)


def read_header(path: Path) -> Header:
    """Parse the plaintext header without unlocking. Used by ``svault info``."""
    return parse_file(storage.read_file(path, MAX_VAULT_SIZE)).header


class Vault:
    """An unlocked vault. Construct it with :meth:`create` or :meth:`open`.

    Locking and saving are serialized by a mutex. The interactive shell locks
    the vault from a timer thread, and without the mutex a lock landing in the
    middle of a save could zeroize the key while it is in use. The file would
    then be written under an all-zero key and the user's data lost.
    """

    def __init__(
        self,
        path: Path,
        header: Header,
        vault_key: bytearray,
        contents: VaultContents,
        disk_digest: bytes,
    ) -> None:
        self.path = path
        self._header = header
        self._key: bytearray | None = vault_key
        self._contents: VaultContents | None = contents
        self._disk_digest = disk_digest
        self._mutex = threading.RLock()

    # ------------------------------------------------------------------ lifecycle

    @classmethod
    def create(
        cls,
        path: Path,
        password: str,
        *,
        kdf: KdfParams,
        keyfile: bytes | None = None,
        policy: KdfPolicy = DEFAULT_POLICY,
    ) -> Vault:
        if path.exists():
            raise VaultExistsError(f"a vault already exists at {path}")
        if not password:
            raise VaultError("the master password must not be empty")
        crypto.check_kdf_params(kdf, policy)
        vault_id = uuid.uuid4().hex
        vault_key = crypto.random_key()
        slot = _wrap_vault_key(vault_id, vault_key, password, kdf, keyfile)
        vault = cls(path, Header(vault_id, (slot,)), vault_key, VaultContents(), b"")
        vault._write()
        return vault

    @classmethod
    def open(
        cls,
        path: Path,
        password: str,
        *,
        keyfile: bytes | None = None,
        policy: KdfPolicy = DEFAULT_POLICY,
    ) -> Vault:
        data = storage.read_file(path, MAX_VAULT_SIZE)
        parsed = parse_file(data)
        header = parsed.header
        vault_key = cls._unwrap(header, password, keyfile, policy)
        try:
            plaintext = crypto.decrypt(vault_key, parsed.payload, parsed.header_block)
        except crypto.DecryptionFailed:
            crypto.zeroize(vault_key)
            raise IntegrityError(
                "the master key is correct but the vault failed its integrity check: "
                "the file was modified or damaged. Restore it from a backup."
            ) from None
        try:
            contents = VaultContents.from_payload(decode_payload(plaintext))
        except BaseException:
            crypto.zeroize(vault_key)
            raise
        return cls(path, header, vault_key, contents, hashlib.sha256(data).digest())

    @staticmethod
    def _unwrap(header: Header, password: str, keyfile: bytes | None, policy: KdfPolicy) -> bytearray:
        needs_keyfile = False
        for slot in header.slots:
            # Validate parameters *before* the KDF touches the password.
            crypto.check_kdf_params(slot.kdf, policy)
            if slot.keyfile and keyfile is None:
                needs_keyfile = True
                continue
            kek = crypto.derive_kek(password, slot.kdf, keyfile if slot.keyfile else None)
            try:
                return bytearray(crypto.decrypt(kek, slot.wrapped_key, slot.aad(header.vault_id)))
            except crypto.DecryptionFailed:
                continue
            finally:
                crypto.zeroize(kek)
        if needs_keyfile:
            raise AuthenticationError("this vault requires a keyfile (use --keyfile)")
        raise AuthenticationError("wrong master password or keyfile")

    def lock(self) -> None:
        """Forget the key and the decrypted contents. Safe to call from another thread."""
        with self._mutex:
            key, self._key = self._key, None
            self._contents = None
            if key is not None:
                crypto.zeroize(key)

    @property
    def locked(self) -> bool:
        return self._key is None

    def __enter__(self) -> Vault:
        return self

    def __exit__(self, *exc: object) -> None:
        self.lock()

    # ------------------------------------------------------------------ accessors

    @property
    def contents(self) -> VaultContents:
        if self._contents is None:
            raise VaultError("the vault is locked")
        return self._contents

    @property
    def header(self) -> Header:
        return self._header

    @property
    def kdf(self) -> KdfParams:
        return self._header.slots[0].kdf

    @property
    def uses_keyfile(self) -> bool:
        return any(slot.keyfile for slot in self._header.slots)

    def add(self, entry: Entry) -> Entry:
        return self.contents.add(entry)

    def find(self, query: str) -> Entry:
        return self.contents.find(query)

    # ------------------------------------------------------------------ persistence

    def save(self, *, backups: int = storage.DEFAULT_BACKUPS) -> None:
        """Encrypt and write the vault, refusing if another process changed the file.

        The check is optimistic concurrency: we remember the hash of what we
        read and compare it before writing. Otherwise a long-running shell and a
        one-off command could silently overwrite each other's changes.
        """
        with self._mutex:
            if self._key is None:
                raise VaultError("the vault is locked")
            if self.path.exists():
                current = storage.read_file(self.path, MAX_VAULT_SIZE)
                if hashlib.sha256(current).digest() != self._disk_digest:
                    raise VaultConflictError(
                        "the vault file was changed by another process since it was opened; "
                        "re-open it and repeat the change"
                    )
                storage.make_backup(self.path, current, backups)
            self._write()

    def _write(self) -> None:
        with self._mutex:
            key = self._key
            if key is None:
                raise VaultError("the vault is locked")
            block = self._header.block()
            payload = crypto.encrypt(key, encode_payload(self.contents.to_payload()), block)
            data = block + payload
            storage.atomic_write(self.path, data)
            self._disk_digest = hashlib.sha256(data).digest()

    def change_master_password(self, new_password: str, *, keyfile: bytes | None, kdf: KdfParams | None = None) -> int:
        """Re-key the vault. Returns the number of old backups removed.

        This rotates the vault key, not just the password. If only the key were
        re-wrapped, anyone holding an old copy of the file plus the old password
        could unwrap the unchanged vault key and decrypt every future version.
        Rotating costs one re-encryption of a small payload.
        """
        if not new_password:
            raise VaultError("the master password must not be empty")
        old = self.kdf
        params = kdf or KdfParams(crypto.new_salt(), old.memory_kib, old.iterations, old.lanes)
        new_key = crypto.random_key()
        slot = _wrap_vault_key(self._header.vault_id, new_key, new_password, params, keyfile)
        with self._mutex:
            if self._key is None:
                crypto.zeroize(new_key)
                raise VaultError("the vault is locked")
            old_key, old_header = self._key, self._header
            self._key, self._header = new_key, Header(self._header.vault_id, (slot,))
            try:
                self.save(backups=0)
            except BaseException:
                crypto.zeroize(new_key)
                self._key, self._header = old_key, old_header
                raise
            crypto.zeroize(old_key)
            return storage.purge_backups(self.path)


def restore_backup(
    path: Path,
    backup: Path,
    password: str,
    *,
    keyfile: bytes | None = None,
    policy: KdfPolicy = DEFAULT_POLICY,
) -> int:
    """Replace the vault with a backup, after proving the backup is intact.

    The backup is fully opened first (KDF, unwrap, payload authentication), so a
    damaged or foreign file can never overwrite the vault. The current vault, if
    readable at all, is kept as a new backup, which makes the restore reversible.
    Returns the number of entries in the restored vault.
    """
    data = storage.read_file(backup, MAX_VAULT_SIZE)
    with Vault.open(backup, password, keyfile=keyfile, policy=policy) as restored:
        count = len(restored.contents)
    if path.exists():
        storage.make_backup(path, storage.read_file(path, MAX_VAULT_SIZE), storage.DEFAULT_BACKUPS + 1)
    storage.atomic_write(path, data)
    return count
