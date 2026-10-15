"""The unlocked state of the GUI, kept free of Qt so it can be reasoned about (and tested) on its own.

A :class:`Session` wraps one unlocked :class:`~securevault.vault.Vault`. It
remembers the keyfile's *path*, never its bytes: the CLI re-reads the keyfile
whenever it needs it, and so does the GUI, so the derived secret does not sit in
memory for the whole session.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from .. import crypto
from ..model import VaultContents
from ..vault import Vault

T = TypeVar("T")


class Session:
    def __init__(self, vault: Vault, keyfile_path: Path | None) -> None:
        self.vault = vault
        self.keyfile_path = keyfile_path

    @property
    def path(self) -> Path:
        return self.vault.path

    @property
    def locked(self) -> bool:
        return self.vault.locked

    @property
    def contents(self) -> VaultContents:
        return self.vault.contents

    def keyfile(self) -> bytes | None:
        """The keyfile secret, re-read from disk, or None if the vault does not use one."""
        if not self.vault.uses_keyfile or self.keyfile_path is None:
            return None
        return crypto.keyfile_secret(self.keyfile_path)

    def verify_password(self, password: str) -> None:
        """Raise :class:`AuthenticationError` unless ``password`` (and the keyfile) open the vault.

        It opens the file a second time and locks that copy at once. Used to
        re-authenticate before changing the master password.
        """
        Vault.open(self.path, password, keyfile=self.keyfile()).lock()

    def commit(self, change: Callable[[VaultContents], T]) -> T:
        """Apply ``change`` to the contents and save, or leave the contents as they were.

        In the CLI a failed save ends the process, so the half-applied change
        dies with it. The GUI keeps running, and without a rollback it would
        show an edit that is not on disk, which the next successful save would
        then persist unannounced. The snapshot restores the entries, so the
        caller must re-read them (the old ``Entry`` objects are replaced).
        """
        contents = self.vault.contents
        snapshot = copy.deepcopy(contents.entries)
        try:
            result = change(contents)
            self.vault.save()
        except BaseException:
            contents.entries[:] = snapshot
            raise
        return result

    def lock(self) -> None:
        self.vault.lock()
