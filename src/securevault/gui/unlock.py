"""The unlock screen: vault file, master password and optional keyfile.

Failures are reported the way the CLI's exit codes separate them, because
they call for different actions:

* wrong password or keyfile: routine, try again;
* integrity failure: the key was right but the file was modified or damaged,
  so restore a backup (offered right here, since the vault will not open);
* KDF below the security floor: a genuine vault never has that, so the file
  may have been swapped for one built to make the password cheap to crack;
* not a vault at all, or written by a newer version.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFormLayout, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from .. import crypto, osutil
from ..errors import AuthenticationError, IntegrityError, VaultError, VaultFormatError, WeakKdfError
from ..vault import Vault, read_header
from . import ui
from .session import Session
from .vault_dialogs import KEYFILE_FILTER, VAULT_FILTER, BackupsDialog, NewVaultDialog, describe
from .widgets import PathField, SecretField


class UnlockView(QWidget):
    def __init__(
        self,
        vault_path: Path,
        keyfile_path: Path | None,
        on_unlocked: Callable[[Session], None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._on_unlocked = on_unlocked
        self.path = PathField("Open vault", VAULT_FILTER, parent=self)
        self.path.set_path(vault_path)
        self.password = SecretField("Master password", self)
        self.password.edit.returnPressed.connect(self.try_unlock)
        self.keyfile = PathField("Keyfile", KEYFILE_FILTER, parent=self)
        self.keyfile.set_path(keyfile_path)
        self.error = ui.plain_label("", self)
        self.error.setWordWrap(True)
        self.error.setStyleSheet("color: #c0392b;")
        self.notice = ui.plain_label("", self)
        self.notice.setWordWrap(True)
        self.unlock_button = QPushButton("Unlock", self)
        self.unlock_button.setDefault(True)
        self.unlock_button.clicked.connect(self.try_unlock)
        new_button = QPushButton("New vault…", self)
        new_button.clicked.connect(self.new_vault)
        backups_button = QPushButton("Backups…", self)
        backups_button.clicked.connect(self.open_backups)
        self.path.edit.editingFinished.connect(self._check_path)

        heading = ui.plain_label("SecureVault is locked", self)
        font = heading.font()
        font.setPointSize(font.pointSize() + 6)
        heading.setFont(font)
        form = QFormLayout()
        form.addRow("Vault file:", self.path)
        form.addRow("Master password:", self.password)
        form.addRow("Keyfile (optional):", self.keyfile)
        row = QHBoxLayout()
        row.addWidget(new_button)
        row.addWidget(backups_button)
        row.addStretch(1)
        row.addWidget(self.unlock_button)
        box = QWidget(self)
        box.setMinimumWidth(560)
        box.setMaximumWidth(720)
        inner = QVBoxLayout(box)
        inner.addWidget(heading)
        inner.addLayout(form)
        inner.addWidget(self.notice)
        inner.addWidget(self.error)
        inner.addLayout(row)
        outer = QVBoxLayout(self)
        outer.addStretch(1)
        outer.addWidget(box, 0, Qt.AlignmentFlag.AlignHCenter)
        outer.addStretch(2)
        self._check_path()

    def reset(self) -> None:
        self.password.clear()
        self.error.clear()
        self._check_path()
        self.password.setFocus()

    def _check_path(self) -> None:
        path = self.path.path()
        notes = []
        if path is not None and not path.exists():
            notes.append("There is no vault at this path yet. Create one with New vault…")
        elif path is not None and osutil.is_group_or_world_accessible(path):
            notes.append("Warning: this vault file is readable by other users (chmod 600 it).")
        self.notice.setText(ui.display(" ".join(notes)))
        self.notice.setVisible(bool(notes))

    def _fail(self, text: str) -> None:
        self.password.clear()
        self.error.setText(text)
        self.password.setFocus()

    def try_unlock(self) -> None:
        path = self.path.path()
        password = self.password.text()
        keyfile_path = self.keyfile.path()
        self.error.clear()
        if path is None:
            self.error.setText("Choose the vault file.")
            return
        if not path.exists():
            self.error.setText(ui.display(f"There is no vault at {path}. Create one with New vault…"))
            return
        if not password:
            self.error.setText("Enter the master password.")
            return
        try:
            header = read_header(path)
            if keyfile_path is None and all(slot.keyfile for slot in header.slots):
                self.error.setText("This vault requires its keyfile as well. Choose it under Keyfile.")
                return
            keyfile = crypto.keyfile_secret(keyfile_path) if keyfile_path else None
            vault = ui.run_blocking(self, "Unlocking (Argon2id)…", lambda: Vault.open(path, password, keyfile=keyfile))
        except AuthenticationError:
            self._fail("Wrong master password or keyfile.")
            return
        except IntegrityError as exc:
            self._fail("Integrity failure: the vault was modified or damaged.")
            self._offer_restore("Integrity failure", f"INTEGRITY FAILURE\n\n{describe(exc)}")
            return
        except WeakKdfError as exc:
            self._fail("Refused to open the vault: its key-derivation settings are below the security floor.")
            self._offer_restore(
                "Suspicious vault file",
                f"{describe(exc)}.\n\nA genuine SecureVault never writes such parameters, so this file "
                "may have been replaced by one built to make your password cheap to crack. Your "
                "password was not processed.",
            )
            return
        except VaultFormatError as exc:
            self._fail(f"This is not a vault SecureVault can open: {describe(exc)}")
            return
        except (VaultError, OSError) as exc:
            self._fail(describe(exc))
            return
        self.password.clear()
        self.error.clear()
        self._on_unlocked(Session(vault, keyfile_path))

    def _offer_restore(self, title: str, text: str) -> None:
        if ui.ask(self, title, text + "\n\nOpen the encrypted backups to restore one?", icon=ui.Icon.Critical):
            self.open_backups()

    def open_backups(self) -> None:
        path = self.path.path()
        if path is None:
            self.error.setText("Choose the vault file first.")
            return
        dialog = BackupsDialog(path, self.keyfile.path(), self)
        try:
            if ui.run_dialog(dialog) and dialog.restored:
                name, count = dialog.restored
                ui.info(self, "Backup restored", f"Restored {count} entries from {name}. Unlock to open it.")
                self.reset()
        finally:
            dialog.deleteLater()

    def new_vault(self) -> None:
        default = self.path.path() or osutil.default_vault_path()
        if default.exists():
            default = default.with_name("new-vault.svault")
        dialog = NewVaultDialog(default, self)
        try:
            if ui.run_dialog(dialog) and dialog.vault is not None:
                self.path.set_path(dialog.vault.path)
                self.keyfile.set_path(dialog.keyfile_path)
                self._on_unlocked(Session(dialog.vault, dialog.keyfile_path))
        finally:
            dialog.deleteLater()
