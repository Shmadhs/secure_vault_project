"""Vault-level dialogs: new vault, master-password change, backups/restore, audit, preferences."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHeaderView,
    QLabel,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import crypto, storage
from ..audit import DEFAULT_MAX_AGE_DAYS, audit
from ..cli import MIN_MASTER_BITS, create_keyfile
from ..errors import AuthenticationError, IntegrityError, VaultConflictError, VaultError
from ..model import Entry
from ..vault import Vault, restore_backup
from . import ui
from .guards import CAPTURE_EXCLUSION_SUPPORTED
from .prefs import Preferences
from .session import Session
from .widgets import NewMasterPassword, PathField, SecretField

KEYFILE_FILTER = "Keyfiles (*.key *.keyfile);;All files (*)"
VAULT_FILTER = "SecureVault vaults (*.svault);;All files (*)"


def describe(exc: BaseException) -> str:
    """A user-facing, display-safe description of an error."""
    if isinstance(exc, OSError):
        where = f" ({exc.filename})" if exc.filename else ""
        return ui.display(f"{exc.strerror or exc}{where}")
    return ui.display(str(exc))


def _error_label(parent: QWidget) -> QLabel:
    label = ui.plain_label("", parent)
    label.setWordWrap(True)
    label.setStyleSheet("color: #c0392b;")
    return label


def _unlock_time_box(parent: QWidget) -> QDoubleSpinBox:
    box = QDoubleSpinBox(parent)
    box.setRange(0.5, 10.0)
    box.setSingleStep(0.5)
    box.setSuffix(" s")
    box.setValue(crypto.DEFAULT_UNLOCK_SECONDS)
    return box


def _confirm_weak(parent: QWidget, master: NewMasterPassword) -> bool:
    bits = master.weak_bits()
    if bits is None:
        return True
    return ui.ask(
        parent,
        "Weak master password",
        f"That password is weak (about {bits:.0f} bits; at least {MIN_MASTER_BITS:.0f} recommended). "
        "A six-word passphrase is easy to remember and much stronger.\n\nUse it anyway?",
    )


class NewVaultDialog(QDialog):
    """``svault init``: choose a path and a master password, optionally create a keyfile."""

    def __init__(self, default_path: Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("New vault")
        self.setMinimumWidth(520)
        self.vault: Vault | None = None
        self.keyfile_path: Path | None = None

        self.path = PathField("Create vault", VAULT_FILTER, save=True, parent=self)
        self.path.set_path(default_path)
        self.master = NewMasterPassword(self)
        self.with_keyfile = QCheckBox("Also create and require a keyfile (a second factor)", self)
        self.keyfile = PathField("Create keyfile", KEYFILE_FILTER, save=True, parent=self)
        self.keyfile.setEnabled(False)
        self.with_keyfile.toggled.connect(self.keyfile.setEnabled)
        self.unlock_time = _unlock_time_box(self)
        self.error = _error_label(self)

        form = QFormLayout()
        form.addRow("Vault file:", self.path)
        form.addRow("Unlock time:", self.unlock_time)
        password_box = QGroupBox("Master password", self)
        QVBoxLayout(password_box).addWidget(self.master)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel, self)
        self.create_button = buttons.addButton("Create vault", QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self.try_accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(password_box)
        layout.addWidget(self.with_keyfile)
        layout.addWidget(self.keyfile)
        layout.addWidget(self.error)
        layout.addWidget(buttons)

    def try_accept(self) -> None:
        path = self.path.path()
        try:
            if path is None:
                raise ValueError("Choose where to create the vault.")
            if path.exists():
                raise ValueError(f"A vault already exists at {path}.")
            password = self.master.password()
            keyfile_path = self.keyfile.path() if self.with_keyfile.isChecked() else None
            if self.with_keyfile.isChecked() and keyfile_path is None:
                raise ValueError("Choose where to create the keyfile.")
            if keyfile_path is not None and keyfile_path.resolve() == path.resolve():
                raise ValueError("The keyfile and the vault must be different files.")
        except ValueError as exc:
            self.error.setText(ui.display(str(exc)))
            return
        if not _confirm_weak(self, self.master):
            return
        seconds = self.unlock_time.value()
        try:
            keyfile: bytes | None = None
            if keyfile_path is not None:
                create_keyfile(keyfile_path)
                keyfile = crypto.keyfile_secret(keyfile_path)

            def work() -> Vault:
                kdf = crypto.calibrate_kdf(seconds)
                return Vault.create(path, password, kdf=kdf, keyfile=keyfile)

            self.vault = ui.run_blocking(self, "Calibrating key derivation and creating the vault…", work)
        except (VaultError, ValueError, OSError) as exc:
            self.error.setText(describe(exc))
            return
        self.keyfile_path = keyfile_path
        if keyfile_path is not None:
            ui.info(
                self,
                "Keyfile created",
                f"Created the keyfile {keyfile_path}.\n\nBack it up offline: without it the vault cannot be opened.",
            )
        self.accept()

    def done(self, result: int) -> None:
        self.master.clear()
        super().done(result)


class PasswdDialog(QDialog):
    """``svault passwd``: rotate the vault key under a new master password (and keyfile choice).

    Unlike ``svault shell``, the current password is asked for again. Anyone
    who finds the window unlocked could otherwise change it and lock the owner
    out of their own vault.
    """

    def __init__(self, session: Session, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Change master password")
        self.setMinimumWidth(520)
        self._session = session
        self.removed_backups = 0
        self.conflict: VaultConflictError | None = None

        self.current = SecretField("Current master password", self)
        self.master = NewMasterPassword(self)
        uses = session.vault.uses_keyfile
        self.keep_keyfile = QRadioButton("Keep the current keyfile" if uses else "No keyfile", self)
        self.new_keyfile = QRadioButton("Create a new keyfile and require it", self)
        self.remove_keyfile = QRadioButton("Stop requiring a keyfile", self)
        self.remove_keyfile.setEnabled(uses)
        group = QButtonGroup(self)
        for button in (self.keep_keyfile, self.new_keyfile, self.remove_keyfile):
            group.addButton(button)
        self.keep_keyfile.setChecked(True)
        self.keyfile = PathField("Create keyfile", KEYFILE_FILTER, save=True, parent=self)
        self.keyfile.setEnabled(False)
        self.new_keyfile.toggled.connect(self.keyfile.setEnabled)
        self.recalibrate = QCheckBox("Re-tune Argon2id for this computer", self)
        self.unlock_time = _unlock_time_box(self)
        self.error = _error_label(self)

        keyfile_box = QGroupBox("Keyfile", self)
        keyfile_layout = QVBoxLayout(keyfile_box)
        for widget in (self.keep_keyfile, self.new_keyfile, self.keyfile, self.remove_keyfile):
            keyfile_layout.addWidget(widget)
        password_box = QGroupBox("New master password", self)
        QVBoxLayout(password_box).addWidget(self.master)
        form = QFormLayout()
        form.addRow("Current password:", self.current)
        form.addRow(self.recalibrate, self.unlock_time)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel, self)
        buttons.addButton("Change password", QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self.try_accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(password_box)
        layout.addWidget(keyfile_box)
        layout.addWidget(
            ui.plain_label(
                "The vault key is rotated and everything re-encrypted. Old backups are deleted, "
                "because they are encrypted under the old key.",
                self,
            )
        )
        layout.addWidget(self.error)
        layout.addWidget(buttons)

    def try_accept(self) -> None:
        session = self._session
        try:
            current = self.current.text()
            if not current:
                raise ValueError("Enter the current master password.")
            password = self.master.password()
            new_keyfile = self.keyfile.path() if self.new_keyfile.isChecked() else None
            if self.new_keyfile.isChecked():
                if new_keyfile is None:
                    raise ValueError("Choose where to create the new keyfile.")
                if new_keyfile.exists():
                    raise ValueError(f"{new_keyfile} already exists; refusing to overwrite a keyfile.")
        except ValueError as exc:
            self.error.setText(ui.display(str(exc)))
            return
        if not _confirm_weak(self, self.master):
            return
        try:
            ui.run_blocking(self, "Checking the current password…", lambda: session.verify_password(current))
        except AuthenticationError:
            self.current.clear()
            self.error.setText("The current master password (or keyfile) is wrong.")
            return
        except (VaultError, OSError) as exc:
            self.error.setText(describe(exc))
            return
        seconds = self.unlock_time.value() if self.recalibrate.isChecked() else None
        try:
            if new_keyfile is not None:
                create_keyfile(new_keyfile)
                keyfile = crypto.keyfile_secret(new_keyfile)
            elif self.remove_keyfile.isChecked():
                keyfile = None
            else:
                keyfile = session.keyfile()

            def work() -> int:
                kdf = crypto.calibrate_kdf(seconds) if seconds else None
                return session.vault.change_master_password(password, keyfile=keyfile, kdf=kdf)

            self.removed_backups = ui.run_blocking(self, "Re-encrypting the vault under a new key…", work)
        except VaultConflictError as exc:
            self.conflict = exc
            self.reject()
            return
        except (VaultError, ValueError, OSError) as exc:
            self.error.setText(describe(exc))
            return
        if new_keyfile is not None:
            session.keyfile_path = new_keyfile
        elif self.remove_keyfile.isChecked():
            session.keyfile_path = None
        self.accept()

    def done(self, result: int) -> None:
        self.current.clear()
        self.master.clear()
        super().done(result)


class BackupsDialog(QDialog):
    """``svault backups`` / ``svault restore``: list the encrypted backups and restore one.

    Reachable from the unlock screen as well, because an integrity failure means
    the vault cannot be unlocked, and that is exactly when a restore is needed.
    """

    def __init__(self, vault_path: Path, keyfile_path: Path | None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Encrypted backups")
        self.setMinimumWidth(560)
        self._vault_path = vault_path
        self.restored: tuple[str, int] | None = None
        self._backups = storage.list_backups(vault_path)

        self.table = QTableWidget(len(self._backups), 3, self)
        self.table.setHorizontalHeaderLabels(["Backup", "Saved", "Size"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        for row, path in enumerate(self._backups):
            try:
                stat = path.stat()
                saved = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                size = f"{stat.st_size} bytes"
            except OSError:  # removed by another process since it was listed
                saved, size = "?", "?"
            for column, text in enumerate((path.name, saved, size)):
                self.table.setItem(row, column, QTableWidgetItem(ui.display(text)))
        if self._backups:
            self.table.selectRow(0)

        self.password = SecretField("Master password of the backup", self)
        self.keyfile = PathField("Keyfile", KEYFILE_FILTER, parent=self)
        self.keyfile.set_path(keyfile_path)
        self.error = _error_label(self)
        self.restore_button = QPushButton("Restore selected backup…", self)
        self.restore_button.clicked.connect(self.restore)
        self.restore_button.setEnabled(bool(self._backups))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        buttons.rejected.connect(self.reject)

        where = ui.display(str(storage.backup_dir(vault_path)))
        heading = (
            f"Encrypted backups of {ui.display(vault_path.name)}, newest first, in {where}."
            if self._backups
            else f"No backups in {where}."
        )
        layout = QVBoxLayout(self)
        layout.addWidget(ui.plain_label(heading, self))
        layout.addWidget(self.table)
        form = QFormLayout()
        form.addRow("Password:", self.password)
        form.addRow("Keyfile:", self.keyfile)
        layout.addLayout(form)
        layout.addWidget(self.error)
        layout.addWidget(self.restore_button)
        layout.addWidget(buttons)

    def selected(self) -> Path | None:
        rows = self.table.selectionModel().selectedRows()
        return self._backups[rows[0].row()] if rows else None

    def restore(self) -> None:
        backup = self.selected()
        password = self.password.text()
        if backup is None:
            self.error.setText("Select a backup first.")
            return
        if not password:
            self.error.setText("Enter the master password the backup was saved with.")
            return
        shown = ui.display(backup.name)
        if not ui.ask(
            self,
            "Restore backup",
            f"Replace {ui.display(self._vault_path.name)} with {shown}?\n\n"
            "The backup is verified first, and the current file is kept as a new backup.",
        ):
            return
        keyfile_path = self.keyfile.path()
        try:
            keyfile = crypto.keyfile_secret(keyfile_path) if keyfile_path else None
            count = ui.run_blocking(
                self,
                "Verifying and restoring the backup…",
                lambda: restore_backup(self._vault_path, backup, password, keyfile=keyfile),
            )
        except AuthenticationError:
            self.password.clear()
            self.error.setText("Wrong master password or keyfile for this backup.")
            return
        except IntegrityError as exc:
            self.error.setText(f"This backup is damaged and was not restored: {describe(exc)}")
            return
        except (VaultError, OSError) as exc:
            self.error.setText(describe(exc))
            return
        self.restored = (shown, count)
        self.accept()

    def done(self, result: int) -> None:
        self.password.clear()
        super().done(result)


class AuditDialog(QDialog):
    """``svault audit``: reused, weak, empty and stale passwords. Double-click jumps to the entry."""

    def __init__(self, entries: Iterable[Entry], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Password health")
        self.resize(720, 420)
        self._entries = list(entries)
        self.selected_id: str | None = None

        self.max_age = QSpinBox(self)
        self.max_age.setRange(1, 36500)
        self.max_age.setValue(DEFAULT_MAX_AGE_DAYS)
        self.max_age.setSuffix(" days")
        self.max_age.valueChanged.connect(self.refresh)
        self.summary = ui.plain_label("", self)
        self.table = QTableWidget(0, 3, self)
        self.table.setHorizontalHeaderLabels(["Finding", "Entry", "Detail"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.cellDoubleClicked.connect(self._jump)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        buttons.rejected.connect(self.reject)
        form = QFormLayout()
        form.addRow("Flag passwords unchanged for more than:", self.max_age)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.summary)
        layout.addWidget(self.table)
        layout.addWidget(buttons)
        self.refresh()

    def refresh(self) -> None:
        findings = audit(self._entries, max_age_days=self.max_age.value())
        self.table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            kind = QTableWidgetItem(finding.kind.upper())
            kind.setData(Qt.ItemDataRole.UserRole, finding.entry.id)
            self.table.setItem(row, 0, kind)
            self.table.setItem(row, 1, QTableWidgetItem(ui.display(finding.entry.title)))
            self.table.setItem(row, 2, QTableWidgetItem(ui.display(finding.detail)))
        if not findings:
            self.summary.setText(f"All {len(self._entries)} entries look healthy.")
            return
        kinds = sorted({f.kind for f in findings})
        counts = ", ".join(f"{k}={sum(f.kind == k for f in findings)}" for k in kinds)
        self.summary.setText(f"{len(findings)} finding(s): {counts}. Double-click one to select the entry.")

    def _jump(self, row: int, _column: int) -> None:
        item = self.table.item(row, 0)
        if item is not None:
            self.selected_id = str(item.data(Qt.ItemDataRole.UserRole))
            self.accept()

    def done(self, result: int) -> None:
        self._entries = []
        self.table.setRowCount(0)
        super().done(result)


class PreferencesDialog(QDialog):
    def __init__(self, prefs: Preferences, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Preferences")
        self._prefs = prefs
        self.idle = QSpinBox(self)
        self.idle.setRange(0, 240)
        self.idle.setSuffix(" min")
        self.idle.setSpecialValueText("never (not recommended)")
        self.idle.setValue(prefs.idle_minutes)
        self.lock_on_minimize = QCheckBox("Lock when the window is minimized", self)
        self.lock_on_minimize.setChecked(prefs.lock_on_minimize)
        self.clear_seconds = QSpinBox(self)
        self.clear_seconds.setRange(0, 3600)
        self.clear_seconds.setSuffix(" s")
        self.clear_seconds.setSpecialValueText("never")
        self.clear_seconds.setValue(prefs.clear_seconds)
        self.hide_from_capture = QCheckBox("Hide windows from screenshots and screen sharing", self)
        self.hide_from_capture.setChecked(prefs.hide_from_capture)
        self.hide_from_capture.setVisible(CAPTURE_EXCLUSION_SUPPORTED)
        form = QFormLayout()
        form.addRow("Auto-lock after:", self.idle)
        form.addRow("", self.lock_on_minimize)
        form.addRow("Clear the clipboard after:", self.clear_seconds)
        form.addRow("", self.hide_from_capture)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def preferences(self) -> Preferences:
        return replace(
            self._prefs,
            idle_minutes=self.idle.value(),
            lock_on_minimize=self.lock_on_minimize.isChecked(),
            clear_seconds=self.clear_seconds.value(),
            hide_from_capture=self.hide_from_capture.isChecked(),
        )
