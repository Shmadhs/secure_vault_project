"""Add, edit and delete dialogs.

The editor shows the stored values *raw*, not escaped. If it showed the
``display()`` form, saving an untouched field would write the escape text
(``\\u202e``) back as literal characters and silently corrupt the entry. So
the fields hold the real values, a warning appears when one of them contains
control or bidi characters, and only fields the user actually changed are
written back.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .. import totp
from ..cli import split_tags
from ..errors import VaultError
from ..model import Entry, validate_title
from . import ui
from .generator_dialog import GeneratorDialog
from .widgets import SecretField


@dataclass
class EntryForm:
    """The values to write. ``None`` means "leave unchanged"; ``totp=""`` removes the secret."""

    title: str | None = None
    username: str | None = None
    password: str | None = None
    url: str | None = None
    notes: str | None = None
    tags: list[str] | None = None
    totp: str | None = None

    def is_empty(self) -> bool:
        return all(value is None for value in vars(self).values())


class EntryDialog(QDialog):
    """Add (``entry is None``) or edit an entry.

    ``apply`` performs the change and saves. It raises for anything the user can
    correct (duplicate title, disk error), and the dialog then stays open with
    the input intact. It returns False if the vault had to be locked instead.
    """

    def __init__(
        self,
        apply: Callable[[EntryForm], bool],
        copy: Callable[[str, str], None],
        entry: Entry | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._apply, self._copy = apply, copy
        # A snapshot, not the live entry: if a save fails, the session rolls the
        # contents back by replacing the entries, and the object that was being
        # edited keeps the half-applied change. Comparing against it would make
        # a second Save look like "nothing changed" and silently drop the edit.
        self._original = deepcopy(entry)
        self.setWindowTitle("Edit entry" if entry else "Add password")
        self.setMinimumWidth(460)

        self.title = QLineEdit(self)
        self.username = QLineEdit(self)
        self.password = SecretField("", self)
        generate = QPushButton("Generate…", self)
        generate.clicked.connect(self._generate)
        password_row = QHBoxLayout()
        password_row.addWidget(self.password, 1)
        password_row.addWidget(generate)
        self.url = QLineEdit(self)
        self.tags = QLineEdit(self)
        self.tags.setPlaceholderText("comma-separated")
        self.totp = SecretField("TOTP secret or otpauth:// URI", self)
        self.remove_totp = QCheckBox("Remove the TOTP secret", self)
        self.remove_totp.toggled.connect(self.totp.setDisabled)
        self.notes = QPlainTextEdit(self)
        self.notes.setTabChangesFocus(True)
        self.notice = ui.plain_label("", self)
        self.notice.setWordWrap(True)
        self.notice.hide()
        self.error = ui.plain_label("", self)
        self.error.setWordWrap(True)
        self.error.setStyleSheet("color: #c0392b;")

        form = QFormLayout()
        form.addRow("Title:", self.title)
        form.addRow("Username:", self.username)
        form.addRow("Password:", password_row)
        form.addRow("URL:", self.url)
        form.addRow("Tags:", self.tags)
        form.addRow("TOTP:", self.totp)
        form.addRow("", self.remove_totp)
        form.addRow("Notes:", self.notes)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel, self
        )
        self.buttons.accepted.connect(self.try_accept)
        self.buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(self.notice)
        layout.addLayout(form)
        layout.addWidget(self.error)
        layout.addWidget(self.buttons)

        if entry is None:
            self.remove_totp.hide()
        else:
            self._load(entry)

    def _load(self, entry: Entry) -> None:
        self.title.setText(entry.title)
        self.username.setText(entry.username)
        self.password.setText(entry.password)
        self.url.setText(entry.url)
        self.tags.setText(", ".join(entry.tags))
        self.notes.setPlainText(entry.notes)
        if entry.totp:
            self.totp.edit.setPlaceholderText("configured; leave empty to keep it")
        else:
            self.remove_totp.hide()
        risky = [entry.title, entry.username, entry.url, entry.notes, *entry.tags]
        if any(ui.has_unsafe(value) for value in risky):
            self.notice.setText(
                "Warning: this entry contains control or bidirectional-override characters, "
                "which can make text look different from what it is. The detail view shows them "
                "escaped. Fields you do not change are kept exactly as stored."
            )
            self.notice.show()

    def _generate(self) -> None:
        dialog = GeneratorDialog(self._copy, use_button=True, parent=self)
        try:
            if ui.run_dialog(dialog) and dialog.value:
                self.password.setText(dialog.value)
        finally:
            dialog.deleteLater()

    def form(self) -> EntryForm:
        """Collect the changes. Raises ValueError with a user-facing message on invalid input."""
        title = validate_title(self.title.text())
        secret = self.totp.text().strip()
        if secret:
            totp.parse(secret)  # validate before storing, as the CLI does
        values = EntryForm(
            title=title,
            username=self.username.text(),
            password=self.password.text(),
            url=self.url.text(),
            notes=self.notes.toPlainText(),
            tags=split_tags(self.tags.text()),
            totp=secret,
        )
        old = self._original
        if old is None:
            return values
        return EntryForm(
            title=title if self.title.text() != old.title else None,
            username=values.username if values.username != old.username else None,
            password=values.password if values.password != old.password else None,
            url=values.url if values.url != old.url else None,
            notes=values.notes if values.notes != old.notes else None,
            tags=values.tags if self.tags.text() != ", ".join(old.tags) else None,
            totp="" if self.remove_totp.isChecked() else (secret or None),
        )

    def try_accept(self) -> None:
        try:
            values = self.form()
            if not values.is_empty() and not self._apply(values):
                return  # the vault was locked, which already closed this dialog
        except (ValueError, VaultError, OSError) as exc:
            detail = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
            self.error.setText(ui.display(detail))
            return
        self.accept()

    def done(self, result: int) -> None:
        self.password.clear()
        self.totp.clear()
        self.notes.clear()
        self._original = None
        super().done(result)


class DeleteDialog(QDialog):
    """Deletion needs the title typed exactly as displayed, like ``svault rm`` needs the exact title."""

    def __init__(self, shown_title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Delete entry")
        self._expected = shown_title
        self.confirm = QLineEdit(self)
        self.confirm.setPlaceholderText("type the title to confirm")
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel, self)
        self.delete_button = self.buttons.addButton("Delete", QDialogButtonBox.ButtonRole.DestructiveRole)
        self.delete_button.setEnabled(False)
        self.delete_button.clicked.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.confirm.textChanged.connect(lambda text: self.delete_button.setEnabled(text == self._expected))
        layout = QVBoxLayout(self)
        layout.addWidget(
            ui.plain_label(
                "This deletes the entry from the vault. A previous version remains in the "
                "encrypted backups.\n\nType its title exactly as shown to confirm:",
                self,
            )
        )
        shown = ui.plain_label(shown_title, self)
        font = shown.font()
        font.setBold(True)
        shown.setFont(font)
        layout.addWidget(shown)
        layout.addWidget(self.confirm)
        layout.addWidget(self.buttons)

    def accept(self) -> None:
        if self.confirm.text() == self._expected:  # the button state is not the only gate
            super().accept()
