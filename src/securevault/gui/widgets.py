"""Reusable input widgets: secret fields, file pickers and the new-master-password form."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFontDatabase, QKeyEvent, QKeySequence
from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QStackedWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .. import generator
from ..cli import MIN_MASTER_BITS
from .ui import plain_label

MASTER_PASSPHRASE_WORDS = 6


class _NoCopyLineEdit(QLineEdit):
    """A line edit whose text cannot be copied, cut or dragged out, even when shown.

    Qt already blocks copying in password mode, but not once the text is
    revealed. Ctrl+C would then put the secret on the system clipboard without
    the Windows history and cloud-sync exclusion or the auto-clear that every
    other copy in SecureVault gets.
    """

    _BLOCKED = (QKeySequence.StandardKey.Copy, QKeySequence.StandardKey.Cut)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setDragEnabled(False)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if any(event.matches(key) for key in self._BLOCKED):
            event.accept()
            return
        super().keyPressEvent(event)


class SecretField(QWidget):
    """A secret line edit (password mode) with a reveal toggle; its text never reaches the clipboard."""

    textChanged = Signal(str)

    def __init__(self, placeholder: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.edit = _NoCopyLineEdit(self)
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.setPlaceholderText(placeholder)
        self.edit.textChanged.connect(self.textChanged)
        self.reveal = QToolButton(self)
        self.reveal.setText("Show")
        self.reveal.setCheckable(True)
        self.reveal.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.reveal.toggled.connect(self._on_reveal)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.edit)
        layout.addWidget(self.reveal)
        self.setFocusProxy(self.edit)

    def _on_reveal(self, shown: bool) -> None:
        self.edit.setEchoMode(QLineEdit.EchoMode.Normal if shown else QLineEdit.EchoMode.Password)
        self.reveal.setText("Hide" if shown else "Show")

    def text(self) -> str:
        return self.edit.text()

    def setText(self, text: str) -> None:
        self.edit.setText(text)

    def clear(self) -> None:
        self.reveal.setChecked(False)
        self.edit.clear()


class PathField(QWidget):
    """A path line edit with a Browse button."""

    def __init__(self, caption: str, file_filter: str, *, save: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._caption, self._filter, self._save = caption, file_filter, save
        self.edit = QLineEdit(self)
        browse = QPushButton("Browse…", self)
        browse.clicked.connect(self._browse)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.edit)
        layout.addWidget(browse)
        self.setFocusProxy(self.edit)

    def _browse(self) -> None:
        start = self.edit.text().strip()
        if self._save:
            chosen, _ = QFileDialog.getSaveFileName(self, self._caption, start, self._filter)
        else:
            chosen, _ = QFileDialog.getOpenFileName(self, self._caption, start, self._filter)
        if chosen:
            self.edit.setText(str(Path(chosen)))

    def path(self) -> Path | None:
        text = self.edit.text().strip()
        return Path(text) if text else None

    def set_path(self, path: Path | None) -> None:
        self.edit.setText(str(path) if path else "")


class NewMasterPassword(QWidget):
    """Choose a new master password, offering a generated passphrase first (as ``svault init`` does)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.generate_radio = QRadioButton(
            f"Generate a {MASTER_PASSPHRASE_WORDS}-word passphrase for me "
            f"({generator.passphrase_entropy(MASTER_PASSPHRASE_WORDS):.0f} bits)",
            self,
        )
        self.own_radio = QRadioButton("Choose my own password", self)
        group = QButtonGroup(self)
        group.addButton(self.generate_radio)
        group.addButton(self.own_radio)
        self.generate_radio.setChecked(True)

        # Generated passphrase. Deliberately not selectable: it belongs on paper,
        # not in the clipboard history.
        generated = QWidget(self)
        self.phrase_label = plain_label("", generated)
        self.phrase_label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font.setPointSize(font.pointSize() + 3)
        self.phrase_label.setFont(font)
        again = QPushButton("Another one", generated)
        again.clicked.connect(self.regenerate)
        self.typeback = SecretField("Type it back from where you wrote it", generated)
        gen_layout = QVBoxLayout(generated)
        gen_layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        row.addWidget(self.phrase_label, 1)
        row.addWidget(again)
        gen_layout.addLayout(row)
        gen_layout.addWidget(
            plain_label(
                "Write it on paper and keep it somewhere safe. It cannot be recovered: there is no 'forgot password'.",
                generated,
            )
        )
        gen_layout.addWidget(self.typeback)

        own = QWidget(self)
        self.first = SecretField("New master password", own)
        self.repeat = SecretField("Repeat it", own)
        self.strength = plain_label("", own)
        self.strength.setWordWrap(True)
        self.first.textChanged.connect(self._update_strength)
        own_layout = QFormLayout(own)
        own_layout.setContentsMargins(0, 0, 0, 0)
        own_layout.addRow("Password:", self.first)
        own_layout.addRow("Repeat:", self.repeat)
        own_layout.addRow("", self.strength)

        self._pages = QStackedWidget(self)
        self._pages.addWidget(generated)
        self._pages.addWidget(own)
        self.own_radio.toggled.connect(lambda on: self._pages.setCurrentIndex(1 if on else 0))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.generate_radio)
        layout.addWidget(self.own_radio)
        layout.addWidget(self._pages)
        self._phrase = ""
        self.regenerate()

    def regenerate(self) -> None:
        self._phrase = generator.generate_passphrase(MASTER_PASSPHRASE_WORDS)
        self.phrase_label.setText(self._phrase)
        self.typeback.clear()

    def _update_strength(self, text: str) -> None:
        if not text:
            self.strength.setText("")
            return
        bits = generator.estimate_strength(text)
        note = (
            f" Weak: at least {MIN_MASTER_BITS:.0f} recommended. A six-word passphrase is easy to "
            "remember and much stronger."
            if bits < MIN_MASTER_BITS
            else ""
        )
        self.strength.setText(f"About {bits:.0f} bits.{note}")

    @property
    def generating(self) -> bool:
        return self.generate_radio.isChecked()

    def password(self) -> str:
        """The chosen password. Raises ValueError with a message for the user if it is not acceptable."""
        if self.generating:
            if self.typeback.text() != self._phrase:
                raise ValueError("The passphrase you typed back does not match. Check what you wrote down.")
            return self._phrase
        first = self.first.text()
        if not first:
            raise ValueError("The master password must not be empty.")
        if self.repeat.text() != first:
            raise ValueError("The passwords do not match.")
        return first

    def weak_bits(self) -> float | None:
        """The estimated strength if the user's own password is below the recommended minimum."""
        if self.generating:
            return None
        bits = generator.estimate_strength(self.first.text())
        return bits if bits < MIN_MASTER_BITS else None

    def clear(self) -> None:
        self.typeback.clear()
        self.first.clear()
        self.repeat.clear()
        self.phrase_label.clear()
        self._phrase = ""
