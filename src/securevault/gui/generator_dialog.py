"""Password and passphrase generator with an entropy readout (``svault gen`` in a window)."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QTextOption
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import generator
from ..cli import MIN_MASTER_BITS
from .ui import display, plain_label

DEFAULT_LENGTH = 24
DEFAULT_WORDS = 6


class GeneratorDialog(QDialog):
    """Generate a value. ``copy`` copies through the core clipboard; with ``use_button`` the
    dialog can also hand the value back to an entry editor.
    """

    def __init__(
        self,
        copy: Callable[[str, str], None],
        *,
        use_button: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Generate a password")
        self._copy = copy
        self._value = ""

        self.tabs = QTabWidget(self)
        password_tab = QWidget(self)
        self.length = QSpinBox(password_tab)
        self.length.setRange(generator.MIN_LENGTH, generator.MAX_LENGTH)
        self.length.setValue(DEFAULT_LENGTH)
        self.use_lower = QCheckBox("Lowercase a–z", password_tab)
        self.use_upper = QCheckBox("Uppercase A–Z", password_tab)
        self.use_digits = QCheckBox("Digits 0–9", password_tab)
        self.use_symbols = QCheckBox("Symbols", password_tab)
        self.ambiguous = QCheckBox("Avoid look-alikes (l, 1, O, 0…)", password_tab)
        for box in (self.use_lower, self.use_upper, self.use_digits, self.use_symbols):
            box.setChecked(True)
        form = QFormLayout(password_tab)
        form.addRow("Length:", self.length)
        for box in (self.use_lower, self.use_upper, self.use_digits, self.use_symbols, self.ambiguous):
            form.addRow("", box)
        self.tabs.addTab(password_tab, "Password")

        phrase_tab = QWidget(self)
        self.words = QSpinBox(phrase_tab)
        self.words.setRange(1, generator.MAX_WORDS)
        self.words.setValue(DEFAULT_WORDS)
        self.separator = QLineEdit("-", phrase_tab)
        self.separator.setMaxLength(8)
        self.capitalize = QCheckBox("Capitalize words", phrase_tab)
        form = QFormLayout(phrase_tab)
        form.addRow("Words:", self.words)
        form.addRow("Separator:", self.separator)
        form.addRow("", self.capitalize)
        self.tabs.addTab(phrase_tab, "Passphrase")

        # Shown, but not selectable: copying goes through the Copy button and the
        # core clipboard (auto-clear, history exclusion), never through Ctrl+C.
        self.output = QPlainTextEdit(self)
        self.output.setReadOnly(True)
        self.output.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        self.output.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        self.output.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.output.setMaximumHeight(80)
        self.entropy = plain_label("", self)
        self.entropy.setWordWrap(True)

        buttons = QDialogButtonBox(self)
        regenerate = QPushButton("Regenerate", self)
        regenerate.clicked.connect(self.regenerate)
        self.copy_button = QPushButton("Copy", self)
        self.copy_button.clicked.connect(self._on_copy)
        buttons.addButton(regenerate, QDialogButtonBox.ButtonRole.ActionRole)
        buttons.addButton(self.copy_button, QDialogButtonBox.ButtonRole.ActionRole)
        self.use_button: QPushButton | None = None
        if use_button:
            self.use_button = QPushButton("Use this", self)
            self.use_button.setDefault(True)
            self.use_button.clicked.connect(self.accept)
            buttons.addButton(self.use_button, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton(QDialogButtonBox.StandardButton.Close).clicked.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.tabs)
        layout.addWidget(self.output)
        layout.addWidget(self.entropy)
        layout.addWidget(buttons)

        for spin in (self.length, self.words):
            spin.valueChanged.connect(self.regenerate)
        for box in (self.use_lower, self.use_upper, self.use_digits, self.use_symbols, self.ambiguous, self.capitalize):
            box.toggled.connect(self.regenerate)
        self.separator.textChanged.connect(self.regenerate)
        self.tabs.currentChanged.connect(self.regenerate)
        self.regenerate()

    @property
    def value(self) -> str:
        return self._value

    def regenerate(self) -> None:
        try:
            if self.tabs.currentIndex() == 1:
                count = self.words.value()
                value = generator.generate_passphrase(
                    count, self.separator.text(), capitalize=self.capitalize.isChecked()
                )
                bits = generator.passphrase_entropy(count)
            else:
                options = {
                    "lower": self.use_lower.isChecked(),
                    "upper": self.use_upper.isChecked(),
                    "digits": self.use_digits.isChecked(),
                    "symbols": self.use_symbols.isChecked(),
                    "exclude_ambiguous": self.ambiguous.isChecked(),
                }
                classes = generator.build_alphabet(**options)
                value = generator.generate_password(self.length.value(), **options)
                bits = generator.password_entropy(self.length.value(), len("".join(classes)))
        except ValueError as exc:
            self._set_value("", f"Cannot generate: {exc}.")
            return
        note = (
            f" Below the {MIN_MASTER_BITS:.0f} bits recommended for anything important."
            if bits < MIN_MASTER_BITS
            else ""
        )
        self._set_value(value, f"Entropy: {bits:.0f} bits.{note}")

    def _set_value(self, value: str, status: str) -> None:
        self._value = value
        self.output.setPlainText(display(value))
        self.entropy.setText(status)
        self.copy_button.setEnabled(bool(value))
        if self.use_button is not None:
            self.use_button.setEnabled(bool(value))

    def _on_copy(self) -> None:
        if self._value:
            self._copy(self._value, "the generated value")

    def done(self, result: int) -> None:
        if result != QDialog.DialogCode.Accepted:
            self._value = ""
        self.output.clear()
        super().done(result)
