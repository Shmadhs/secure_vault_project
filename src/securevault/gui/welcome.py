"""First run: no vault yet, so welcome the user instead of showing a lock screen.

A lock screen with nothing behind it, and a disabled "Add password" button,
is a dead end. Here the first step is the only one that matters: choosing the
master password. Where the vault is saved, a keyfile and the unlock time are
folded away under "Advanced"; the defaults are right for almost everyone.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from . import ui
from .session import Session
from .unlock import heading, link_button
from .vault_dialogs import NewVaultForm


class WelcomeView(QWidget):
    def __init__(
        self,
        vault_path: Path,
        on_created: Callable[[Session], None],
        on_have_vault: Callable[[], None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._on_created = on_created
        self.form = NewVaultForm(vault_path, self)
        self.create_button = QPushButton("Create my vault", self)
        self.create_button.setDefault(True)
        self.create_button.clicked.connect(self.create_vault)
        self.have_vault = link_button("I already have a vault…", self)
        self.have_vault.clicked.connect(on_have_vault)

        buttons = QHBoxLayout()
        buttons.addWidget(self.have_vault)
        buttons.addStretch(1)
        buttons.addWidget(self.create_button)
        box = QWidget(self)
        box.setMinimumWidth(560)
        box.setMaximumWidth(680)
        inner = QVBoxLayout(box)
        inner.setSpacing(12)
        inner.addWidget(heading("Welcome to SecureVault", box))
        intro = ui.plain_label(
            "A password manager that keeps everything on this computer: no cloud, no account. "
            "Start by choosing the master password that will unlock it.",
            box,
        )
        intro.setWordWrap(True)
        inner.addWidget(intro)
        inner.addWidget(self.form)
        inner.addLayout(buttons)
        outer = QVBoxLayout(self)
        outer.addStretch(1)
        outer.addWidget(box, 0, Qt.AlignmentFlag.AlignHCenter)
        outer.addStretch(2)

    def reset(self, vault_path: Path) -> None:
        """Show a fresh suggestion each time; nothing from a previous visit lingers."""
        self.form.clear()
        self.form.path.set_path(vault_path)
        self.form.master.regenerate()

    def leave(self) -> None:
        self.form.clear()

    def create_vault(self) -> None:
        created = self.form.create_vault()
        if created is None:
            return
        vault, keyfile_path = created
        self.form.clear()
        self._on_created(Session(vault, keyfile_path))
