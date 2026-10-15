"""Fixtures for the GUI tests (pytest-qt, headless).

* Qt runs on the ``offscreen`` platform, so no display is needed (CI, SSH).
* The real clipboard is never touched: ``clipboard.get_clipboard`` and the
  detached clearing helper are replaced, while ``copy_with_autoclear`` and
  ``clear_if_unchanged`` themselves run unmodified.
* Message boxes and dialogs are scripted through the two hooks every window
  uses (``ui.message`` and ``ui.run_dialog``), so the dialogs' own validation
  and accept logic is what gets exercised. All three fixtures are autouse: a
  real modal dialog would block a headless test forever, and an unexpected
  one now fails the test instead.
* Vaults use the cheapest parameters the *production* KDF policy allows
  (64 MiB, t=3): the GUI never weakens that policy, so neither do its tests.
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QDialog, QMessageBox, QWidget
from pytestqt.qtbot import QtBot

from securevault import clipboard, crypto
from securevault.crypto import KdfParams
from securevault.gui import ui
from securevault.gui.main_window import MainWindow
from securevault.model import Entry
from securevault.vault import Vault

PW = "Κύριος-gui-correct-horse-battery"
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # b"12345678901234567890", RFC 6238 Appendix B
REAL_MESSAGE = ui.message  # captured before the autouse fixture replaces it


def policy_floor_kdf() -> KdfParams:
    return KdfParams(crypto.new_salt(), memory_kib=64 * 1024, iterations=3, lanes=1)


@dataclass
class FakeClipboard:
    text: str = ""
    scheduled: list[tuple[str, int]] = field(default_factory=list)
    name: str = "fake"

    def copy(self, text: str) -> None:
        self.text = text

    def paste(self) -> str:
        return self.text

    def clear(self) -> None:
        self.text = ""


@dataclass
class Messages:
    """Records ui.message calls. Questions are answered from ``answers`` (default: No)."""

    calls: list[tuple[QMessageBox.Icon, str, str]] = field(default_factory=list)
    answers: list[bool] = field(default_factory=list)

    def __call__(
        self,
        parent: QWidget | None,
        icon: QMessageBox.Icon,
        title: str,
        text: str,
        *,
        buttons: QMessageBox.StandardButton = ui.Button.Ok,
        default: QMessageBox.StandardButton = ui.Button.NoButton,
    ) -> QMessageBox.StandardButton:
        self.calls.append((icon, title, text))
        if buttons & ui.Button.Yes:
            return ui.Button.Yes if (self.answers.pop(0) if self.answers else False) else ui.Button.No
        return ui.Button.Ok

    def titles(self) -> list[str]:
        return [title for _, title, _ in self.calls]


@dataclass
class Dialogs:
    """Stands in for ui.run_dialog: each queued handler drives the next dialog."""

    handlers: list[Callable[[QDialog], None]] = field(default_factory=list)
    seen: list[str] = field(default_factory=list)

    def expect(self, handler: Callable[[QDialog], None]) -> None:
        self.handlers.append(handler)

    def __call__(self, dialog: QDialog) -> bool:
        self.seen.append(type(dialog).__name__)
        if not self.handlers:
            raise AssertionError(f"unexpected dialog: {type(dialog).__name__}")
        self.handlers.pop(0)(dialog)
        return dialog.result() == QDialog.DialogCode.Accepted


@pytest.fixture(autouse=True)
def clip(monkeypatch: pytest.MonkeyPatch) -> FakeClipboard:
    fake = FakeClipboard()
    monkeypatch.setattr(clipboard, "get_clipboard", lambda: fake)
    monkeypatch.setattr(clipboard, "schedule_clear", lambda text, seconds: fake.scheduled.append((text, seconds)))
    return fake


@pytest.fixture(autouse=True)
def messages(monkeypatch: pytest.MonkeyPatch) -> Messages:
    recorder = Messages()
    monkeypatch.setattr(ui, "message", recorder)
    return recorder


@pytest.fixture(autouse=True)
def dialogs(monkeypatch: pytest.MonkeyPatch) -> Iterator[Dialogs]:
    script = Dialogs()
    monkeypatch.setattr(ui, "run_dialog", script)
    yield script
    assert not script.handlers, f"dialogs never opened: {len(script.handlers)}"


@pytest.fixture
def settings(tmp_path: Path) -> QSettings:
    return QSettings(str(tmp_path / "prefs.ini"), QSettings.Format.IniFormat)


@pytest.fixture
def sample_entries() -> list[Entry]:
    return [
        Entry(
            title="GitHub",
            username="kostas",
            password="gh-Secret-1",
            url="https://github.com",
            tags=["work", "dev"],
            totp=RFC_SECRET,
        ),
        Entry(title="Bank", username="me", password="bank-pass-2", tags=["finance"], notes="PIN hint"),
        Entry(title="Email", username="me@example.com", password="mail-pass-3", tags=["personal", "Work"]),
    ]


MakeVault = Callable[..., Path]


@pytest.fixture
def make_vault(tmp_path: Path) -> MakeVault:
    def make(entries: Sequence[Entry] = (), name: str = "gui.svault", keyfile: bytes | None = None) -> Path:
        path = tmp_path / name
        vault = Vault.create(path, PW, kdf=policy_floor_kdf(), keyfile=keyfile)
        for entry in entries:
            vault.add(entry)
        vault.save()
        vault.lock()
        return path

    return make


@pytest.fixture
def vault_file(make_vault: MakeVault, sample_entries: list[Entry]) -> Path:
    return make_vault(sample_entries)


@pytest.fixture
def window(qtbot: QtBot, settings: QSettings, vault_file: Path) -> MainWindow:
    win = MainWindow(settings, vault_file)
    qtbot.addWidget(win)
    win.show()
    return win


def unlock(win: MainWindow, password: str = PW, keyfile: Path | None = None) -> None:
    win.unlock_view.password.setText(password)
    win.unlock_view.keyfile.set_path(keyfile)
    win.unlock_view.try_unlock()


@pytest.fixture
def unlocked(window: MainWindow) -> MainWindow:
    unlock(window)
    assert window.session is not None
    return window


def open_vault(path: Path, password: str = PW, keyfile: bytes | None = None) -> Vault:
    return Vault.open(path, password, keyfile=keyfile)


def titles(win: MainWindow) -> list[str]:
    model = win.vault_view.model
    return [str(model.data(model.index(row, 0))) for row in range(model.rowCount())]


def select(win: MainWindow, title: str) -> Entry:
    assert win.session is not None
    entry = win.session.contents.find(title, fuzzy=False)
    win.vault_view.select(entry.id)
    assert win.vault_view.detail.entry is entry
    return entry
