"""Unlock screen: distinct failure messages, keyfile handling, new vault, restore from the lock screen."""

from __future__ import annotations

from pathlib import Path

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QDialog
from pytestqt.qtbot import QtBot

from securevault import crypto
from securevault.crypto import KdfParams
from securevault.errors import AuthenticationError
from securevault.gui import prefs as prefs_store
from securevault.gui import ui
from securevault.gui.main_window import MainWindow
from securevault.gui.vault_dialogs import BackupsDialog, NewVaultDialog
from securevault.vault import Vault

from ..conftest import FAST_POLICY
from .conftest import PW, Dialogs, MakeVault, Messages, open_vault, titles, unlock


def test_unlock_shows_entries_and_remembers_the_vault(
    window: MainWindow, settings: QSettings, vault_file: Path
) -> None:
    assert window.session is None
    assert window.stack.currentWidget() is window.unlock_view
    unlock(window)
    assert window.session is not None
    assert window.stack.currentWidget() is window.vault_view
    assert titles(window) == ["Bank", "Email", "GitHub"]
    assert vault_file.name in window.windowTitle()
    assert prefs_store.load(settings).last_vault == str(vault_file)
    assert window.unlock_view.password.text() == ""  # not left in the hidden field


def test_wrong_password_is_routine_and_retryable(window: MainWindow, messages: Messages) -> None:
    unlock(window, "not the password")
    assert window.session is None
    assert window.unlock_view.error.text() == "Wrong master password or keyfile."
    assert window.unlock_view.password.text() == ""
    assert messages.calls == []  # inline, no alarming dialog
    unlock(window)
    assert window.session is not None


def test_integrity_failure_is_distinct_and_offers_restore(
    window: MainWindow, vault_file: Path, messages: Messages, dialogs: Dialogs
) -> None:
    data = bytearray(vault_file.read_bytes())
    data[-1] ^= 0x01  # flip a bit of the payload's GCM tag; the key slot is intact
    vault_file.write_bytes(bytes(data))

    unlock(window)  # declines the restore offer (default answer: No)
    assert window.session is None
    assert "Integrity failure" in window.unlock_view.error.text()
    assert "Wrong master password" not in window.unlock_view.error.text()
    icon, title, text = messages.calls[-1]
    assert icon == ui.Icon.Critical
    assert title == "Integrity failure"
    assert "INTEGRITY FAILURE" in text

    messages.answers.append(True)  # this time accept the offer
    dialogs.expect(lambda dialog: dialog.reject())
    unlock(window)
    assert dialogs.seen == ["BackupsDialog"]


def test_weak_kdf_header_is_refused_as_suspicious(
    qtbot: QtBot, settings: QSettings, tmp_path: Path, messages: Messages
) -> None:
    path = tmp_path / "weak.svault"
    cheap = KdfParams(crypto.new_salt(), memory_kib=256, iterations=1, lanes=1)
    Vault.create(path, PW, kdf=cheap, policy=FAST_POLICY).lock()
    win = MainWindow(settings, path)
    qtbot.addWidget(win)
    unlock(win)
    assert win.session is None
    assert "below the security floor" in win.unlock_view.error.text()
    assert messages.titles() == ["Suspicious vault file"]
    assert "was not processed" in messages.calls[0][2]


def test_missing_keyfile_is_detected_before_the_kdf(
    qtbot: QtBot, settings: QSettings, make_vault: MakeVault, tmp_path: Path
) -> None:
    keyfile = tmp_path / "vault.key"
    keyfile.write_bytes(crypto.generate_keyfile_bytes())
    path = make_vault(keyfile=crypto.keyfile_secret(keyfile))
    win = MainWindow(settings, path)
    qtbot.addWidget(win)
    unlock(win)
    assert win.session is None
    assert "requires its keyfile" in win.unlock_view.error.text()
    unlock(win, keyfile=keyfile)
    assert win.session is not None
    assert win.session.keyfile_path == keyfile


def test_not_a_vault_and_missing_file(qtbot: QtBot, settings: QSettings, tmp_path: Path) -> None:
    junk = tmp_path / "junk.svault"
    junk.write_bytes(b"this is not a vault at all")
    win = MainWindow(settings, junk)
    qtbot.addWidget(win)
    unlock(win)
    assert "not a vault SecureVault can open" in win.unlock_view.error.text()

    win.unlock_view.path.set_path(tmp_path / "missing.svault")
    unlock(win)
    assert "Create one with New vault" in win.unlock_view.error.text()


@pytest.fixture
def fast_calibration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        crypto,
        "calibrate_kdf",
        lambda *a, **k: KdfParams(crypto.new_salt(), memory_kib=64 * 1024, iterations=3, lanes=1),
    )


@pytest.mark.usefixtures("fast_calibration")
def test_new_vault_with_generated_passphrase(window: MainWindow, dialogs: Dialogs, tmp_path: Path) -> None:
    target = tmp_path / "fresh.svault"
    phrase: list[str] = []

    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, NewVaultDialog)
        dialog.path.set_path(target)
        shown = dialog.master.phrase_label.text()
        assert len(shown.split("-")) == 6
        dialog.master.typeback.setText("wrong words")
        dialog.try_accept()
        assert "does not match" in dialog.error.text()
        assert not target.exists()
        dialog.master.typeback.setText(shown)
        dialog.try_accept()
        phrase.append(shown)

    dialogs.expect(fill)
    window.unlock_view.new_vault()
    assert window.session is not None  # straight into the new, empty vault
    assert titles(window) == []
    open_vault(target, phrase[0]).lock()


@pytest.mark.usefixtures("fast_calibration")
def test_new_vault_weak_own_password_needs_confirmation(
    window: MainWindow, dialogs: Dialogs, messages: Messages, tmp_path: Path
) -> None:
    target = tmp_path / "weak-choice.svault"

    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, NewVaultDialog)
        dialog.path.set_path(target)
        dialog.master.own_radio.setChecked(True)
        dialog.master.first.setText("abc")
        dialog.master.repeat.setText("abd")
        dialog.try_accept()
        assert "do not match" in dialog.error.text()
        dialog.master.repeat.setText("abc")
        dialog.try_accept()  # declined (default answer: No)
        assert not target.exists()
        messages.answers.append(True)
        dialog.try_accept()

    dialogs.expect(fill)
    window.unlock_view.new_vault()
    assert messages.titles() == ["Weak master password", "Weak master password"]
    open_vault(target, "abc").lock()


@pytest.mark.usefixtures("fast_calibration")
def test_new_vault_with_keyfile(window: MainWindow, dialogs: Dialogs, tmp_path: Path) -> None:
    target, keyfile = tmp_path / "kf.svault", tmp_path / "kf.key"

    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, NewVaultDialog)
        dialog.path.set_path(target)
        dialog.master.own_radio.setChecked(True)
        dialog.master.first.setText(PW)
        dialog.master.repeat.setText(PW)
        dialog.with_keyfile.setChecked(True)
        dialog.keyfile.set_path(keyfile)
        dialog.try_accept()

    dialogs.expect(fill)
    window.unlock_view.new_vault()
    assert window.session is not None
    assert window.session.keyfile_path == keyfile
    with pytest.raises(AuthenticationError):
        open_vault(target)
    open_vault(target, keyfile=crypto.keyfile_secret(keyfile)).lock()


def test_new_vault_refuses_to_overwrite(window: MainWindow, dialogs: Dialogs, vault_file: Path) -> None:
    before = vault_file.read_bytes()

    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, NewVaultDialog)
        dialog.path.set_path(vault_file)
        dialog.try_accept()
        assert "already exists" in dialog.error.text()
        dialog.reject()

    dialogs.expect(fill)
    window.unlock_view.new_vault()
    assert vault_file.read_bytes() == before


def test_backups_reachable_while_locked(window: MainWindow, dialogs: Dialogs) -> None:
    def check(dialog: QDialog) -> None:
        assert isinstance(dialog, BackupsDialog)
        dialog.reject()

    dialogs.expect(check)
    window.open_backups()
    assert window.session is None


def test_new_vault_keyfile_must_differ_from_the_vault(window: MainWindow, dialogs: Dialogs, tmp_path: Path) -> None:
    target = tmp_path / "same.svault"

    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, NewVaultDialog)
        dialog.path.set_path(target)
        dialog.master.typeback.setText(dialog.master.phrase_label.text())
        dialog.with_keyfile.setChecked(True)
        dialog.keyfile.set_path(target)
        dialog.try_accept()
        assert "must be different files" in dialog.error.text()
        dialog.reject()

    dialogs.expect(fill)
    window.unlock_view.new_vault()
    assert not target.exists()
