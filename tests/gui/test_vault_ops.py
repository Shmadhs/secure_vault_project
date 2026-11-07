"""Master-password change, backups and restore, preferences, launcher plumbing."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QDialog
from pytestqt.qtbot import QtBot

from securevault import crypto, storage
from securevault.errors import AuthenticationError
from securevault.gui import app as gui_app
from securevault.gui import prefs as prefs_store
from securevault.gui.entry_dialogs import EntryDialog
from securevault.gui.main_window import MainWindow
from securevault.gui.prefs import Preferences
from securevault.gui.vault_dialogs import BackupsDialog, PasswdDialog, PreferencesDialog

from .conftest import PW, Dialogs, Messages, open_vault, select, titles, unlock

NEW_PW = "Νέος-κύριος-κωδικός-staple-horse"


def rename(win: MainWindow, dialogs: Dialogs, old: str, new: str) -> None:
    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, EntryDialog)
        dialog.title.setText(new)
        dialog.try_accept()

    select(win, old)
    dialogs.expect(fill)
    win.edit_entry()


def passwd(win: MainWindow, dialogs: Dialogs, current: str, configure: object = None) -> PasswdDialog:
    opened: list[PasswdDialog] = []

    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, PasswdDialog)
        opened.append(dialog)
        dialog.current.setText(current)
        dialog.master.own_radio.setChecked(True)
        dialog.master.first.setText(NEW_PW)
        dialog.master.repeat.setText(NEW_PW)
        if callable(configure):
            configure(dialog)
        dialog.try_accept()
        if dialog.result() != QDialog.DialogCode.Accepted:
            dialog.reject()

    dialogs.expect(fill)
    win.change_master_password()
    return opened[0]


def test_passwd_requires_the_current_password(unlocked: MainWindow, dialogs: Dialogs, vault_file: Path) -> None:
    dialog = passwd(unlocked, dialogs, "wrong current password")
    assert "wrong" in dialog.error.text()
    open_vault(vault_file, PW).lock()  # unchanged
    assert unlocked.session is not None


def test_passwd_rotates_the_key_and_purges_backups(
    unlocked: MainWindow, dialogs: Dialogs, messages: Messages, vault_file: Path
) -> None:
    rename(unlocked, dialogs, "Bank", "Bank 2")  # make another backup
    assert storage.list_backups(vault_file)
    passwd(unlocked, dialogs, PW)
    assert messages.titles() == ["Master password changed"]
    assert "Removed" in messages.calls[0][2]
    assert storage.list_backups(vault_file) == []
    with pytest.raises(AuthenticationError):
        open_vault(vault_file, PW)
    assert sorted(e.title for e in open_vault(vault_file, NEW_PW).contents) == ["Bank 2", "Email", "GitHub"]
    rename(unlocked, dialogs, "Bank 2", "Bank 3")  # the session keeps working under the new key
    assert "Bank 3" in [e.title for e in open_vault(vault_file, NEW_PW).contents]


def test_passwd_adds_then_removes_a_keyfile(
    unlocked: MainWindow, dialogs: Dialogs, vault_file: Path, tmp_path: Path
) -> None:
    keyfile = tmp_path / "new.key"

    def add_keyfile(dialog: PasswdDialog) -> None:
        dialog.new_keyfile.setChecked(True)
        dialog.keyfile.set_path(keyfile)

    passwd(unlocked, dialogs, PW, add_keyfile)
    assert unlocked.session is not None
    assert unlocked.session.keyfile_path == keyfile
    with pytest.raises(AuthenticationError):
        open_vault(vault_file, NEW_PW)
    open_vault(vault_file, NEW_PW, keyfile=crypto.keyfile_secret(keyfile)).lock()

    def remove_keyfile(dialog: PasswdDialog) -> None:
        assert dialog.remove_keyfile.isEnabled()
        dialog.remove_keyfile.setChecked(True)

    passwd(unlocked, dialogs, NEW_PW, remove_keyfile)
    assert unlocked.session.keyfile_path is None
    open_vault(vault_file, NEW_PW).lock()


def test_passwd_refuses_to_overwrite_an_existing_keyfile(
    unlocked: MainWindow, dialogs: Dialogs, vault_file: Path, tmp_path: Path
) -> None:
    existing = tmp_path / "existing.key"
    existing.write_bytes(b"precious" * 8)

    def reuse(dialog: PasswdDialog) -> None:
        dialog.new_keyfile.setChecked(True)
        dialog.keyfile.set_path(existing)

    dialog = passwd(unlocked, dialogs, PW, reuse)
    assert "refusing to overwrite" in dialog.error.text()
    assert existing.read_bytes() == b"precious" * 8
    open_vault(vault_file, PW).lock()


def test_restore_from_the_main_window_locks_and_reverts(
    unlocked: MainWindow, dialogs: Dialogs, messages: Messages, vault_file: Path
) -> None:
    rename(unlocked, dialogs, "Bank", "Bank renamed")
    # The newest backup is the state just before that rename.

    def restore(dialog: QDialog) -> None:
        assert isinstance(dialog, BackupsDialog)
        assert dialog.table.rowCount() >= 1
        dialog.table.selectRow(0)
        dialog.password.setText(PW)
        messages.answers.append(True)  # "Replace ... with ...?"
        dialog.restore()

    dialogs.expect(restore)
    unlocked.open_backups()
    assert unlocked.session is None  # the open session's digest is stale after a restore
    assert messages.titles() == ["Restore backup", "Backup restored"]
    assert sorted(e.title for e in open_vault(vault_file).contents) == ["Bank", "Email", "GitHub"]
    unlock(unlocked)
    assert titles(unlocked) == ["Bank", "Email", "GitHub"]


def test_restore_with_the_wrong_password(unlocked: MainWindow, dialogs: Dialogs, messages: Messages) -> None:
    def restore(dialog: QDialog) -> None:
        assert isinstance(dialog, BackupsDialog)
        dialog.password.setText("not it")
        messages.answers.append(True)
        dialog.restore()
        assert "Wrong master password" in dialog.error.text()
        dialog.reject()

    dialogs.expect(restore)
    unlocked.open_backups()
    assert unlocked.session is not None


def test_preferences_apply_and_persist(
    qtbot: QtBot, unlocked: MainWindow, dialogs: Dialogs, settings: QSettings, vault_file: Path
) -> None:
    def change(dialog: QDialog) -> None:
        assert isinstance(dialog, PreferencesDialog)
        dialog.idle.setValue(7)
        dialog.lock_on_minimize.setChecked(False)
        dialog.clear_seconds.setValue(45)
        dialog.accept()

    dialogs.expect(change)
    unlocked.open_preferences()
    assert unlocked.idle.interval_ms == 7 * 60_000
    stored = prefs_store.load(settings)
    assert (stored.idle_minutes, stored.lock_on_minimize, stored.clear_seconds) == (7, False, 45)
    again = MainWindow(settings, vault_file)
    qtbot.addWidget(again)
    assert again.prefs.clear_seconds == 45


def test_keyfile_path_is_never_persisted(qtbot: QtBot, settings: QSettings, make_vault: object, tmp_path: Path) -> None:
    keyfile = tmp_path / "secret-location.key"
    keyfile.write_bytes(crypto.generate_keyfile_bytes())
    path = make_vault(keyfile=crypto.keyfile_secret(keyfile))  # type: ignore[operator]
    win = MainWindow(settings, path)
    qtbot.addWidget(win)
    unlock(win, keyfile=keyfile)
    assert win.session is not None
    settings.sync()
    assert "secret-location" not in Path(settings.fileName()).read_text(encoding="utf-8")


def test_tampered_settings_are_clamped(settings: QSettings) -> None:
    settings.setValue("idle_minutes", "99999")
    settings.setValue("clear_seconds", "-5")
    settings.setValue("lock_on_minimize", "maybe")
    loaded = prefs_store.load(settings)
    assert (loaded.idle_minutes, loaded.clear_seconds, loaded.lock_on_minimize) == (240, 0, True)


def test_initial_paths_precedence(settings: QSettings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = argparse.Namespace(vault=None, keyfile=None)
    monkeypatch.delenv("SVAULT_VAULT", raising=False)
    monkeypatch.delenv("SVAULT_KEYFILE", raising=False)
    prefs_store.save(settings, Preferences(last_vault=str(tmp_path / "last.svault")))
    assert gui_app.initial_paths(args, settings) == (tmp_path / "last.svault", None)
    monkeypatch.setenv("SVAULT_VAULT", str(tmp_path / "env.svault"))
    monkeypatch.setenv("SVAULT_KEYFILE", str(tmp_path / "env.key"))
    assert gui_app.initial_paths(args, settings) == (tmp_path / "env.svault", tmp_path / "env.key")
    args = argparse.Namespace(vault=tmp_path / "arg.svault", keyfile=None)
    assert gui_app.initial_paths(args, settings)[0] == tmp_path / "arg.svault"
