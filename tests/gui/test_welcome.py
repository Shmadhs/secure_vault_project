"""First run and the login screen: the GUI must read as a password manager, not a file tool."""

from __future__ import annotations

from pathlib import Path

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QDialog
from pytestqt.qtbot import QtBot

from securevault import crypto
from securevault.crypto import KdfParams
from securevault.gui.entry_dialogs import EntryDialog
from securevault.gui.main_window import MainWindow

from .conftest import Dialogs, FilePicker, open_vault, titles, unlock


@pytest.fixture(autouse=True)
def fast_calibration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        crypto,
        "calibrate_kdf",
        lambda *a, **k: KdfParams(crypto.new_salt(), memory_kib=64 * 1024, iterations=3, lanes=1),
    )


@pytest.fixture
def first_run(qtbot: QtBot, settings: QSettings, tmp_path: Path) -> MainWindow:
    win = MainWindow(settings, tmp_path / "SecureVault" / "vault.svault")  # nothing there yet
    qtbot.addWidget(win)
    win.show()
    return win


def assert_vault_actions_hidden(win: MainWindow) -> None:
    assert win.toolbar.isHidden()
    assert not win.entry_menu.menuAction().isVisible()
    assert not win.act_new.isVisible()
    assert not win.act_new.isEnabled()


def test_first_run_shows_the_welcome_screen_not_a_lock_screen(first_run: MainWindow) -> None:
    assert first_run.stack.currentWidget() is first_run.welcome_view
    assert_vault_actions_hidden(first_run)  # no disabled "Add password" that looks broken
    assert first_run.welcome_view.form.master.generating  # a strong passphrase is offered first
    assert not first_run.welcome_view.form.advanced.expanded  # location/keyfile are folded away


def test_from_first_run_to_the_first_password_in_two_steps(
    first_run: MainWindow, dialogs: Dialogs, tmp_path: Path
) -> None:
    welcome = first_run.welcome_view
    phrase = welcome.form.master.phrase_label.text()
    welcome.form.master.typeback.setText(phrase)
    welcome.create_button.click()  # step 1

    assert first_run.session is not None
    assert first_run.stack.currentWidget() is first_run.vault_view
    assert not first_run.toolbar.isHidden()
    assert first_run.act_new.isVisible()
    assert first_run.act_new.isEnabled()
    view = first_run.vault_view
    assert not view.empty.isHidden()
    assert view.splitter.isHidden()
    assert welcome.form.master.phrase_label.text() == ""  # the passphrase does not linger on screen

    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, EntryDialog)
        assert dialog.windowTitle() == "Add password"
        dialog.title.setText("GitHub")
        dialog.password.setText("gh-pass")
        dialog.try_accept()

    dialogs.expect(fill)
    view.add_first.click()  # step 2
    assert titles(first_run) == ["GitHub"]
    assert view.empty.isHidden()
    assert not view.splitter.isHidden()
    path = tmp_path / "SecureVault" / "vault.svault"
    assert [e.title for e in open_vault(path, phrase).contents] == ["GitHub"]


def test_welcome_errors_keep_the_user_on_the_welcome_screen(first_run: MainWindow) -> None:
    welcome = first_run.welcome_view
    welcome.form.master.typeback.setText("not what was shown")
    welcome.create_button.click()
    assert first_run.session is None
    assert first_run.stack.currentWidget() is welcome
    assert "does not match" in welcome.form.error.text()


def test_i_already_have_a_vault(first_run: MainWindow, files: FilePicker, vault_file: Path) -> None:
    files.answers.append(vault_file)
    first_run.welcome_view.have_vault.click()
    assert first_run.stack.currentWidget() is first_run.unlock_view
    assert first_run.unlock_view.path.path() == vault_file
    assert first_run.welcome_view.form.master.phrase_label.text() == ""  # cleared on the way out
    unlock(first_run)
    assert titles(first_run) == ["Bank", "Email", "GitHub"]


def test_login_screen_is_just_the_master_password(window: MainWindow) -> None:
    assert window.stack.currentWidget() is window.unlock_view
    assert_vault_actions_hidden(window)
    assert window.unlock_view.keyfile_row.isHidden()  # this vault needs no keyfile, so none is asked
    unlock(window)
    assert not window.toolbar.isHidden()
    window.lock("test")
    assert window.stack.currentWidget() is window.unlock_view  # the vault exists: login, not welcome
    assert_vault_actions_hidden(window)


def test_change_vault_from_the_login_screen(window: MainWindow, files: FilePicker, make_vault: object) -> None:
    other = make_vault(name="other.svault")  # type: ignore[operator]
    files.answers.append(other)
    window.unlock_view.path.change.click()
    assert window.unlock_view.path.path() == other
    unlock(window)
    assert window.session is not None
    assert window.session.path == other
