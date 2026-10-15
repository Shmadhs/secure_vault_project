"""Locking: idle timer, minimize, closing, open dialogs, the clipboard, and busy operations."""

from __future__ import annotations

from pathlib import Path

import pytest
from PySide6.QtCore import QEvent, QPoint, QSettings, Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QApplication, QDialog
from pytestqt.qtbot import QtBot

from securevault.gui import guards
from securevault.gui import prefs as prefs_store
from securevault.gui.entry_dialogs import EntryDialog
from securevault.gui.guards import IdleTimer
from securevault.gui.main_window import MainWindow
from securevault.gui.prefs import Preferences

from .conftest import FakeClipboard, select, unlock


def assert_purged(win: MainWindow) -> None:
    assert win.session is None
    assert win.stack.currentWidget() is win.unlock_view
    assert win.vault_view.model.rowCount() == 0
    assert win.vault_view.detail.entry is None
    assert win.vault_view.detail.password.text() == ""
    assert win.vault_view.detail.notes.toPlainText() == ""
    assert win.vault_view.search.text() == ""
    assert not win.act_copy_pass.isEnabled()


def test_idle_lock_purges_everything(qtbot: QtBot, unlocked: MainWindow) -> None:
    assert unlocked.session is not None
    vault = unlocked.session.vault
    select(unlocked, "GitHub")
    unlocked.vault_view.detail.reveal.setChecked(True)
    unlocked.vault_view.search.setText("git")
    unlocked.idle.set_interval(50)
    qtbot.waitUntil(lambda: unlocked.session is None, timeout=3000)
    assert vault.locked  # key zeroized and contents dropped by the core
    assert_purged(unlocked)
    assert "inactivity" in unlocked.statusBar().currentMessage()


def test_activity_postpones_the_idle_lock(qtbot: QtBot, unlocked: MainWindow) -> None:
    unlocked.idle.set_interval(300)
    for _ in range(6):
        qtbot.wait(100)
        QApplication.sendEvent(
            unlocked.vault_view.table,
            QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Down, Qt.KeyboardModifier.NoModifier),
        )
    assert unlocked.session is not None  # 600 ms passed, but never 300 ms without a key press
    qtbot.waitUntil(lambda: unlocked.session is None, timeout=3000)


def test_mouse_movement_alone_is_not_activity(qtbot: QtBot, unlocked: MainWindow) -> None:
    unlocked.idle.set_interval(200)
    for _ in range(4):
        qtbot.wait(80)
        qtbot.mouseMove(unlocked.vault_view.table, QPoint(10, 10))
    qtbot.waitUntil(lambda: unlocked.session is None, timeout=3000)


def test_lock_closes_open_dialogs_and_their_secrets(qtbot: QtBot, unlocked: MainWindow) -> None:
    entry = select(unlocked, "GitHub")
    dialog = EntryDialog(lambda form: True, unlocked.copy_value, entry, unlocked)
    dialog.open()  # non-blocking, as if the user were editing when the timer fired
    qtbot.waitUntil(dialog.isVisible)
    assert dialog.password.text() == "gh-Secret-1"
    unlocked.lock("test")
    assert not dialog.isVisible()
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert dialog.password.text() == ""
    assert_purged(unlocked)


def test_lock_on_minimize(qtbot: QtBot, unlocked: MainWindow) -> None:
    unlocked.setWindowState(Qt.WindowState.WindowMinimized)
    qtbot.waitUntil(lambda: unlocked.session is None, timeout=3000)
    assert_purged(unlocked)


def test_lock_on_minimize_can_be_turned_off(qtbot: QtBot, settings: QSettings, vault_file: Path) -> None:
    prefs_store.save(settings, Preferences(lock_on_minimize=False))
    win = MainWindow(settings, vault_file)
    qtbot.addWidget(win)
    win.show()
    unlock(win)
    win.setWindowState(Qt.WindowState.WindowMinimized)
    qtbot.wait(50)
    assert win.session is not None


def test_closing_the_window_locks(unlocked: MainWindow) -> None:
    assert unlocked.session is not None
    vault = unlocked.session.vault
    unlocked.close()
    assert vault.locked


def test_lock_clears_our_value_from_the_clipboard(unlocked: MainWindow, clip: FakeClipboard) -> None:
    select(unlocked, "GitHub")
    unlocked.vault_view.detail.copy_password.click()
    assert clip.text == "gh-Secret-1"
    unlocked.lock("test")
    assert clip.text == ""


def test_lock_leaves_what_the_user_copied_since(unlocked: MainWindow, clip: FakeClipboard) -> None:
    select(unlocked, "GitHub")
    unlocked.vault_view.detail.copy_password.click()
    clip.text = "something the user copied afterwards"
    unlocked.lock("test")
    assert clip.text == "something the user copied afterwards"


def test_lock_waits_for_a_running_key_derivation(qtbot: QtBot, unlocked: MainWindow) -> None:
    unlocked._on_busy(+1)  # what ui.run_blocking does around a worker
    unlocked.lock("when minimized")
    assert unlocked.session is not None
    unlocked._on_busy(-1)
    qtbot.waitUntil(lambda: unlocked.session is None, timeout=3000)
    assert "when minimized" in unlocked.statusBar().currentMessage()


def test_idle_timer_holds_off_while_busy(qtbot: QtBot) -> None:
    fired: list[bool] = []
    timer = IdleTimer(40)
    timer.expired.connect(lambda: fired.append(True))
    timer.arm()
    timer.busy(+1)
    qtbot.wait(150)
    assert fired == []
    timer.busy(-1)
    qtbot.waitUntil(lambda: fired == [True], timeout=2000)


def test_idle_timer_disabled_with_zero(qtbot: QtBot) -> None:
    fired: list[bool] = []
    timer = IdleTimer(0)
    timer.expired.connect(lambda: fired.append(True))
    timer.arm()
    qtbot.wait(100)
    assert fired == []


def test_new_windows_are_excluded_from_capture(
    qtbot: QtBot, unlocked: MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    applied: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        guards,
        "set_capture_exclusion",
        lambda widget, exclude: applied.append((type(widget).__name__, exclude)) or True,
    )
    dialog = QDialog(unlocked)
    qtbot.addWidget(dialog)
    dialog.show()
    assert ("QDialog", True) in applied
    unlocked.guard.exclude_from_capture = False
    applied.clear()
    dialog.hide()
    dialog.show()
    assert applied == []


def test_capture_exclusion_is_a_no_op_offscreen(unlocked: MainWindow) -> None:
    # The offscreen platform has no HWNDs, so the Win32 call must not be attempted.
    assert guards.set_capture_exclusion(unlocked, True) is False
