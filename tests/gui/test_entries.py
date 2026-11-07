"""Entry list, detail pane, copy buttons, TOTP, add/edit/delete, rollback, sanitization."""

from __future__ import annotations

import errno
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QDialog, QFormLayout, QLabel, QMessageBox
from pytestqt.qtbot import QtBot

from securevault import clipboard, generator, storage, totp
from securevault.gui import ui
from securevault.gui.entry_dialogs import DeleteDialog, EntryDialog
from securevault.gui.generator_dialog import GeneratorDialog
from securevault.gui.main_window import MASK, MainWindow
from securevault.gui.vault_dialogs import AuditDialog
from securevault.model import Entry

from .conftest import (
    REAL_MESSAGE,
    RFC_SECRET,
    Dialogs,
    FakeClipboard,
    MakeVault,
    Messages,
    open_vault,
    select,
    titles,
    unlock,
)

BIDI_TITLE = "invoice\u202efdp.exe"
HTML_TITLE = '<img src="file:///etc/passwd"><a href="x">click</a>'
RFC_SECRET_SPACED = " GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ "


def make_window(qtbot: QtBot, settings: QSettings, path: Path) -> MainWindow:
    win = MainWindow(settings, path)
    qtbot.addWidget(win)
    unlock(win)
    return win


def test_search_and_tag_filter(unlocked: MainWindow) -> None:
    view = unlocked.vault_view
    view.search.setText("me@example")  # usernames are searched, like `svault search`
    assert titles(unlocked) == ["Email"]
    view.search.setText("pin hint")  # notes too, case-insensitively
    assert titles(unlocked) == ["Bank"]
    view.search.clear()
    view.tag.setCurrentIndex(view.tag.findData("work"))
    assert titles(unlocked) == ["Email", "GitHub"]  # tag match is case-insensitive ("Work")
    assert view.count.text() == "2 of 3 entries"
    view.tag.setCurrentIndex(0)
    assert len(titles(unlocked)) == 3


def test_password_is_masked_and_reveal_resets_on_selection(unlocked: MainWindow) -> None:
    detail = unlocked.vault_view.detail
    select(unlocked, "GitHub")
    assert detail.password.text() == MASK  # fixed width: the length is not revealed
    detail.reveal.setChecked(True)
    assert detail.password.text() == "gh-Secret-1"
    select(unlocked, "Bank")
    assert not detail.reveal.isChecked()
    assert detail.password.text() == MASK


def test_copy_buttons_go_through_the_core_clipboard(unlocked: MainWindow, clip: FakeClipboard) -> None:
    detail = unlocked.vault_view.detail
    select(unlocked, "GitHub")
    detail.copy_password.click()
    assert clip.text == "gh-Secret-1"
    assert clip.scheduled == [("gh-Secret-1", clipboard.DEFAULT_CLEAR_SECONDS)]
    assert "cleared in 20 s" in unlocked.statusBar().currentMessage()
    detail.copy_username.click()
    assert clip.text == "kostas"
    select(unlocked, "Bank")
    detail.copy_notes.click()
    assert clip.text == "PIN hint"
    assert not detail.copy_url.isEnabled()  # Bank has no URL


def test_copy_warns_when_the_clear_helper_cannot_start(
    unlocked: MainWindow, clip: FakeClipboard, messages: Messages, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(text: str, seconds: int) -> None:
        raise OSError("cannot spawn")

    monkeypatch.setattr(clipboard, "schedule_clear", broken)
    select(unlocked, "GitHub")
    unlocked.vault_view.detail.copy_password.click()
    assert clip.text == "gh-Secret-1"  # the copy itself happened, so the user must be told
    assert messages.titles() == ["Clipboard"]


def test_clipboard_unavailable_is_reported(
    unlocked: MainWindow, messages: Messages, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing() -> None:
        raise clipboard.ClipboardUnavailableError("no clipboard tool found")

    monkeypatch.setattr(clipboard, "get_clipboard", missing)
    select(unlocked, "GitHub")
    unlocked.vault_view.detail.copy_password.click()
    assert messages.titles() == ["Clipboard unavailable"]


def test_totp_code_countdown_and_copy(
    unlocked: MainWindow, clip: FakeClipboard, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: 59.0))
    detail = unlocked.vault_view.detail
    select(unlocked, "GitHub")
    assert detail.totp_code.text() == "287082"  # RFC 6238 Appendix B, T=59, 6 digits
    assert detail.totp_bar.value() == 1
    detail.copy_totp.click()
    # Like `svault totp --copy`: cleared once the code has expired.
    assert clip.scheduled[-1] == ("287082", 2)


def test_invalid_totp_is_shown_not_fatal(qtbot: QtBot, settings: QSettings, make_vault: MakeVault) -> None:
    win = make_window(qtbot, settings, make_vault([Entry(title="Broken", totp="not base32 !!")]))
    select(win, "Broken")
    assert win.vault_view.detail.totp_code.text().startswith("invalid:")
    assert not win.vault_view.detail.copy_totp.isEnabled()


def test_add_entry_is_saved(unlocked: MainWindow, dialogs: Dialogs, vault_file: Path) -> None:
    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, EntryDialog)
        dialog.title.setText("  Router  ")
        dialog.username.setText("admin")
        dialog.password.setText("r0uter-Pass")
        dialog.tags.setText("net, home ,")
        dialog.totp.setText(RFC_SECRET_SPACED)
        dialog.notes.setPlainText("MikroTik hAP")
        dialog.try_accept()

    dialogs.expect(fill)
    unlocked.new_entry()
    assert unlocked.vault_view.detail.entry is not None
    assert unlocked.vault_view.detail.entry.title == "Router"
    on_disk = open_vault(vault_file).contents.find("Router", fuzzy=False)
    assert (on_disk.username, on_disk.password, on_disk.tags, on_disk.notes) == (
        "admin",
        "r0uter-Pass",
        ["net", "home"],
        "MikroTik hAP",
    )
    assert on_disk.totp == RFC_SECRET_SPACED.strip()


def test_duplicate_title_keeps_the_dialog_open(unlocked: MainWindow, dialogs: Dialogs, vault_file: Path) -> None:
    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, EntryDialog)
        dialog.title.setText("github")  # titles are unique case-insensitively
        dialog.password.setText("x")
        dialog.try_accept()
        assert "already exists" in dialog.error.text()
        assert dialog.result() != QDialog.DialogCode.Accepted
        dialog.title.setText("GitHub (work)")
        dialog.try_accept()

    dialogs.expect(fill)
    unlocked.new_entry()
    assert sorted(e.title for e in open_vault(vault_file).contents) == ["Bank", "Email", "GitHub", "GitHub (work)"]


def test_invalid_totp_is_rejected_in_the_editor(unlocked: MainWindow, dialogs: Dialogs) -> None:
    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, EntryDialog)
        dialog.totp.setText("otpauth://hotp/x?secret=" + RFC_SECRET)
        dialog.try_accept()
        assert "HOTP" in dialog.error.text()
        dialog.reject()

    select(unlocked, "Bank")
    dialogs.expect(fill)
    unlocked.edit_entry()


def test_edit_writes_only_changed_fields(
    qtbot: QtBot, settings: QSettings, make_vault: MakeVault, dialogs: Dialogs
) -> None:
    path = make_vault([Entry(title=BIDI_TITLE, username="old", password="p1", notes="a\x1b[31mb")])
    win = make_window(qtbot, settings, path)

    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, EntryDialog)
        assert not dialog.notice.isHidden()  # warns about the bidi/control characters
        assert dialog.title.text() == BIDI_TITLE  # the editor holds the raw value
        dialog.username.setText("new")
        dialog.try_accept()

    select(win, BIDI_TITLE)
    dialogs.expect(fill)
    win.edit_entry()
    stored = open_vault(path).contents.find(BIDI_TITLE, fuzzy=False)
    assert stored.title == BIDI_TITLE  # not replaced by its escaped display form
    assert stored.notes == "a\x1b[31mb"
    assert stored.username == "new"
    assert stored.history == []  # the password was not touched


def test_edit_password_keeps_history_and_totp_can_be_removed(
    unlocked: MainWindow, dialogs: Dialogs, vault_file: Path
) -> None:
    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, EntryDialog)
        assert dialog.password.text() == "gh-Secret-1"
        dialog.password.setText("gh-Secret-2")
        dialog.remove_totp.setChecked(True)
        dialog.try_accept()

    select(unlocked, "GitHub")
    dialogs.expect(fill)
    unlocked.edit_entry()
    stored = open_vault(vault_file).contents.find("GitHub", fuzzy=False)
    assert stored.password == "gh-Secret-2"
    assert [h.password for h in stored.history] == ["gh-Secret-1"]
    assert stored.totp == ""


def test_generator_from_the_editor(unlocked: MainWindow, dialogs: Dialogs, vault_file: Path) -> None:
    generated: list[str] = []

    def use_generated(dialog: QDialog) -> None:
        assert isinstance(dialog, GeneratorDialog)
        dialog.tabs.setCurrentIndex(1)
        dialog.words.setValue(5)
        generated.append(dialog.value)
        assert dialog.use_button is not None
        dialog.use_button.click()

    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, EntryDialog)
        dialog.title.setText("Passphrase entry")
        dialog._generate()
        dialog.try_accept()

    dialogs.expect(fill)
    dialogs.expect(use_generated)
    unlocked.new_entry()
    stored = open_vault(vault_file).contents.find("Passphrase entry", fuzzy=False)
    assert stored.password == generated[0]
    assert len(stored.password.split("-")) == 5


def test_delete_needs_the_exact_title(unlocked: MainWindow, dialogs: Dialogs, vault_file: Path) -> None:
    def confirm(dialog: QDialog) -> None:
        assert isinstance(dialog, DeleteDialog)
        dialog.confirm.setText("bank")  # case matters here, unlike lookups
        assert not dialog.delete_button.isEnabled()
        dialog.accept()  # the button state is not the only gate
        assert dialog.result() != QDialog.DialogCode.Accepted
        dialog.confirm.setText("Bank")
        assert dialog.delete_button.isEnabled()
        dialog.delete_button.click()

    select(unlocked, "Bank")
    dialogs.expect(confirm)
    unlocked.delete_entry()
    assert titles(unlocked) == ["Email", "GitHub"]
    assert sorted(e.title for e in open_vault(vault_file).contents) == ["Email", "GitHub"]
    assert "previous version remains" in unlocked.statusBar().currentMessage()


def test_delete_cancelled_keeps_the_entry(unlocked: MainWindow, dialogs: Dialogs) -> None:
    select(unlocked, "Bank")
    dialogs.expect(lambda dialog: dialog.reject())
    unlocked.delete_entry()
    assert "Bank" in titles(unlocked)


def test_failed_save_rolls_back_the_change(
    unlocked: MainWindow, dialogs: Dialogs, vault_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = vault_file.read_bytes()

    def disk_full(path: Path, data: bytes) -> None:
        raise OSError(errno.ENOSPC, "No space left on device", str(path))

    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, EntryDialog)
        dialog.title.setText("Renamed")
        dialog.try_accept()
        assert "No space left" in dialog.error.text()
        dialog.reject()

    monkeypatch.setattr(storage, "atomic_write", disk_full)
    select(unlocked, "Bank")
    dialogs.expect(fill)
    unlocked.edit_entry()
    assert unlocked.session is not None
    assert sorted(e.title for e in unlocked.session.contents) == ["Bank", "Email", "GitHub"]
    assert titles(unlocked) == ["Bank", "Email", "GitHub"]
    assert vault_file.read_bytes() == before


def test_change_from_another_process_rolls_back_and_locks(
    unlocked: MainWindow, dialogs: Dialogs, messages: Messages, vault_file: Path
) -> None:
    other = open_vault(vault_file)  # e.g. `svault add` while the GUI is open
    other.add(Entry(title="From the CLI"))
    other.save()
    other.lock()

    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, EntryDialog)
        dialog.title.setText("From the GUI")
        dialog.try_accept()

    dialogs.expect(fill)
    unlocked.new_entry()
    assert unlocked.session is None
    assert messages.titles() == ["Vault changed on disk"]
    on_disk = sorted(e.title for e in open_vault(vault_file).contents)
    assert on_disk == ["Bank", "Email", "From the CLI", "GitHub"]


def test_markup_and_bidi_are_never_rendered(qtbot: QtBot, settings: QSettings, make_vault: MakeVault) -> None:
    entry = Entry(title=HTML_TITLE, username=BIDI_TITLE, url="\x1b]52;c;aGk=\x07", tags=["<b>t</b>"])
    win = make_window(qtbot, settings, make_vault([entry]))
    select(win, HTML_TITLE)
    # QFormLayout's own captions ("Username:") are static strings of ours. Every
    # other label, i.e. every label that can show vault data, must be plain text.
    captions = set()
    for form in win.findChildren(QFormLayout):
        for row in range(form.rowCount()):
            item = form.itemAt(row, QFormLayout.ItemRole.LabelRole)
            if item is not None and item.widget() is not None:
                captions.add(item.widget())
    labels = [label for label in win.findChildren(QLabel) if label not in captions]
    assert len(labels) > 10
    for label in labels:
        assert label.textFormat() == Qt.TextFormat.PlainText, label.text()
    detail = win.vault_view.detail
    assert detail.title.text() == HTML_TITLE  # shown literally, as text
    assert detail.username.text() == "invoice\\u202efdp.exe"
    assert detail.url.text() == "\\u001b]52;c;aGk=\\u0007"  # OSC 52 neutralized
    model = win.vault_view.model
    assert model.data(model.index(0, 1)) == "invoice\\u202efdp.exe"


def test_message_boxes_are_plain_text(monkeypatch: pytest.MonkeyPatch, qtbot: QtBot) -> None:
    seen: list[QMessageBox] = []

    def run_box(box: QMessageBox) -> int:
        seen.append(box)
        return int(QMessageBox.StandardButton.Ok.value)

    monkeypatch.setattr(QMessageBox, "exec", run_box)
    REAL_MESSAGE(None, ui.Icon.Critical, "t", HTML_TITLE)
    assert seen[0].textFormat() == Qt.TextFormat.PlainText


def test_generator_entropy_and_copy(qtbot: QtBot) -> None:
    copied: list[tuple[str, str]] = []
    dialog = GeneratorDialog(lambda value, label: copied.append((value, label)))
    qtbot.addWidget(dialog)
    pool = len(generator.LOWER + generator.UPPER + generator.DIGITS + generator.SYMBOLS)
    assert dialog.entropy.text().startswith(f"Entropy: {generator.password_entropy(24, pool):.0f} bits")
    assert len(dialog.value) == 24
    dialog.length.setValue(8)
    assert "Below the 60 bits" in dialog.entropy.text()
    for box in (dialog.use_lower, dialog.use_upper, dialog.use_digits, dialog.use_symbols):
        box.setChecked(False)
    assert dialog.entropy.text().startswith("Cannot generate")
    assert not dialog.copy_button.isEnabled()
    dialog.tabs.setCurrentIndex(1)
    assert dialog.entropy.text().startswith(f"Entropy: {generator.passphrase_entropy(6):.0f} bits")
    dialog.copy_button.click()
    assert copied == [(dialog.value, "the generated value")]
    dialog.reject()
    assert dialog.value == ""  # nothing lingers after the dialog is closed


def test_audit_lists_findings_and_jumps_to_an_entry(
    qtbot: QtBot, settings: QSettings, make_vault: MakeVault, dialogs: Dialogs
) -> None:
    path = make_vault(
        [
            Entry(title="One", password="Shared-Pass-1234567890"),
            Entry(title="Two", password="Shared-Pass-1234567890"),
            Entry(title="Weak", password="dragon"),
        ]
    )
    win = make_window(qtbot, settings, path)
    select(win, "One")

    def inspect(dialog: QDialog) -> None:
        assert isinstance(dialog, AuditDialog)
        kinds = [dialog.table.item(row, 0).text() for row in range(dialog.table.rowCount())]
        assert kinds.count("REUSED") == 2
        assert "WEAK" in kinds
        assert "finding(s)" in dialog.summary.text()
        dialog._jump(kinds.index("WEAK"), 0)

    dialogs.expect(inspect)
    win.open_audit()
    assert win.vault_view.detail.entry is not None
    assert win.vault_view.detail.entry.title == "Weak"


def test_saving_again_after_a_failed_save_really_saves(
    unlocked: MainWindow, dialogs: Dialogs, vault_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression: the editor compared against the live entry, which the failed
    # save had already modified before the rollback. The retry then looked like
    # "nothing changed" and closed the dialog without saving anything.
    real_write = storage.atomic_write
    attempts: list[Path] = []

    def full_once(path: Path, data: bytes) -> None:
        attempts.append(path)
        if len(attempts) == 1:
            raise OSError(errno.ENOSPC, "No space left on device", str(path))
        real_write(path, data)

    def fill(dialog: QDialog) -> None:
        assert isinstance(dialog, EntryDialog)
        dialog.username.setText("changed-user")
        dialog.try_accept()
        assert "No space left" in dialog.error.text()
        dialog.try_accept()  # space freed, Save clicked again
        assert dialog.result() == QDialog.DialogCode.Accepted

    monkeypatch.setattr(storage, "atomic_write", full_once)
    select(unlocked, "Bank")
    dialogs.expect(fill)
    unlocked.edit_entry()
    assert open_vault(vault_file).contents.find("Bank", fuzzy=False).username == "changed-user"


def test_revealed_secret_fields_never_reach_the_system_clipboard(qtbot: QtBot, unlocked: MainWindow) -> None:
    entry = select(unlocked, "GitHub")
    dialog = EntryDialog(lambda form: True, unlocked.copy_value, entry, unlocked)
    qtbot.addWidget(dialog)
    QGuiApplication.clipboard().setText("before")
    dialog.password.reveal.setChecked(True)
    dialog.password.edit.selectAll()
    qtbot.keyClick(dialog.password.edit, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    qtbot.keyClick(dialog.password.edit, Qt.Key.Key_X, Qt.KeyboardModifier.ControlModifier)
    assert QGuiApplication.clipboard().text() == "before"
    assert dialog.password.text() == "gh-Secret-1"  # Ctrl+X did not cut it either
    assert dialog.password.edit.contextMenuPolicy() == Qt.ContextMenuPolicy.NoContextMenu


def test_remove_totp_disables_the_secret_field(qtbot: QtBot, unlocked: MainWindow) -> None:
    entry = select(unlocked, "GitHub")
    dialog = EntryDialog(lambda form: True, unlocked.copy_value, entry, unlocked)
    qtbot.addWidget(dialog)
    dialog.remove_totp.setChecked(True)
    assert not dialog.totp.isEnabled()
    assert dialog.form().totp == ""


def test_double_click_opens_the_editor(qtbot: QtBot, unlocked: MainWindow, dialogs: Dialogs) -> None:
    entry = select(unlocked, "Bank")
    view = unlocked.vault_view
    row = view.model.row_of(entry.id)
    assert row is not None
    center = view.table.visualRect(view.model.index(row, 0)).center()

    def check(dialog: QDialog) -> None:
        assert isinstance(dialog, EntryDialog)
        assert dialog.title.text() == "Bank"
        dialog.reject()

    dialogs.expect(check)
    qtbot.mouseClick(view.table.viewport(), Qt.MouseButton.LeftButton, pos=center)
    qtbot.mouseDClick(view.table.viewport(), Qt.MouseButton.LeftButton, pos=center)
    assert dialogs.seen == ["EntryDialog"]
