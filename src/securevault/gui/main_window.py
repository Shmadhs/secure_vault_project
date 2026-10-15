"""The main window: unlock screen, entry list, detail pane, and every vault action.

Locking is more than ``Vault.lock()``. The key and the decrypted contents are
dropped by the core, but the GUI holds its own references: the list model, the
detail pane, the TOTP secret, and any open dialog (an editor holds a password in
a QLineEdit). :meth:`MainWindow.lock` clears all of them and closes every
dialog. Python cannot wipe those strings from memory (see the threat model);
dropping every reference is what the GUI can do.
"""

from __future__ import annotations

import contextlib
import subprocess  # nosec B404 - imported only for its exception type
from collections.abc import Callable, Iterable
from dataclasses import replace
from pathlib import Path
from typing import Any, Protocol

from PySide6.QtCore import (
    QAbstractTableModel,
    QEvent,
    QModelIndex,
    QPersistentModelIndex,
    QSettings,
    Qt,
    QTimer,
)
from PySide6.QtGui import QAction, QCloseEvent, QFontDatabase, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableView,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .. import __version__, clipboard, totp
from ..errors import EntryNotFoundError, VaultConflictError, VaultError
from ..model import Entry, VaultContents
from . import prefs as prefs_store
from . import ui
from .entry_dialogs import DeleteDialog, EntryDialog, EntryForm
from .generator_dialog import GeneratorDialog
from .guards import EventGuard, IdleTimer
from .prefs import Preferences
from .session import Session
from .unlock import UnlockView
from .vault_dialogs import AuditDialog, BackupsDialog, PasswdDialog, PreferencesDialog, describe

MASK = "•" * 10  # fixed width, like `svault show`: the length of the password is not revealed
_CLIPBOARD_ERRORS = (clipboard.ClipboardUnavailableError, OSError, subprocess.SubprocessError)


class Copier(Protocol):
    """Copies a value through the core clipboard (see :meth:`MainWindow.copy_value`)."""

    def __call__(self, value: str, label: str, seconds: int | None = None) -> None: ...


def _find(contents: VaultContents, entry_id: str) -> Entry:
    for entry in contents.entries:
        if entry.id == entry_id:
            return entry
    raise EntryNotFoundError("the entry no longer exists")


def _apply_edit(contents: VaultContents, entry_id: str, form: EntryForm) -> None:
    """The GUI equivalent of ``cmd_edit``: same model calls, same order."""
    entry = _find(contents, entry_id)
    if form.title is not None:
        contents.rename(entry, form.title)
    if form.username is not None:
        entry.username = form.username
    if form.url is not None:
        entry.url = form.url
    if form.notes is not None:
        entry.notes = form.notes
    if form.tags is not None:
        entry.tags = form.tags
    if form.password is not None:
        entry.set_password(form.password)  # keeps the old one in the history
    if form.totp is not None:
        entry.totp = form.totp
    entry.touch()


def _new_entry(form: EntryForm) -> Entry:
    return Entry(
        title=form.title or "",
        username=form.username or "",
        password=form.password or "",
        url=form.url or "",
        notes=form.notes or "",
        tags=form.tags or [],
        totp=form.totp or "",
    )


class EntryTableModel(QAbstractTableModel):
    """Entries shown in the list. Every cell goes through ``display()``; the model is never editable."""

    HEADERS = ("Title", "Username", "URL", "Tags")

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._entries: list[Entry] = []

    def set_entries(self, entries: Iterable[Entry]) -> None:
        self.beginResetModel()
        self._entries = list(entries)
        self.endResetModel()

    def clear(self) -> None:
        self.set_entries([])

    def entry(self, row: int) -> Entry | None:
        return self._entries[row] if 0 <= row < len(self._entries) else None

    def row_of(self, entry_id: str) -> int | None:
        for row, entry in enumerate(self._entries):
            if entry.id == entry_id:
                return row
        return None

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.HEADERS)

    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        entry = self.entry(index.row())
        if entry is None or role != Qt.ItemDataRole.DisplayRole:
            return None
        values = (entry.title, entry.username, entry.url, ", ".join(entry.tags))
        return ui.display(values[index.column()])

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.HEADERS[section]
        return None


class DetailPane(QWidget):
    """One entry: masked password with a reveal toggle, copy buttons, live TOTP code, notes."""

    def __init__(self, copy: Copier, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._copy = copy
        self._entry: Entry | None = None
        self._totp: totp.TotpConfig | None = None

        self.title = ui.plain_label("", self)
        font = self.title.font()
        font.setPointSize(font.pointSize() + 4)
        font.setBold(True)
        self.title.setFont(font)
        self.title.setWordWrap(True)
        self.username = ui.plain_label("", self)
        self.password = ui.plain_label("", self)
        self.password.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.password.setWordWrap(True)
        self.url = ui.plain_label("", self)
        self.url.setWordWrap(True)
        self.tags = ui.plain_label("", self)
        self.totp_code = ui.plain_label("", self)
        code_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        code_font.setPointSize(code_font.pointSize() + 6)
        self.totp_code.setFont(code_font)
        self.totp_bar = QProgressBar(self)
        self.totp_bar.setTextVisible(True)
        self.totp_bar.setMaximumWidth(160)
        self.meta = ui.plain_label("", self)
        self.meta.setWordWrap(True)
        self.notes = QPlainTextEdit(self)
        self.notes.setReadOnly(True)
        # Copy goes through the Copy buttons (auto-clear, history exclusion), not Ctrl+C.
        self.notes.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)

        self.reveal = QToolButton(self)
        self.reveal.setText("Show")
        self.reveal.setCheckable(True)
        self.reveal.toggled.connect(self._render_password)
        self.copy_username = QPushButton("Copy", self)
        self.copy_password = QPushButton("Copy", self)
        self.copy_url = QPushButton("Copy", self)
        self.copy_totp = QPushButton("Copy", self)
        self.copy_notes = QPushButton("Copy notes", self)
        self.copy_username.clicked.connect(lambda: self.copy_field("username"))
        self.copy_password.clicked.connect(lambda: self.copy_field("password"))
        self.copy_url.clicked.connect(lambda: self.copy_field("url"))
        self.copy_notes.clicked.connect(lambda: self.copy_field("notes"))
        self.copy_totp.clicked.connect(self.copy_code)

        def row(*widgets: QWidget) -> QHBoxLayout:
            layout = QHBoxLayout()
            layout.addWidget(widgets[0], 1)
            for widget in widgets[1:]:
                layout.addWidget(widget)
            return layout

        self.form = QFormLayout()
        self.form.addRow("Username:", row(self.username, self.copy_username))
        self.form.addRow("Password:", row(self.password, self.reveal, self.copy_password))
        self.form.addRow("URL:", row(self.url, self.copy_url))
        self.form.addRow("Tags:", self.tags)
        self.form.addRow("TOTP:", row(self.totp_code, self.totp_bar, self.copy_totp))
        self.placeholder = ui.plain_label("", self)
        self.placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.placeholder.setWordWrap(True)

        self.body = QWidget(self)
        body = QVBoxLayout(self.body)
        body.setContentsMargins(0, 0, 0, 0)
        body.addWidget(self.title)
        body.addLayout(self.form)
        body.addWidget(ui.plain_label("Notes:", self.body))
        body.addWidget(self.notes, 1)
        body.addWidget(self.copy_notes, 0, Qt.AlignmentFlag.AlignRight)
        body.addWidget(self.meta)
        layout = QVBoxLayout(self)
        layout.addWidget(self.placeholder)
        layout.addWidget(self.body)

        self._timer = QTimer(self)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._tick)
        self.show_entry(None)

    @property
    def entry(self) -> Entry | None:
        return self._entry

    def show_entry(self, entry: Entry | None, placeholder: str = "Select an entry.") -> None:
        self._entry = entry
        self._totp = None
        self._timer.stop()
        self.reveal.setChecked(False)  # never carry a revealed password over to another entry
        if entry is None:
            self.body.hide()
            self.placeholder.setText(placeholder)
            self.placeholder.show()
            self._blank()
            return
        self.placeholder.hide()
        self.body.show()
        self.title.setText(ui.display(entry.title))
        self.username.setText(ui.display(entry.username))
        self.url.setText(ui.display(entry.url))
        self.tags.setText(ui.display(", ".join(entry.tags)))
        self.notes.setPlainText(ui.display(entry.notes, multiline=True))
        history = f" · {len(entry.history)} previous password(s)" if entry.history else ""
        self.meta.setText(ui.display(f"Created {entry.created} · modified {entry.modified}{history} · id {entry.id}"))
        self.copy_username.setEnabled(bool(entry.username))
        self.copy_password.setEnabled(bool(entry.password))
        self.reveal.setEnabled(bool(entry.password))
        self.copy_url.setEnabled(bool(entry.url))
        self.copy_notes.setEnabled(bool(entry.notes))
        self._render_password()
        if entry.totp:
            try:
                self._totp = totp.parse(entry.totp)
            except totp.TotpError as exc:
                self.totp_code.setText(ui.display(f"invalid: {exc}"))
        else:
            self.totp_code.setText("")
        self.totp_bar.setVisible(self._totp is not None)
        self.copy_totp.setEnabled(self._totp is not None)
        if self._totp is not None:
            self._tick()
            self._timer.start()

    def _blank(self) -> None:
        for label in (self.title, self.username, self.password, self.url, self.tags, self.totp_code, self.meta):
            label.clear()
        self.notes.clear()

    def clear(self) -> None:
        self.show_entry(None, "")

    def _render_password(self) -> None:
        entry = self._entry
        if entry is None or not entry.password:
            self.password.setText("")
            return
        revealed = self.reveal.isChecked()
        self.reveal.setText("Hide" if revealed else "Show")
        self.password.setText(ui.display(entry.password) if revealed else MASK)

    def _tick(self) -> None:
        if self._totp is None:
            self._timer.stop()
            return
        code, remaining = totp.now(self._totp)
        self.totp_code.setText(code)
        self.totp_bar.setRange(0, self._totp.period)
        self.totp_bar.setValue(remaining)
        self.totp_bar.setFormat(f"{remaining} s")

    def copy_field(self, name: str) -> None:
        entry = self._entry
        if entry is None:
            return
        value: str = getattr(entry, name)
        if value:
            self._copy(value, f"the {name} of '{ui.display(entry.title)}'")

    def copy_code(self) -> None:
        if self._entry is None or self._totp is None:
            return
        code, remaining = totp.now(self._totp)
        # Same as `svault totp --copy`: cleared once the code has expired.
        self._copy(code, f"the TOTP code ({remaining} s left)", seconds=remaining + 1)


class VaultView(QWidget):
    """Search box, tag filter and entry list on the left; the detail pane on the right."""

    def __init__(self, copy: Copier, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.search = QLineEdit(self)
        self.search.setPlaceholderText("Search titles, usernames, URLs, tags and notes")
        self.search.setClearButtonEnabled(True)
        self.tag = QComboBox(self)
        self.tag.setMinimumWidth(140)
        self.model = EntryTableModel(self)
        self.table = QTableView(self)
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setWordWrap(False)
        self.count = ui.plain_label("", self)
        self.detail = DetailPane(copy, self)

        left = QWidget(self)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        filters = QHBoxLayout()
        filters.addWidget(self.search, 1)
        filters.addWidget(self.tag)
        left_layout.addLayout(filters)
        left_layout.addWidget(self.table, 1)
        left_layout.addWidget(self.count)
        splitter = QSplitter(self)
        splitter.addWidget(left)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout = QVBoxLayout(self)
        layout.addWidget(splitter)

    def selected_entry(self) -> Entry | None:
        rows = self.table.selectionModel().selectedRows()
        return self.model.entry(rows[0].row()) if rows else None

    def select(self, entry_id: str | None) -> None:
        row = self.model.row_of(entry_id) if entry_id else None
        if row is None:
            row = 0 if self.model.rowCount() else None
        if row is None:
            self.table.clearSelection()
            return
        self.table.selectRow(row)
        self.table.scrollTo(self.model.index(row, 0))

    def set_tags(self, tags: Iterable[str]) -> None:
        current = self.tag.currentData()
        self.tag.blockSignals(True)
        self.tag.clear()
        self.tag.addItem("All tags", "")
        for tag in sorted(set(tags), key=str.casefold):
            self.tag.addItem(ui.display(tag), tag)  # display text sanitized; the raw tag is the filter value
        index = self.tag.findData(current) if current else 0
        self.tag.setCurrentIndex(max(index, 0))
        self.tag.blockSignals(False)

    def purge(self) -> None:
        self.model.clear()
        self.detail.clear()
        self.search.clear()
        self.tag.blockSignals(True)
        self.tag.clear()
        self.tag.blockSignals(False)
        self.count.clear()


class MainWindow(QMainWindow):
    def __init__(
        self,
        settings: QSettings,
        vault_path: Path,
        keyfile_path: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._settings = settings
        self.prefs: Preferences = prefs_store.load(settings)
        self._session: Session | None = None
        self._clipboard_fingerprint: bytes | None = None
        self._busy = 0
        self._pending_lock: str | None = None

        self.idle = IdleTimer(self.prefs.idle_minutes * 60_000, self)
        self.idle.expired.connect(lambda: self.lock("after inactivity"))
        self.guard = EventGuard(self.idle, self)
        self.guard.exclude_from_capture = self.prefs.hide_from_capture
        app = QApplication.instance()
        if isinstance(app, QApplication):
            self.guard.install(app)
        hook = self._on_busy
        ui.busy_hooks.append(hook)

        # A window destroyed without a close event must not leave a hook behind
        # that would call into a deleted C++ object.
        def drop_hook() -> None:
            if hook in ui.busy_hooks:
                ui.busy_hooks.remove(hook)

        self.destroyed.connect(drop_hook)

        self.unlock_view = UnlockView(vault_path, keyfile_path, self._on_unlocked, self)
        self.vault_view = VaultView(self.copy_value, self)
        self.vault_view.search.textChanged.connect(self.refresh)
        self.vault_view.tag.currentIndexChanged.connect(self.refresh)
        self.vault_view.table.selectionModel().selectionChanged.connect(lambda *_: self._show_selected())
        self.vault_view.table.doubleClicked.connect(self.edit_entry)
        self.stack = QStackedWidget(self)
        self.stack.addWidget(self.unlock_view)
        self.stack.addWidget(self.vault_view)
        self.setCentralWidget(self.stack)
        self._build_actions()
        self.resize(1000, 640)
        self._show_locked("")

    # ------------------------------------------------------------------ setup

    def _action(
        self,
        text: str,
        slot: Callable[[], object],
        shortcut: QKeySequence | QKeySequence.StandardKey | str | None = None,
    ) -> QAction:
        action = QAction(text, self)
        if shortcut is not None:
            action.setShortcut(QKeySequence(shortcut))
        action.triggered.connect(lambda _checked=False: slot())
        self.addAction(action)
        return action

    def _build_actions(self) -> None:
        self.act_new = self._action("&New entry…", self.new_entry, QKeySequence.StandardKey.New)
        self.act_edit = self._action("&Edit entry…", self.edit_entry, "Ctrl+E")
        self.act_delete = self._action("&Delete entry…", self.delete_entry, QKeySequence.StandardKey.Delete)
        self.act_copy_user = self._action(
            "Copy &username", lambda: self.vault_view.detail.copy_field("username"), "Ctrl+B"
        )
        self.act_copy_pass = self._action(
            "Copy &password", lambda: self.vault_view.detail.copy_field("password"), "Ctrl+C"
        )
        self.act_copy_url = self._action("Copy U&RL", lambda: self.vault_view.detail.copy_field("url"), "Ctrl+U")
        self.act_copy_totp = self._action("Copy &TOTP code", self.vault_view.detail.copy_code, "Ctrl+T")
        self.act_generator = self._action("&Generator…", self.open_generator, "Ctrl+G")
        self.act_audit = self._action("Password &health…", self.open_audit)
        self.act_passwd = self._action("Change &master password…", self.change_master_password)
        self.act_backups = self._action("&Backups…", self.open_backups)
        self.act_prefs = self._action("&Preferences…", self.open_preferences)
        self.act_lock = self._action("&Lock", lambda: self.lock("by you"), "Ctrl+L")
        self.act_quit = self._action("&Quit", self.close, QKeySequence.StandardKey.Quit)
        self.act_find = self._action("&Find", self.vault_view.search.setFocus, QKeySequence.StandardKey.Find)

        bar = self.menuBar()
        vault_menu = bar.addMenu("&Vault")
        for action in (self.act_lock, self.act_passwd, self.act_backups, self.act_prefs):
            vault_menu.addAction(action)
        vault_menu.addSeparator()
        vault_menu.addAction(self.act_quit)
        entry_menu = bar.addMenu("&Entry")
        for action in (self.act_new, self.act_edit, self.act_delete):
            entry_menu.addAction(action)
        entry_menu.addSeparator()
        for action in (self.act_copy_user, self.act_copy_pass, self.act_copy_url, self.act_copy_totp):
            entry_menu.addAction(action)
        tools_menu = bar.addMenu("&Tools")
        for action in (self.act_generator, self.act_audit, self.act_find):
            tools_menu.addAction(action)
        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)
        for action in (self.act_new, self.act_edit, self.act_delete, self.act_generator, self.act_audit, self.act_lock):
            toolbar.addAction(action)
        self._vault_actions = [
            self.act_new,
            self.act_edit,
            self.act_delete,
            self.act_copy_user,
            self.act_copy_pass,
            self.act_copy_url,
            self.act_copy_totp,
            self.act_audit,
            self.act_passwd,
            self.act_lock,
            self.act_find,
        ]

    def _update_actions(self) -> None:
        unlocked = self._session is not None
        selected = unlocked and self.vault_view.detail.entry is not None
        for action in self._vault_actions:
            action.setEnabled(unlocked)
        for action in (self.act_edit, self.act_delete, self.act_copy_user, self.act_copy_pass, self.act_copy_url):
            action.setEnabled(selected)
        self.act_copy_totp.setEnabled(selected and self.vault_view.detail.copy_totp.isEnabled())

    # ------------------------------------------------------------------ state

    @property
    def session(self) -> Session | None:
        return self._session

    def _on_unlocked(self, session: Session) -> None:
        self._session = session
        self.prefs = replace(self.prefs, last_vault=str(session.path))
        prefs_store.save(self._settings, self.prefs)
        self.setWindowTitle(f"SecureVault — {ui.display(session.path.name)}")
        self.stack.setCurrentWidget(self.vault_view)
        self.refresh()
        if not len(session.contents):
            self.vault_view.detail.show_entry(None, "The vault is empty. Add an entry with New entry.")
        self.vault_view.search.setFocus()
        self.idle.arm()
        self._update_actions()
        self.statusBar().showMessage("Vault unlocked.", 5000)

    def _show_locked(self, reason: str) -> None:
        self.setWindowTitle("SecureVault")
        self.stack.setCurrentWidget(self.unlock_view)
        self.unlock_view.reset()
        self._update_actions()
        self.statusBar().showMessage(f"Locked {reason}." if reason else f"SecureVault {__version__}")

    def lock(self, reason: str = "") -> None:
        """Lock the vault and drop every reference the GUI holds to its contents."""
        if self._busy:
            # A key derivation is running on a worker thread. The vault's mutex
            # would make locking safe, but the dialog that started the work
            # would then resume on a locked vault. Lock as soon as it is done.
            self._pending_lock = reason
            return
        session, self._session = self._session, None
        if session is not None:
            session.lock()
        self.idle.disarm()
        self.vault_view.purge()
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QDialog) and widget.isVisible():
                widget.reject()
        self._clear_clipboard()
        self._show_locked(reason)

    def _on_busy(self, delta: int) -> None:
        self._busy = max(0, self._busy + delta)
        self.idle.busy(delta)
        if not self._busy and self._pending_lock is not None:
            reason, self._pending_lock = self._pending_lock, None
            QTimer.singleShot(0, lambda: self.lock(reason))

    def changeEvent(self, event: QEvent) -> None:
        super().changeEvent(event)
        if (
            event.type() == QEvent.Type.WindowStateChange
            and self.isMinimized()
            and self.prefs.lock_on_minimize
            and self._session is not None
        ):
            self.lock("when minimized")

    def closeEvent(self, event: QCloseEvent) -> None:
        self._busy = 0
        self.lock()
        if self._on_busy in ui.busy_hooks:
            ui.busy_hooks.remove(self._on_busy)
        super().closeEvent(event)

    # ------------------------------------------------------------------ list

    def refresh(self) -> None:
        session = self._session
        view = self.vault_view
        if session is None:
            return
        keep = view.detail.entry.id if view.detail.entry else None
        contents = session.contents
        term = view.search.text().strip()
        entries = contents.search(term) if term else list(contents)
        view.set_tags(tag for entry in contents.entries for tag in entry.tags)
        tag = str(view.tag.currentData() or "")
        if tag:
            entries = [e for e in entries if tag.casefold() in (t.casefold() for t in e.tags)]
        view.model.set_entries(entries)
        view.count.setText(f"{len(entries)} of {len(contents)} entries")
        view.select(keep)
        self._show_selected(force=True)  # an edited entry is the same object, so re-render it

    def _show_selected(self, *, force: bool = False) -> None:
        if self._session is None:
            return
        entry = self.vault_view.selected_entry()
        detail = self.vault_view.detail
        if force or entry is not detail.entry or entry is None:
            empty = not len(self._session.contents)
            detail.show_entry(
                entry, "The vault is empty. Add an entry with New entry." if empty else "Select an entry."
            )
        self._update_actions()

    def select_entry(self, entry_id: str) -> None:
        self.vault_view.search.clear()
        self.vault_view.tag.setCurrentIndex(0)
        self.refresh()
        self.vault_view.select(entry_id)

    # ------------------------------------------------------------------ changes

    def _commit(self, change: Callable[[VaultContents], object]) -> bool:
        """Save a change through the session. False if the vault had to be locked instead.

        Errors the user can fix propagate; on a conflict (the file changed on
        disk since it was opened) the change is rolled back and the vault
        locked, so the next unlock loads the current file.
        """
        session = self._session
        if session is None:
            return False
        try:
            session.commit(change)
        except VaultConflictError as exc:
            self.lock("because the file changed on disk")
            ui.warning(
                self,
                "Vault changed on disk",
                f"{describe(exc)}.\n\nYour change was not saved. Unlock again to load the current "
                "version of the vault, then repeat it.",
            )
            return False
        finally:
            self.refresh()
        return True

    def _run(self, dialog: QDialog) -> bool:
        """Run a dialog; accepted only if the vault is still unlocked afterwards."""
        try:
            return ui.run_dialog(dialog) and self._session is not None
        finally:
            dialog.deleteLater()

    def new_entry(self) -> None:
        if self._session is None:
            return
        added: list[str] = []

        def apply(form: EntryForm) -> bool:
            entry = _new_entry(form)
            added.append(entry.id)
            return self._commit(lambda contents: contents.add(entry))

        if self._run(EntryDialog(apply, self.copy_value, None, self)) and added:
            self.select_entry(added[-1])
            self.statusBar().showMessage("Entry added.", 5000)

    def edit_entry(self) -> None:
        entry = self.vault_view.detail.entry
        if self._session is None or entry is None:
            return
        entry_id = entry.id

        def apply(form: EntryForm) -> bool:
            return self._commit(lambda contents: _apply_edit(contents, entry_id, form))

        if self._run(EntryDialog(apply, self.copy_value, entry, self)):
            self.select_entry(entry_id)
            self.statusBar().showMessage("Entry updated.", 5000)

    def delete_entry(self) -> None:
        entry = self.vault_view.detail.entry
        if self._session is None or entry is None:
            return
        shown, entry_id = ui.display(entry.title), entry.id
        if not self._run(DeleteDialog(shown, self)):
            return
        try:
            done = self._commit(lambda contents: contents.remove(_find(contents, entry_id)))
        except (VaultError, OSError) as exc:
            ui.error(self, "Not deleted", describe(exc))
            return
        if done:
            self.statusBar().showMessage(f"Deleted '{shown}'. A previous version remains in the encrypted backups.")

    # ------------------------------------------------------------------ tools

    def copy_value(self, value: str, label: str, seconds: int | None = None) -> None:
        """Copy through the core clipboard, exactly like the CLI's ``_deliver``."""
        delay = self.prefs.clear_seconds if seconds is None else seconds
        try:
            scheduled = clipboard.copy_with_autoclear(value, delay)
        except _CLIPBOARD_ERRORS as exc:
            ui.error(self, "Clipboard unavailable", f"Could not copy: {describe(exc)}")
            return
        self._clipboard_fingerprint = clipboard.fingerprint(value)
        tail = f"; it will be cleared in {delay} s" if scheduled else ""
        self.statusBar().showMessage(f"Copied {label} to the clipboard{tail}.", 8000)
        if delay > 0 and not scheduled:
            ui.warning(self, "Clipboard", "Could not start the auto-clear helper; clear the clipboard yourself.")

    def _clear_clipboard(self) -> None:
        """On lock and exit, remove our last copied value, but only if it is still there."""
        expected, self._clipboard_fingerprint = self._clipboard_fingerprint, None
        if expected is None:
            return
        with contextlib.suppress(*_CLIPBOARD_ERRORS):  # the detached helper still clears it on schedule
            clipboard.clear_if_unchanged(clipboard.get_clipboard(), expected)

    def open_generator(self) -> None:
        self._run(GeneratorDialog(self.copy_value, parent=self))

    def open_audit(self) -> None:
        if self._session is None:
            return
        dialog = AuditDialog(self._session.contents, self)
        if self._run(dialog) and dialog.selected_id:
            self.select_entry(dialog.selected_id)

    def change_master_password(self) -> None:
        session = self._session
        if session is None:
            return
        dialog = PasswdDialog(session, self)
        accepted = self._run(dialog)
        if dialog.conflict is not None:
            self.lock("because the file changed on disk")
            ui.warning(self, "Vault changed on disk", f"{describe(dialog.conflict)}.\n\nThe password was not changed.")
            return
        if not accepted:
            return
        removed = dialog.removed_backups
        text = "Master password changed. The vault key was rotated and everything re-encrypted."
        if removed:
            text += f"\n\nRemoved {removed} old backup(s) encrypted under the previous key."
        ui.info(self, "Master password changed", text)

    def open_backups(self) -> None:
        session = self._session
        if session is None:
            self.unlock_view.open_backups()
            return
        dialog = BackupsDialog(session.path, session.keyfile_path, self)
        if self._run(dialog) and dialog.restored:
            name, count = dialog.restored
            # The open session's view of the file is now stale (its saved digest
            # no longer matches), so it must be locked and re-opened.
            self.lock("after the restore")
            ui.info(self, "Backup restored", f"Restored {count} entries from {name}. Unlock to open it.")

    def open_preferences(self) -> None:
        dialog = PreferencesDialog(self.prefs, self)
        if not ui.run_dialog(dialog):
            dialog.deleteLater()
            return
        self.prefs = dialog.preferences()
        dialog.deleteLater()
        prefs_store.save(self._settings, self.prefs)
        self.idle.set_interval(self.prefs.idle_minutes * 60_000)
        self.guard.exclude_from_capture = self.prefs.hide_from_capture
        self.guard.apply_capture_policy()
        self.statusBar().showMessage("Preferences saved.", 5000)
