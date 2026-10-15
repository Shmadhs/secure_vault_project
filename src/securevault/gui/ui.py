"""Safe building blocks shared by every window: plain-text display, messages, dialogs, workers.

Two rules are enforced here so that no widget can forget them:

* **Vault data is shown as plain text, after** :func:`cli.term_safe`. Qt's
  QLabel, QMessageBox and tooltips guess whether a string is HTML
  (``Qt.AutoText``). An imported title such as ``<img src=...>`` or
  ``<a href=...>`` would then be rendered as markup. Every label and message
  here is pinned to ``Qt.PlainText``, and ``term_safe`` additionally escapes
  control characters and bidi overrides, which can make one title look like
  another (``moc.lapyap`` displayed as ``paypal.com``).
* **Argon2id never runs on the GUI thread.** Unlocking takes about a second
  with up to 1 GiB of memory. On the GUI thread the window would freeze and
  Windows would mark it "Not responding".
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Generic, TypeVar

from PySide6.QtCore import QEventLoop, Qt, QThread
from PySide6.QtWidgets import QDialog, QFileDialog, QLabel, QMessageBox, QProgressDialog, QWidget

from ..cli import term_safe

T = TypeVar("T")

Icon = QMessageBox.Icon
Button = QMessageBox.StandardButton


def display(text: str, *, multiline: bool = False) -> str:
    """Vault text as it may be displayed: control characters and bidi overrides escaped."""
    return term_safe(text, multiline=multiline)


def has_unsafe(text: str) -> bool:
    """True if ``text`` contains characters that :func:`display` would escape."""
    return term_safe(text, multiline=True) != text


def plain_label(text: str = "", parent: QWidget | None = None) -> QLabel:
    label = QLabel(parent)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setText(text)
    return label


def message(
    parent: QWidget | None,
    icon: QMessageBox.Icon,
    title: str,
    text: str,
    *,
    buttons: QMessageBox.StandardButton = Button.Ok,
    default: QMessageBox.StandardButton = Button.NoButton,
) -> QMessageBox.StandardButton:
    """Modal message box with plain-text content. Every message in the GUI goes through here."""
    box = QMessageBox(icon, title, text, buttons, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    if default != Button.NoButton:
        box.setDefaultButton(default)
    try:
        return Button(box.exec())
    finally:
        box.deleteLater()


def error(parent: QWidget | None, title: str, text: str) -> None:
    message(parent, Icon.Critical, title, text)


def warning(parent: QWidget | None, title: str, text: str) -> None:
    message(parent, Icon.Warning, title, text)


def info(parent: QWidget | None, title: str, text: str) -> None:
    message(parent, Icon.Information, title, text)


def ask(parent: QWidget | None, title: str, text: str, *, icon: QMessageBox.Icon = Icon.Question) -> bool:
    """Yes/No question; No is the default so Enter never confirms something destructive."""
    buttons = Button.Yes | Button.No
    return message(parent, icon, title, text, buttons=buttons, default=Button.No) == Button.Yes


def run_dialog(dialog: QDialog) -> bool:
    """Show ``dialog`` modally and report whether it was accepted. Tests replace this hook."""
    return dialog.exec() == QDialog.DialogCode.Accepted


def choose_path(
    parent: QWidget | None, caption: str, start: str, file_filter: str, *, save: bool = False
) -> Path | None:
    """The system file picker. Every file choice goes through here, so tests can replace it."""
    if save:
        chosen, _ = QFileDialog.getSaveFileName(parent, caption, start, file_filter)
    else:
        chosen, _ = QFileDialog.getOpenFileName(parent, caption, start, file_filter)
    return Path(chosen) if chosen else None


class _Worker(QThread, Generic[T]):
    def __init__(self, fn: Callable[[], T]) -> None:
        super().__init__()
        self._fn = fn
        self.result: T | None = None
        self.error: BaseException | None = None

    def run(self) -> None:
        try:
            self.result = self._fn()
        except BaseException as exc:  # re-raised on the GUI thread by run_blocking
            self.error = exc


# Called with +1 / -1 around every blocking operation. The main window uses it to
# hold off the idle lock while a key derivation is running.
busy_hooks: list[Callable[[int], None]] = []


def run_blocking(parent: QWidget | None, text: str, fn: Callable[[], T]) -> T:
    """Run ``fn`` on a worker thread and wait for it without freezing the window.

    The local event loop keeps repainting, but excludes user input, so nothing
    can be clicked while the vault is half-way through an operation. Any
    exception from ``fn`` is re-raised here, on the GUI thread.
    """
    for hook in busy_hooks:
        hook(+1)
    worker: _Worker[T] = _Worker(fn)
    progress = QProgressDialog(text, "", 0, 0, parent)
    progress.setLabel(plain_label(text))
    progress.setCancelButton(None)
    progress.setWindowModality(Qt.WindowModality.WindowModal)
    progress.setMinimumDuration(400)
    progress.setWindowTitle("SecureVault")
    loop = QEventLoop()
    worker.finished.connect(loop.quit)
    try:
        worker.start()
        loop.exec(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)
        worker.wait()
    finally:
        progress.close()
        progress.deleteLater()
        for hook in busy_hooks:
            hook(-1)
    if worker.error is not None:
        raise worker.error
    return worker.result  # type: ignore[return-value]  # set whenever error is None
