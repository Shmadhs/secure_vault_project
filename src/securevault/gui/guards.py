"""Application-wide protections: the idle lock and exclusion from screen capture.

Idle lock
    The CLI shell locks from a ``threading.Timer``, which is why ``Vault.lock()``
    takes a mutex: the timer thread could otherwise zeroize the key in the
    middle of a save. Here the timer is a ``QTimer``, which fires on the GUI
    thread, the same thread that performs every save, so a lock can never
    interleave one. The only save that runs elsewhere is ``passwd`` on a worker
    thread; the idle lock is paused for its duration (see ``ui.busy_hooks``),
    and the vault's mutex still guards it as a second line of defense.

    Key presses, clicks and the mouse wheel count as activity. Mere mouse
    movement does not: a nudged mouse should not keep an unattended vault open.

Screen capture (Windows)
    ``SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`` makes a window appear
    blank in screenshots, recordings and screen sharing (Teams, Zoom). It is
    applied to every top-level window as it is first shown, dialogs included,
    since the entry editor and the generator display passwords too.
"""

from __future__ import annotations

import sys

from PySide6.QtCore import QEvent, QObject, QTimer, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication, QWidget

_ACTIVITY = frozenset(
    {
        QEvent.Type.KeyPress,
        QEvent.Type.MouseButtonPress,
        QEvent.Type.MouseButtonDblClick,
        QEvent.Type.Wheel,
        QEvent.Type.TouchBegin,
    }
)

WDA_NONE = 0x00
WDA_MONITOR = 0x01
WDA_EXCLUDEFROMCAPTURE = 0x11  # Windows 10 2004+; older versions only support WDA_MONITOR


def set_capture_exclusion(widget: QWidget, exclude: bool) -> bool:
    """Hide (or show again) a top-level window from screen capture. Windows only."""
    # The offscreen platform (tests, CI) hands out fake window ids, not HWNDs.
    if sys.platform != "win32" or QGuiApplication.platformName() != "windows":
        return False
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
    user32.SetWindowDisplayAffinity.restype = wintypes.BOOL
    hwnd = wintypes.HWND(int(widget.winId()))
    if not exclude:
        return bool(user32.SetWindowDisplayAffinity(hwnd, WDA_NONE))
    if user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE):
        return True
    # Before Windows 10 2004 the window can at least be shown as a black box.
    return bool(user32.SetWindowDisplayAffinity(hwnd, WDA_MONITOR))


CAPTURE_EXCLUSION_SUPPORTED = sys.platform == "win32"


class IdleTimer(QObject):
    """Emits :attr:`expired` after ``interval_ms`` without user activity, while armed."""

    expired = Signal()

    def __init__(self, interval_ms: int, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._interval = interval_ms
        self._armed = False
        self._busy = 0
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._fire)

    @property
    def interval_ms(self) -> int:
        return self._interval

    def set_interval(self, interval_ms: int) -> None:
        self._interval = interval_ms
        self.poke()

    def arm(self) -> None:
        self._armed = True
        self.poke()

    def disarm(self) -> None:
        self._armed = False
        self._timer.stop()

    def poke(self) -> None:
        """Register activity: restart the countdown."""
        if self._armed and self._interval > 0:
            self._timer.start(self._interval)
        else:
            self._timer.stop()

    def busy(self, delta: int) -> None:
        """Hold off expiry while a blocking operation runs; restart the countdown afterwards."""
        self._busy = max(0, self._busy + delta)
        self.poke()

    def _fire(self) -> None:
        if not self._armed:
            return
        if self._busy:
            self.poke()
            return
        self._armed = False
        self.expired.emit()


class EventGuard(QObject):
    """Application event filter feeding the idle timer and applying capture exclusion."""

    def __init__(self, idle: IdleTimer, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._idle = idle
        self.exclude_from_capture = CAPTURE_EXCLUSION_SUPPORTED

    def install(self, app: QApplication) -> None:
        app.installEventFilter(self)

    def apply_capture_policy(self) -> None:
        for widget in QApplication.topLevelWidgets():
            if widget.isVisible():
                set_capture_exclusion(widget, self.exclude_from_capture)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        kind = event.type()
        if kind in _ACTIVITY:
            self._idle.poke()
        elif (
            kind == QEvent.Type.Show
            and self.exclude_from_capture
            and isinstance(watched, QWidget)
            and watched.isWindow()
        ):
            set_capture_exclusion(watched, True)
        return False
