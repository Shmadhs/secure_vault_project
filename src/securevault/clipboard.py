"""Clipboard access with automatic clearing.

Design decisions:

* **Windows** uses the Win32 API directly through ctypes, not a wrapper library.
  That lets us attach the registered formats that keep secrets out of clipboard
  history (Win+V) and Cloud Clipboard sync. Without them, every copied password
  sits in a history the user may never clear.
* **Linux** uses ``wl-copy``/``wl-paste`` on Wayland and ``xclip`` or ``xsel``
  on X11. The secret is passed on **stdin**, never in argv, where any local
  user could read it from the process list.
* **Clearing only removes what we put there.** The clearer compares a SHA-256
  fingerprint of the current clipboard with the one it was given. If the user
  has since copied something else, it is left alone.
* **Clearing survives the CLI exiting.** A one-shot ``svault get`` returns at
  once, and a small detached helper clears the clipboard later. The helper
  receives only the fingerprint, over stdin.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import subprocess  # nosec B404 - only fixed argv lists, never a shell
import sys
import time
from pathlib import Path
from typing import Any, Protocol

DEFAULT_CLEAR_SECONDS = 20
HELPER_COMMAND = "__clipboard-clear"
_FINGERPRINT_SIZE = 32


class ClipboardUnavailableError(RuntimeError):
    """No usable clipboard mechanism on this system."""


class Clipboard(Protocol):
    name: str

    def copy(self, text: str) -> None: ...
    def paste(self) -> str: ...
    def clear(self) -> None: ...


def fingerprint(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8")).digest()


# --------------------------------------------------------------------------- Windows


class WindowsClipboard:
    """Win32 clipboard via ctypes, with history and cloud-sync exclusion."""

    name = "win32"
    _ctypes: Any
    _u32: Any
    _k32: Any
    _CF_UNICODETEXT = 13
    _GMEM_MOVEABLE = 0x0002
    # Registered format names documented by Microsoft ("Cloud Clipboard and
    # Clipboard History Formats").
    _EXCLUSION_FORMATS = (
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
        "CanUploadToCloudClipboard",
    )

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise ClipboardUnavailableError("the Win32 clipboard exists only on Windows")
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        u32 = ctypes.WinDLL("user32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # Explicit signatures matter: on 64-bit Windows the default ctypes
        # restype (C int) would truncate HANDLE and pointer values.
        u32.OpenClipboard.argtypes = [wintypes.HWND]
        u32.OpenClipboard.restype = wintypes.BOOL
        u32.CloseClipboard.argtypes = []
        u32.CloseClipboard.restype = wintypes.BOOL
        u32.EmptyClipboard.argtypes = []
        u32.EmptyClipboard.restype = wintypes.BOOL
        u32.GetClipboardData.argtypes = [wintypes.UINT]
        u32.GetClipboardData.restype = wintypes.HANDLE
        u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        u32.SetClipboardData.restype = wintypes.HANDLE
        u32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
        u32.RegisterClipboardFormatW.restype = wintypes.UINT
        k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        k32.GlobalAlloc.restype = wintypes.HGLOBAL
        k32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        k32.GlobalLock.restype = wintypes.LPVOID
        k32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        k32.GlobalUnlock.restype = wintypes.BOOL
        k32.GlobalFree.argtypes = [wintypes.HGLOBAL]
        k32.GlobalFree.restype = wintypes.HGLOBAL
        self._u32, self._k32 = u32, k32

    def _open(self) -> None:
        # Another process may hold the clipboard briefly. Retry for about a second.
        for _ in range(20):
            if self._u32.OpenClipboard(None):
                return
            time.sleep(0.05)
        raise ClipboardUnavailableError("the clipboard is locked by another application")

    def _put(self, fmt: int, data: bytes) -> None:
        handle = self._k32.GlobalAlloc(self._GMEM_MOVEABLE, len(data))
        if not handle:
            raise ClipboardUnavailableError("GlobalAlloc failed")
        pointer = self._k32.GlobalLock(handle)
        if not pointer:
            self._k32.GlobalFree(handle)
            raise ClipboardUnavailableError("GlobalLock failed")
        self._ctypes.memmove(pointer, data, len(data))
        self._k32.GlobalUnlock(handle)
        if not self._u32.SetClipboardData(fmt, handle):
            self._k32.GlobalFree(handle)  # ownership did not pass to the system
            raise ClipboardUnavailableError("SetClipboardData failed")

    def copy(self, text: str) -> None:
        self._open()
        try:
            self._u32.EmptyClipboard()
            self._put(self._CF_UNICODETEXT, text.encode("utf-16-le") + b"\x00\x00")
            zero_dword = struct.pack("<I", 0)
            for name in self._EXCLUSION_FORMATS:
                fmt = self._u32.RegisterClipboardFormatW(name)
                if fmt:
                    self._put(fmt, zero_dword)
        finally:
            self._u32.CloseClipboard()

    def paste(self) -> str:
        self._open()
        try:
            handle = self._u32.GetClipboardData(self._CF_UNICODETEXT)
            if not handle:
                return ""
            pointer = self._k32.GlobalLock(handle)
            if not pointer:
                return ""
            try:
                return str(self._ctypes.wstring_at(pointer))
            finally:
                self._k32.GlobalUnlock(handle)
        finally:
            self._u32.CloseClipboard()

    def clear(self) -> None:
        self._open()
        try:
            self._u32.EmptyClipboard()
        finally:
            self._u32.CloseClipboard()


# --------------------------------------------------------------------------- POSIX tools


class CommandClipboard:
    """Clipboard through external tools; the secret always travels over stdin."""

    def __init__(self, name: str, copy_cmd: list[str], paste_cmd: list[str], clear_cmd: list[str] | None) -> None:
        self.name = name
        self._copy_cmd, self._paste_cmd, self._clear_cmd = copy_cmd, paste_cmd, clear_cmd

    def copy(self, text: str) -> None:
        # stdout/stderr go to DEVNULL. xclip and wl-copy fork a background
        # process that keeps serving the selection, and capturing its output
        # would make us wait on pipes it never closes.
        result = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
            self._copy_cmd,
            input=text.encode("utf-8"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            raise ClipboardUnavailableError(f"{self._copy_cmd[0]} failed")

    def paste(self) -> str:
        result = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
            self._paste_cmd, capture_output=True, timeout=10, check=False
        )
        return result.stdout.decode("utf-8", errors="replace") if result.returncode == 0 else ""

    def clear(self) -> None:
        if self._clear_cmd:
            subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
                self._clear_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        else:
            self.copy("")


def _which(name: str) -> str | None:
    return shutil.which(name)


def get_clipboard() -> Clipboard:
    if sys.platform == "win32":
        return WindowsClipboard()
    if sys.platform == "darwin":
        pbcopy, pbpaste = _which("pbcopy"), _which("pbpaste")
        if pbcopy and pbpaste:
            return CommandClipboard("pbcopy", [pbcopy], [pbpaste], None)
    if os.environ.get("WAYLAND_DISPLAY"):
        wl_copy, wl_paste = _which("wl-copy"), _which("wl-paste")
        if wl_copy and wl_paste:
            return CommandClipboard("wl-clipboard", [wl_copy], [wl_paste, "--no-newline"], [wl_copy, "--clear"])
    if os.environ.get("DISPLAY"):
        xclip, xsel = _which("xclip"), _which("xsel")
        if xclip:
            return CommandClipboard(
                "xclip",
                [xclip, "-selection", "clipboard", "-in"],
                [xclip, "-selection", "clipboard", "-out"],
                None,
            )
        if xsel:
            return CommandClipboard(
                "xsel",
                [xsel, "--clipboard", "--input"],
                [xsel, "--clipboard", "--output"],
                [xsel, "--clipboard", "--clear"],
            )
    raise ClipboardUnavailableError(
        "no clipboard tool found: install wl-clipboard (Wayland) or xclip/xsel (X11), or use --print"
    )


def clear_if_unchanged(clipboard: Clipboard, expected: bytes) -> bool:
    """Clear the clipboard only if it still holds the value with this fingerprint."""
    try:
        current = clipboard.paste()
    except (ClipboardUnavailableError, OSError, subprocess.SubprocessError):
        return False
    if fingerprint(current) != expected:
        return False
    clipboard.clear()
    return True


# --------------------------------------------------------------------------- auto-clear


def _helper_argv(seconds: int) -> tuple[list[str], str]:
    """Command line and working directory for the detached clearing helper.

    ``python -m`` puts the current directory first on ``sys.path``, so a
    planted ``securevault/`` folder in the user's cwd would be imported instead
    of ours. Running the helper from the directory that contains our installed
    package makes that resolution point back at the real code.
    """
    if getattr(sys, "frozen", False):  # PyInstaller one-file build
        return [sys.executable, HELPER_COMMAND, str(seconds)], str(Path(sys.executable).parent)
    package_parent = Path(__file__).resolve().parent.parent
    return [sys.executable, "-m", "securevault", HELPER_COMMAND, str(seconds)], str(package_parent)


_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200


def _spawn_helper(argv: list[str], cwd: str) -> subprocess.Popen[bytes]:
    env = dict(os.environ)
    if getattr(sys, "frozen", False):
        # A PyInstaller one-file program that launches its own executable
        # normally makes the new process share its temporary extraction
        # directory, and the parent then waits for it before exiting. Here that
        # meant `svault get` only returned once the helper had already cleared
        # the clipboard. This variable makes the helper an independent instance.
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    common: dict[str, object] = {
        "cwd": cwd,
        "env": env,
        "stdin": subprocess.PIPE,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if sys.platform == "win32":
        common["creationflags"] = _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP
    else:
        common["start_new_session"] = True
    return subprocess.Popen(argv, **common)  # type: ignore[call-overload,no-any-return]  # noqa: S603  # nosec B603


def schedule_clear(text: str, seconds: int) -> None:
    """Start a detached process that clears ``text`` from the clipboard after ``seconds``."""
    argv, cwd = _helper_argv(seconds)
    proc = _spawn_helper(argv, cwd)
    if proc.stdin is None:  # cannot happen with stdin=PIPE; keeps the type checker honest
        raise ClipboardUnavailableError("could not start the clipboard helper")
    proc.stdin.write(fingerprint(text))
    proc.stdin.close()


def run_helper(seconds: int) -> int:
    """Entry point of the detached helper: read the fingerprint, wait, then clear."""
    expected = sys.stdin.buffer.read(_FINGERPRINT_SIZE)
    if len(expected) != _FINGERPRINT_SIZE:
        return 2
    time.sleep(max(0, min(seconds, 3600)))
    try:
        clear_if_unchanged(get_clipboard(), expected)
    except ClipboardUnavailableError:
        return 1
    return 0


def copy_with_autoclear(text: str, seconds: int = DEFAULT_CLEAR_SECONDS) -> bool:
    """Copy ``text`` and schedule its removal. Returns False if no clearing was scheduled.

    The copy has already happened when the helper fails to start, so the caller
    must tell the user rather than silently leave a password on the clipboard.
    """
    get_clipboard().copy(text)
    if seconds <= 0:
        return False
    try:
        schedule_clear(text, seconds)
    except (OSError, ClipboardUnavailableError):
        return False
    return True
