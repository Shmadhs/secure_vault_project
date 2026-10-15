"""Desktop GUI for SecureVault: ``svault-gui`` (``pip install securevault[gui]``).

The GUI is a thin layer over the same core as the CLI. It never touches the
cryptography or the file format directly: unlocking, saving, re-keying and
restoring all go through :mod:`securevault.vault`, exactly as ``svault`` does.

PySide6 is imported lazily, here and only here, so ``svault`` and the core
never load Qt and keep their single runtime dependency.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

from .. import clipboard, osutil

INSTALL_HINT = 'The SecureVault GUI needs PySide6. Install it with:  pip install "securevault[gui]"'


def _report_missing_qt() -> None:
    """Explain the missing extra. ``svault-gui`` runs under pythonw on Windows, which has no stderr."""
    if sys.stderr is not None:
        sys.stderr.write(INSTALL_HINT + "\n")
    if sys.platform == "win32":
        import ctypes

        mb_iconerror = 0x10
        ctypes.WinDLL("user32").MessageBoxW(None, INSTALL_HINT, "SecureVault", mb_iconerror)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    # A frozen build relaunches its own executable as the clipboard-clearing
    # helper (see clipboard._helper_argv), so that request must be handled
    # before anything else, and without Qt.
    if arguments[:1] == [clipboard.HELPER_COMMAND]:
        seconds = int(arguments[1]) if len(arguments) > 1 and arguments[1].isdigit() else 0
        return clipboard.run_helper(seconds)
    osutil.harden_process()
    try:
        import PySide6.QtWidgets  # noqa: F401
    except ImportError:
        _report_missing_qt()
        return 1
    from .app import run

    return run(arguments)
