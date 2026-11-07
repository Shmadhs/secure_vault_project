"""The GUI stays optional: the core never loads Qt, and the launcher degrades cleanly without it.

These run in the core-only test job, where PySide6 is not installed.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from securevault import clipboard, gui, osutil


def test_core_and_cli_never_import_qt() -> None:
    code = (
        "import sys, securevault.cli, securevault.vault, securevault.clipboard, securevault.gui\n"
        "loaded = [m for m in sys.modules if m.split('.')[0] in ('PySide6', 'shiboken6')]\n"
        "assert not loaded, loaded\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_launcher_without_pyside6_explains_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "PySide6", None)  # makes `import PySide6...` fail
    monkeypatch.setitem(sys.modules, "PySide6.QtWidgets", None)
    monkeypatch.setattr(osutil, "harden_process", lambda: [])
    reported: list[bool] = []
    monkeypatch.setattr(gui, "_report_missing_qt", lambda: reported.append(True))
    assert gui.main([]) == 1
    assert reported == [True]


def test_missing_qt_message(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "platform", "linux")  # the Windows path would open a real message box
    gui._report_missing_qt()
    assert 'pip install "securevault[gui]"' in capsys.readouterr().err


def test_launcher_runs_the_clipboard_helper_before_anything_else(monkeypatch: pytest.MonkeyPatch) -> None:
    # A frozen svault-gui is relaunched as its own clipboard-clearing helper.
    monkeypatch.setitem(sys.modules, "PySide6", None)  # that path must not need Qt
    seconds: list[int] = []
    monkeypatch.setattr(clipboard, "run_helper", lambda s: seconds.append(s) or 0)
    assert gui.main([clipboard.HELPER_COMMAND, "7"]) == 0
    assert seconds == [7]
