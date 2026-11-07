"""Clipboard, storage and OS-integration tests."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from securevault import clipboard, osutil, storage


class FakeClipboard:
    name = "fake"

    def __init__(self) -> None:
        self.value = ""

    def copy(self, text: str) -> None:
        self.value = text

    def paste(self) -> str:
        return self.value

    def clear(self) -> None:
        self.value = ""


def test_clear_only_if_unchanged() -> None:
    board = FakeClipboard()
    board.copy("secret")
    assert clipboard.clear_if_unchanged(board, clipboard.fingerprint("secret"))
    assert board.value == ""


def test_does_not_clear_what_the_user_copied_later() -> None:
    board = FakeClipboard()
    board.copy("something the user copied afterwards")
    assert not clipboard.clear_if_unchanged(board, clipboard.fingerprint("secret"))
    assert board.value == "something the user copied afterwards"


def test_fingerprint_is_keyed_per_copy() -> None:
    first, second = clipboard.fingerprint("secret"), clipboard.fingerprint("secret")
    assert first != second  # a fresh key each time, so no stable hash of the password
    assert clipboard.matches(first, "secret")
    assert clipboard.matches(second, "secret")
    assert not clipboard.matches(first, "Secret")
    assert not clipboard.matches(first[:-1], "secret")


def test_helper_runs_from_package_parent_not_cwd() -> None:
    argv, cwd = clipboard._helper_argv(20)
    assert argv[-2:] == [clipboard.HELPER_COMMAND, "20"]
    assert (Path(cwd) / "securevault" / "__init__.py").exists()


@pytest.mark.parametrize("frozen", [False, True])
def test_helper_spawn_is_detached_and_gets_only_a_fingerprint(monkeypatch: pytest.MonkeyPatch, frozen: bool) -> None:
    import io
    import subprocess

    captured: dict[str, object] = {}

    class FakePopen:
        def __init__(self, argv: list[str], **kwargs: object) -> None:
            captured.update(kwargs, argv=argv)
            self.stdin = io.BytesIO()
            self.stdin.close = lambda: captured.update(sent=self.stdin.getvalue())  # type: ignore[method-assign]

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    if frozen:
        monkeypatch.setattr(sys, "frozen", True, raising=False)
    clipboard.schedule_clear("the-secret", 20)
    sent = captured["sent"]
    assert isinstance(sent, bytes)
    assert clipboard.matches(sent, "the-secret")  # a fingerprint of it ...
    assert b"the-secret" not in sent  # ... never the secret itself
    assert "the-secret" not in " ".join(captured["argv"])  # type: ignore[arg-type]
    env = captured["env"]
    assert isinstance(env, dict)
    # One-file builds must start the helper as an independent instance (see _spawn_helper).
    assert (env.get("PYINSTALLER_RESET_ENVIRONMENT") == "1") is frozen
    if sys.platform == "win32":
        assert captured["creationflags"]
    else:
        assert captured["start_new_session"] is True


def test_helper_rejects_short_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"short")))
    assert clipboard.run_helper(0) == 2


@pytest.mark.skipif(
    sys.platform != "win32" or not os.environ.get("SVAULT_TEST_CLIPBOARD"),
    reason="touches the real Windows clipboard; set SVAULT_TEST_CLIPBOARD=1",
)
def test_windows_clipboard_excluded_from_history() -> None:
    import ctypes

    board = clipboard.WindowsClipboard()
    previous = board.paste()
    try:
        board.copy("svault-test-Ω")
        assert board.paste() == "svault-test-Ω"
        user32 = ctypes.WinDLL("user32")
        for name in clipboard.WindowsClipboard._EXCLUSION_FORMATS:
            fmt = user32.RegisterClipboardFormatW(name)
            assert user32.IsClipboardFormatAvailable(fmt), name
        assert clipboard.clear_if_unchanged(board, clipboard.fingerprint("svault-test-Ω"))
        assert board.paste() == ""
    finally:
        if previous:
            board.copy(previous)


@pytest.mark.skipif(
    sys.platform == "win32"
    or not os.environ.get("SVAULT_TEST_CLIPBOARD")
    or not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
    reason="touches a real X11/Wayland clipboard; CI runs it under xvfb with SVAULT_TEST_CLIPBOARD=1",
)
def test_posix_clipboard_roundtrip() -> None:
    board = clipboard.get_clipboard()
    board.copy("svault-test-Ω")
    assert board.paste() == "svault-test-Ω"
    assert not clipboard.clear_if_unchanged(board, clipboard.fingerprint("something else"))
    assert clipboard.clear_if_unchanged(board, clipboard.fingerprint("svault-test-Ω"))
    assert board.paste() == ""


def test_atomic_write_and_backups(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "v.svault"
    storage.atomic_write(path, b"one")
    assert path.read_bytes() == b"one"
    for i in range(4):
        storage.make_backup(path, f"b{i}".encode(), keep=2)
    backups = storage.list_backups(path)
    assert len(backups) == 2
    assert backups[0].read_bytes() == b"b3"
    assert storage.purge_backups(path) == 2
    assert storage.list_backups(path) == []


def test_backups_of_different_vaults_do_not_mix(tmp_path: Path) -> None:
    a, b = tmp_path / "a.svault", tmp_path / "ab.svault"
    storage.make_backup(a, b"a", keep=5)
    storage.make_backup(b, b"b", keep=5)
    assert [p.read_bytes() for p in storage.list_backups(a)] == [b"a"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_posix_permissions(tmp_path: Path) -> None:
    path = tmp_path / "private" / "v.svault"
    storage.atomic_write(path, b"x")
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    path.chmod(0o644)
    assert osutil.is_group_or_world_accessible(path)


def test_default_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert osutil.default_data_dir() == tmp_path / "securevault"
    monkeypatch.setenv("XDG_DATA_HOME", "relative/path")  # must be ignored per the XDG spec
    assert osutil.default_data_dir() == Path.home() / ".local" / "share" / "securevault"
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert osutil.default_vault_path() == tmp_path / "SecureVault" / "vault.svault"


def test_available_memory_is_sane() -> None:
    memory = osutil.available_memory_bytes()
    assert memory is None or memory > 16 * 1024 * 1024


def test_harden_process_does_not_raise() -> None:
    applied = osutil.harden_process()
    if sys.platform.startswith("linux"):
        assert "core-dumps-disabled" in applied
