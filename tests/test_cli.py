"""End-to-end tests of the command-line interface.

Prompts are replaced with scripted answers. Vaults use the cheapest parameters
the production policy allows (64 MiB, t=3), so these tests also run the real
default policy.
"""

from __future__ import annotations

import io
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from securevault import cli
from securevault.vault_format import parse_file

PW = "Κύριος-κωδικός-correct-horse-battery"
REAL_READ_LINE = cli.read_line  # captured before any fixture patches it
KDF_ARGS = ["--kdf-memory", "64", "--kdf-iterations", "3", "--kdf-parallelism", "1"]


class Script:
    """Feeds scripted answers to read_secret/read_line in call order."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.secrets: list[str] = []
        self.lines: list[str] = []
        monkeypatch.setattr(cli, "read_secret", self._secret)
        monkeypatch.setattr(cli, "read_line", self._line)

    def _secret(self, prompt: str) -> str:
        if not self.secrets:
            raise AssertionError(f"unexpected secret prompt: {prompt!r}")
        return self.secrets.pop(0)

    def _line(self, prompt: str) -> str:
        if not self.lines:
            raise EOFError
        return self.lines.pop(0)


@pytest.fixture
def script(monkeypatch: pytest.MonkeyPatch) -> Script:
    return Script(monkeypatch)


@pytest.fixture
def vault(tmp_path: Path, script: Script) -> Path:
    path = tmp_path / "cli.svault"
    script.lines = ["n"]  # do not generate a passphrase
    script.secrets = [PW, PW]
    assert run(path, "init", *KDF_ARGS) == 0
    return path


def run(path: Path, *args: str) -> int:
    return cli.main(["--vault", str(path), *args])


def unlock(script: Script, times: int = 1) -> None:
    script.secrets.extend([PW] * times)


def test_init_refuses_existing(vault: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(vault, "init", *KDF_ARGS) == cli.EXIT_ERROR
    assert "already exists" in capsys.readouterr().err


def test_init_with_generated_passphrase(tmp_path: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "gen.svault"
    script.lines = ["y"]
    captured: dict[str, str] = {}

    def secret(prompt: str) -> str:
        out = capsys.readouterr().out
        phrase = next(line.strip() for line in out.splitlines() if line.count("-") == 5)
        captured["phrase"] = phrase
        return phrase

    script._secret = secret  # type: ignore[method-assign]
    cli.read_secret = secret  # type: ignore[assignment]
    assert run(path, "init", *KDF_ARGS) == 0
    assert len(captured["phrase"].split("-")) == 6


def test_weak_master_password_needs_confirmation(tmp_path: Path, script: Script) -> None:
    path = tmp_path / "weak.svault"
    script.lines = ["n", "n", "y"]
    script.secrets = ["password1", "password1", "password1", "password1"]
    assert run(path, "init", *KDF_ARGS) == 0  # declined once, then accepted
    assert path.exists()


def test_add_get_show_list_search(vault: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    unlock(script)
    script.secrets.extend(["gh-secret", "gh-secret"])
    assert run(vault, "add", "GitHub", "-u", "kostas", "--url", "https://github.com", "--tags", "dev,work") == 0
    unlock(script)
    assert run(vault, "add", "Τράπεζα Πειραιώς", "-u", "kp", "-g", "--length", "30") == 0
    capsys.readouterr()

    unlock(script)
    assert run(vault, "get", "github", "--print") == 0
    assert capsys.readouterr().out.strip() == "gh-secret"

    unlock(script)
    assert run(vault, "get", "πειραιώς", "--field", "username", "--print") == 0
    assert capsys.readouterr().out.strip() == "kp"

    unlock(script)
    assert run(vault, "show", "github") == 0
    out = capsys.readouterr().out
    assert "kostas" in out
    assert "gh-secret" not in out

    unlock(script)
    assert run(vault, "show", "github", "--reveal") == 0
    assert "gh-secret" in capsys.readouterr().out

    unlock(script)
    assert run(vault, "list", "--tag", "work") == 0
    out = capsys.readouterr().out
    assert "GitHub" in out
    assert "Τράπεζα" not in out

    unlock(script)
    assert run(vault, "search", "πειρ") == 0
    assert "Τράπεζα Πειραιώς" in capsys.readouterr().out


def test_secrets_never_in_plaintext_file(vault: Path, script: Script) -> None:
    unlock(script)
    script.secrets.extend(["hunter2-unique", "hunter2-unique"])
    run(vault, "add", "Site", "-u", "user-unique")
    raw = vault.read_bytes()
    assert b"hunter2-unique" not in raw
    assert b"user-unique" not in raw


def test_wrong_password_exit_code(vault: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    script.secrets = ["wrong"]
    assert run(vault, "list") == cli.EXIT_AUTH
    assert "wrong master password" in capsys.readouterr().err


def test_tampered_vault_exit_code(vault: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    data = bytearray(vault.read_bytes())
    data[-3] ^= 0x10
    vault.write_bytes(bytes(data))
    unlock(script)
    assert run(vault, "list") == cli.EXIT_INTEGRITY
    assert "INTEGRITY FAILURE" in capsys.readouterr().err


def test_edit_and_password_history(vault: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    unlock(script)
    script.secrets.extend(["old", "old"])
    run(vault, "add", "Mail")
    unlock(script)
    script.secrets.extend(["new", "new"])
    assert run(vault, "edit", "mail", "--password", "--username", "me", "--title", "Email") == 0
    capsys.readouterr()
    unlock(script)
    run(vault, "show", "email")
    out = capsys.readouterr().out
    assert "me" in out
    assert "1 previous password" in out


def test_edit_nothing(vault: Path, script: Script) -> None:
    unlock(script)
    script.secrets.extend(["x", "x"])
    run(vault, "add", "Mail")
    unlock(script)
    assert run(vault, "edit", "Mail") == cli.EXIT_ERROR


def test_rm_confirmation(vault: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    unlock(script)
    script.secrets.extend(["x", "x"])
    run(vault, "add", "Temp")
    unlock(script)
    script.lines = ["n"]
    run(vault, "rm", "Temp")
    unlock(script)
    run(vault, "rm", "Temp", "-y")
    capsys.readouterr()
    unlock(script)
    run(vault, "list")
    assert "Temp" not in capsys.readouterr().out


def test_totp_command(vault: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    unlock(script)
    script.secrets.extend(["", "JBSWY3DPEHPK3PXP"])
    assert run(vault, "add", "2FA", "--totp") == 0
    capsys.readouterr()
    unlock(script)
    assert run(vault, "totp", "2FA") == 0
    code = capsys.readouterr().out.split()[0]
    assert code.isdigit()
    assert len(code) == 6


def test_invalid_totp_rejected_before_saving(vault: Path, script: Script) -> None:
    unlock(script)
    script.secrets.extend(["", "not-base32!!"])
    assert run(vault, "add", "2FA", "--totp") == cli.EXIT_ERROR


def test_gen_prints_only_the_password(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["gen", "--length", "40"]) == 0
    captured = capsys.readouterr()
    assert len(captured.out.strip()) == 40
    assert "entropy" in captured.err
    assert cli.main(["gen", "--words", "7", "--separator", " "]) == 0
    assert len(capsys.readouterr().out.split()) == 7


def test_audit_command(vault: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    for title in ("A", "B"):
        unlock(script)
        script.secrets.extend(["Same-Password-2024!", "Same-Password-2024!"])
        run(vault, "add", title)
    capsys.readouterr()
    unlock(script)
    assert run(vault, "audit") == 0
    assert "REUSED" in capsys.readouterr().out


def test_export_and_import(vault: Path, tmp_path: Path, script: Script) -> None:
    unlock(script)
    script.secrets.extend(["p1", "p1"])
    run(vault, "add", "One", "-u", "u1")
    out = tmp_path / "export.csv"
    unlock(script)
    script.lines = ["export"]
    assert run(vault, "export", str(out), "--format", "csv") == 0
    assert "p1" in out.read_text(encoding="utf-8")
    if os.name == "posix":
        assert out.stat().st_mode & 0o077 == 0

    unlock(script)
    script.lines = ["export"]
    assert run(vault, "export", str(out)) == cli.EXIT_ERROR  # refuses to overwrite

    unlock(script)
    assert run(vault, "import", str(out)) == 0
    unlock(script)
    assert run(vault, "get", "One (2)", "--print") == 0


def test_export_requires_typed_confirmation(vault: Path, tmp_path: Path, script: Script) -> None:
    unlock(script)
    script.lines = ["yes"]
    run(vault, "export", str(tmp_path / "x.json"))
    assert not (tmp_path / "x.json").exists()


def test_import_dry_run_changes_nothing(
    vault: Path, tmp_path: Path, script: Script, capsys: pytest.CaptureFixture[str]
) -> None:
    csv_file = tmp_path / "in.csv"
    csv_file.write_text("title,password\nA,1\nB,2\n", encoding="utf-8")
    before = vault.read_bytes()
    unlock(script)
    assert run(vault, "import", str(csv_file), "--dry-run") == 0
    assert "would import 2" in capsys.readouterr().out
    assert vault.read_bytes() == before


def test_info_needs_no_password(vault: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(vault, "info") == 0
    out = capsys.readouterr().out
    assert "Argon2id 64 MiB, t=3, p=1" in out


def test_passwd_rotates_and_purges(vault: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    unlock(script)
    script.secrets.extend(["x", "x"])
    run(vault, "add", "Keep")
    old_id = parse_file(vault.read_bytes()).header.vault_id
    unlock(script)
    script.lines = ["n"]
    script.secrets.extend(["Brand-new-master-passphrase-2026", "Brand-new-master-passphrase-2026"])
    assert run(vault, "passwd") == 0
    assert "Removed 1 old backup" in capsys.readouterr().out
    assert parse_file(vault.read_bytes()).header.vault_id == old_id
    script.secrets = [PW]
    assert run(vault, "list") == cli.EXIT_AUTH
    script.secrets = ["Brand-new-master-passphrase-2026"]
    assert run(vault, "list") == 0


def test_keyfile_flow(tmp_path: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    path, keyfile = tmp_path / "kf.svault", tmp_path / "vault.key"
    script.lines = ["n"]
    script.secrets = [PW, PW]
    assert run(path, "init", "--new-keyfile", str(keyfile), *KDF_ARGS) == 0
    assert keyfile.stat().st_size == 64
    unlock(script)
    assert run(path, "list") == cli.EXIT_AUTH
    assert "requires a keyfile" in capsys.readouterr().err
    unlock(script)
    assert cli.main(["--vault", str(path), "--keyfile", str(keyfile), "list"]) == 0
    assert "keyfile required" in (run(path, "info"), capsys.readouterr().out)[1]


def test_keyfile_command_refuses_overwrite(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = tmp_path / "k"
    assert cli.main(["keyfile", str(key)]) == 0
    assert cli.main(["keyfile", str(key)]) == cli.EXIT_ERROR


def test_password_stdin(vault: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(PW + "\n"))
    assert cli.main(["--vault", str(vault), "--password-stdin", "list"]) == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert cli.main(["--vault", str(vault), "--password-stdin", "list"]) == cli.EXIT_ERROR


def test_read_secret_refuses_non_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("visible\n"))
    with pytest.raises(cli.VaultError, match="not a terminal"):
        cli.read_secret("pw: ")


@pytest.mark.parametrize(
    ("raw", "safe"),
    [
        ("plain", "plain"),
        ("a\x1b]52;c;ZXZpbA==\x07b", "a\\u001b]52;c;ZXZpbA==\\u0007b"),
        ("\x1b[2J", "\\u001b[2J"),
        ("evil\u202egnp.exe", "evil\\u202egnp.exe"),
        ("line1\nline2", "line1 line2"),
        ("Τράπεζα", "Τράπεζα"),
    ],
)
def test_term_safe(raw: str, safe: str) -> None:
    assert cli.term_safe(raw) == safe


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == cli.EXIT_USAGE
    assert "usage" in capsys.readouterr().out


# --------------------------------------------------------------------------- shell


def test_shell_session(vault: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    unlock(script)  # initial unlock
    script.lines = ["add Shell -g", "list", "bogus", 'get "Shell" --print', "lock", "list", "help", "exit"]
    unlock(script)  # after 'lock'
    assert run(vault, "shell") == 0
    out = capsys.readouterr()
    assert "Added 'Shell'" in out.out
    assert out.out.count("Shell") >= 3
    assert "Locked." in out.out
    assert "Vault locked. Bye." in out.out


def test_shell_three_attempts(vault: Path, script: Script) -> None:
    script.secrets = ["bad1", "bad2", PW]
    script.lines = ["exit"]
    assert run(vault, "shell") == 0


def test_idle_lock(vault: Path, script: Script) -> None:
    unlock(script)
    ctx = cli.Context(vault_path=vault, err=io.StringIO())
    v = ctx.vault()
    idle = cli._IdleLock(ctx, 0.05)
    idle.arm()
    deadline = time.monotonic() + 5
    while not v.locked and time.monotonic() < deadline:
        time.sleep(0.01)
    assert v.locked
    assert idle.fired


@pytest.fixture(autouse=True)
def _restore_read_secret() -> Iterator[None]:
    original = cli.read_secret
    yield
    cli.read_secret = original  # type: ignore[assignment]


# --------------------------------------------------------------------------- review regressions


def test_rm_requires_exact_title(vault: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    unlock(script)
    script.secrets.extend(["x", "x"])
    run(vault, "add", "Bank of Example")
    unlock(script)
    assert run(vault, "rm", "bank", "-y") == cli.EXIT_ERROR  # fuzzy match must not delete
    assert "exact title" in capsys.readouterr().err
    unlock(script)
    assert run(vault, "rm", "bank of example", "-y") == 0


def test_backups_and_restore(vault: Path, script: Script, capsys: pytest.CaptureFixture[str]) -> None:
    for title in ("First", "Second"):
        unlock(script)
        script.secrets.extend(["x", "x"])
        run(vault, "add", title)
    assert run(vault, "backups") == 0
    assert "1. " in capsys.readouterr().out
    data = bytearray(vault.read_bytes())
    data[-2] ^= 0x01
    vault.write_bytes(bytes(data))  # simulate corruption
    unlock(script)
    assert run(vault, "list") == cli.EXIT_INTEGRITY

    script.secrets = ["wrong"]
    script.lines = ["y"]
    assert run(vault, "restore", "1") == cli.EXIT_AUTH  # a wrong password never overwrites
    unlock(script)
    script.lines = ["y"]
    assert run(vault, "restore", "1") == 0  # newest backup = the vault before "Second"
    capsys.readouterr()
    unlock(script)
    assert run(vault, "list") == 0
    out = capsys.readouterr().out
    assert "First" in out
    assert "Second" not in out
    assert run(vault, "restore", "99") == cli.EXIT_ERROR


def test_os_errors_become_messages(
    vault: Path, script: Script, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from securevault import storage

    def denied(path: Path, data: bytes) -> None:
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(storage, "atomic_write", denied)
    unlock(script)
    script.secrets.extend(["x", "x"])
    assert run(vault, "add", "X") == cli.EXIT_ERROR
    assert "Permission denied" in capsys.readouterr().err


def test_malformed_csv_is_an_error_not_a_crash(vault: Path, tmp_path: Path, script: Script) -> None:
    bad = tmp_path / "bad.csv"
    bad.write_text("title,password\nA," + "x" * 200_000 + "\n", encoding="utf-8")
    unlock(script)
    assert run(vault, "import", str(bad)) == cli.EXIT_ERROR


def test_prompts_do_not_pollute_stdout(
    vault: Path, script: Script, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "read_line", REAL_READ_LINE)
    monkeypatch.setattr(sys, "stdin", io.StringIO("export\n"))
    unlock(script)
    assert run(vault, "export", "-") == 0
    out = capsys.readouterr()
    assert out.out.startswith("{")  # pure JSON on stdout
    assert "Type 'export'" in out.err


def test_idle_lock_cancel_prevents_locking(vault: Path, script: Script) -> None:
    unlock(script)
    ctx = cli.Context(vault_path=vault, err=io.StringIO())
    v = ctx.vault()
    idle = cli._IdleLock(ctx, 0.05)
    idle.arm()
    idle.cancel()
    time.sleep(0.2)
    assert not v.locked
    assert not idle.fired


def test_clipboard_failure_to_schedule_is_reported(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from securevault import clipboard

    class Board:
        name = "fake"

        def copy(self, text: str) -> None:
            pass

    def no_helper(text: str, seconds: int) -> None:
        raise OSError("cannot spawn")

    monkeypatch.setattr(clipboard, "get_clipboard", Board)
    monkeypatch.setattr(clipboard, "schedule_clear", no_helper)
    assert cli.main(["gen", "--copy"]) == 0
    assert "could not start the auto-clear helper" in capsys.readouterr().err
