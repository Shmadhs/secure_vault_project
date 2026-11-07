"""Crash-safe file I/O and encrypted backups.

A save must never leave the user with a half-written vault and no good copy.
We write to a temporary file in the same directory, fsync it, then atomically
rename it over the original. A crash at any point leaves either the complete
old file or the complete new one.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from .errors import VaultError
from .osutil import ensure_private_dir

BACKUP_DIR_NAME = "backups"
DEFAULT_BACKUPS = 5


def read_file(path: Path, max_size: int) -> bytes:
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_size + 1)
    except FileNotFoundError:
        raise VaultError(f"no vault at {path} (run 'svault init' to create one)") from None
    except OSError as exc:
        raise VaultError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if len(data) > max_size:
        raise VaultError(f"{path} is too large to be a vault")
    return data


def atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` so readers only ever see the old or new contents."""
    directory = path.parent
    ensure_private_dir(directory)
    # mkstemp creates the file with mode 0600 on POSIX.
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=directory)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        _replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _fsync_directory(directory)


def _replace(src: Path, dst: Path) -> None:
    # On Windows the rename fails while another process (antivirus, a sync
    # client) briefly holds the target open. Retry for about a second.
    attempts = 10 if sys.platform == "win32" else 1
    for attempt in range(attempts):
        try:
            src.replace(dst)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.1)


def _fsync_directory(directory: Path) -> None:
    """Persist the rename itself (POSIX; Windows has no directory fsync)."""
    if os.name != "posix":
        return
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def backup_dir(vault_path: Path) -> Path:
    return vault_path.parent / BACKUP_DIR_NAME


def list_backups(vault_path: Path) -> list[Path]:
    """Backups of ``vault_path``, newest first."""
    directory = backup_dir(vault_path)
    if not directory.is_dir():
        return []
    pattern = f"{vault_path.stem}.*{vault_path.suffix}"
    return sorted(directory.glob(pattern), reverse=True)


def make_backup(vault_path: Path, data: bytes, keep: int) -> None:
    """Store an encrypted copy of the previous vault version, keeping the newest ``keep``."""
    if keep <= 0:
        return
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    atomic_write(backup_dir(vault_path) / f"{vault_path.stem}.{stamp}{vault_path.suffix}", data)
    for old in list_backups(vault_path)[keep:]:
        old.unlink(missing_ok=True)


def purge_backups(vault_path: Path) -> int:
    """Delete all backups. Used after a master-password change.

    Old backups are encrypted under the previous key, so keeping them would keep
    the old password useful to anyone who has it.
    """
    removed = 0
    for path in list_backups(vault_path):
        path.unlink(missing_ok=True)
        removed += 1
    return removed
