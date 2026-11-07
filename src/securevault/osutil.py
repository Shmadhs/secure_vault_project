"""Operating-system specifics: default paths, permissions, memory, process hardening.

Everything platform-dependent that is not the clipboard lives here, so the rest
of the code stays portable.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

APP_DIR_NAME = "SecureVault"
VAULT_FILE_NAME = "vault.svault"


def default_data_dir() -> Path:
    """Per-user data directory following each platform's convention.

    * Windows: ``%LOCALAPPDATA%\\SecureVault``. Local rather than Roaming, so a
      domain profile does not silently copy the vault to a file server.
    * macOS: ``~/Library/Application Support/SecureVault``
    * Linux/BSD: ``$XDG_DATA_HOME/securevault`` (default ``~/.local/share``)
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        return Path(base) / APP_DIR_NAME if base else Path.home() / "AppData" / "Local" / APP_DIR_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_DIR_NAME
    xdg = os.environ.get("XDG_DATA_HOME", "")
    # The XDG spec says relative paths must be ignored.
    base_path = Path(xdg) if xdg and Path(xdg).is_absolute() else Path.home() / ".local" / "share"
    return base_path / APP_DIR_NAME.lower()


def default_vault_path() -> Path:
    return default_data_dir() / VAULT_FILE_NAME


def ensure_private_dir(directory: Path) -> None:
    """Create ``directory`` (and parents) if missing, owner-only on POSIX.

    Existing directories are left alone: a user who points the vault at a folder
    they already manage should not have its permissions changed under them.
    """
    if directory.is_dir():
        return
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        directory.chmod(0o700)


def is_group_or_world_accessible(path: Path) -> bool:
    """True if a POSIX file grants any permission to group or others.

    Always False on Windows, where per-user profile ACLs are the protection and
    POSIX mode bits are not meaningful.
    """
    if os.name != "posix":
        return False
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(stat.S_IMODE(mode) & 0o077)


def available_memory_bytes() -> int | None:
    """Best-effort estimate of memory available to us, or None if unknown."""
    try:
        if sys.platform == "win32":
            return _windows_available_memory()
        if sys.platform.startswith("linux"):
            with open("/proc/meminfo", encoding="ascii") as fh:
                for line in fh:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) * 1024
            return None
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        # Total physical memory: halve it as a stand-in for "available".
        return int(pages * page_size // 2)
    except (OSError, ValueError, AttributeError):
        return None


def _windows_available_memory() -> int | None:
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
    kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return None
    return int(status.ullAvailPhys)


def harden_process() -> list[str]:
    """Apply best-effort protections against secrets leaking out of process memory.

    Returns the names of the measures that took effect. Failures are silent: a
    missing protection is better than a password manager that will not start.

    * Core dumps disabled (``RLIMIT_CORE = 0``): a crash would otherwise write
      the decrypted vault to disk.
    * Linux ``PR_SET_DUMPABLE = 0``: other processes of the same user can no
      longer ptrace us or read ``/proc/<pid>/mem``. Root still can.
    """
    applied: list[str] = []
    if sys.platform == "win32":
        return applied
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        applied.append("core-dumps-disabled")
    except (ImportError, ValueError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            pr_set_dumpable = 4
            if libc.prctl(pr_set_dumpable, 0, 0, 0, 0) == 0:
                applied.append("ptrace-protection")
        except (OSError, AttributeError):
            pass
    return applied
