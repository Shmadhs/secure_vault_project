"""User preferences, persisted with QSettings (the registry on Windows, ~/.config on Linux).

Only non-secret settings are stored. The keyfile path is deliberately never
remembered: a plaintext record of where the second factor lives would help
whoever reads the registry or the config directory.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QSettings

from .. import clipboard
from ..cli import DEFAULT_IDLE_MINUTES


@dataclass(frozen=True)
class Preferences:
    idle_minutes: int = DEFAULT_IDLE_MINUTES
    lock_on_minimize: bool = True
    clear_seconds: int = clipboard.DEFAULT_CLEAR_SECONDS
    hide_from_capture: bool = True
    last_vault: str = ""


def _int(settings: QSettings, key: str, default: int, low: int, high: int) -> int:
    try:
        value = int(str(settings.value(key, default)))
    except ValueError:
        return default
    return min(max(value, low), high)


def _bool(settings: QSettings, key: str, default: bool) -> bool:
    value = str(settings.value(key, default)).strip().casefold()
    return value in {"true", "1"} if value in {"true", "1", "false", "0"} else default


def load(settings: QSettings) -> Preferences:
    defaults = Preferences()
    return Preferences(
        idle_minutes=_int(settings, "idle_minutes", defaults.idle_minutes, 0, 240),
        lock_on_minimize=_bool(settings, "lock_on_minimize", defaults.lock_on_minimize),
        clear_seconds=_int(settings, "clear_seconds", defaults.clear_seconds, 0, 3600),
        hide_from_capture=_bool(settings, "hide_from_capture", defaults.hide_from_capture),
        last_vault=str(settings.value("last_vault", "") or ""),
    )


def save(settings: QSettings, prefs: Preferences) -> None:
    settings.setValue("idle_minutes", prefs.idle_minutes)
    settings.setValue("lock_on_minimize", prefs.lock_on_minimize)
    settings.setValue("clear_seconds", prefs.clear_seconds)
    settings.setValue("hide_from_capture", prefs.hide_from_capture)
    settings.setValue("last_vault", prefs.last_vault)
    settings.sync()
