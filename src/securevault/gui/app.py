"""Application start-up for ``svault-gui``."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from .. import __version__, osutil
from . import prefs as prefs_store
from .main_window import MainWindow

ORGANIZATION = "SecureVault"
APPLICATION = "svault-gui"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="svault-gui", description="SecureVault desktop GUI.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--vault", type=Path, help="vault file (default: $SVAULT_VAULT, the last one opened, or the per-user default)"
    )
    parser.add_argument("--keyfile", type=Path, help="keyfile to pre-select (default: $SVAULT_KEYFILE)")
    return parser


def initial_paths(args: argparse.Namespace, settings: QSettings) -> tuple[Path, Path | None]:
    """Same precedence as the CLI (option, then environment), then the last vault the GUI opened."""
    vault = args.vault
    if vault is None and os.environ.get("SVAULT_VAULT"):
        vault = Path(os.environ["SVAULT_VAULT"])
    if vault is None:
        last = prefs_store.load(settings).last_vault
        vault = Path(last) if last else osutil.default_vault_path()
    keyfile = args.keyfile
    if keyfile is None and os.environ.get("SVAULT_KEYFILE"):
        keyfile = Path(os.environ["SVAULT_KEYFILE"])
    return vault, keyfile


def run(argv: Sequence[str]) -> int:
    args = build_parser().parse_args(list(argv))
    existing = QApplication.instance()
    app = existing if isinstance(existing, QApplication) else QApplication([sys.argv[0] if sys.argv else APPLICATION])
    app.setOrganizationName(ORGANIZATION)
    app.setApplicationName(APPLICATION)
    app.setApplicationDisplayName("SecureVault")
    app.setApplicationVersion(__version__)
    settings = QSettings(ORGANIZATION, APPLICATION)
    vault, keyfile = initial_paths(args, settings)
    window = MainWindow(settings, vault, keyfile)
    # Logoff and shutdown can end the event loop without a close event.
    app.aboutToQuit.connect(lambda: window.lock("on exit"))
    window.show()
    return int(app.exec())
