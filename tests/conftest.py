from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from securevault import crypto
from securevault.crypto import KdfParams, KdfPolicy

# Unit tests use tiny Argon2 parameters for speed, so they need a policy whose
# floor admits them. Production code never uses this policy. tests/test_vault.py
# checks that the real DEFAULT_POLICY rejects these parameters.
FAST_POLICY = KdfPolicy(min_memory_kib=8, min_work=8)
PASSWORD = "correct horse battery staple"


@pytest.fixture
def fast_kdf() -> KdfParams:
    return KdfParams(crypto.new_salt(), memory_kib=256, iterations=1, lanes=1)


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    return tmp_path / "test.svault"


# The GUI tests need the optional `gui` and `gui-test` extras. Without them they
# are not collected at all, which keeps the core test job free of Qt. (pytest-qt
# cannot simply be skipped: it aborts the run at start-up if Qt is missing.)
if importlib.util.find_spec("PySide6") is None or importlib.util.find_spec("pytestqt") is None:
    collect_ignore = ["gui"]
