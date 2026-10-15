from __future__ import annotations

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
