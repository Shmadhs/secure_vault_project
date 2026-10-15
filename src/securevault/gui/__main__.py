"""Allow ``python -m securevault.gui``."""

from __future__ import annotations

import sys

from . import main

sys.exit(main())
