"""PyInstaller entry point for the standalone ``svault`` binary."""

from securevault.cli import main

raise SystemExit(main())
