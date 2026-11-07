"""Import from other password managers' CSV exports; export to CSV/JSON.

Supported CSV dialects are detected from the header row. Bitwarden, KeePassXC,
Chrome/Edge, Firefox and SecureVault's own export all work, because columns are
matched by name through an alias table, not by position.

Exports are **plaintext**. They exist for migrating away (no lock-in). The CLI
makes the user re-enter the master password and acknowledge the risk.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, TextIO
from urllib.parse import urlsplit

from .model import Entry, VaultContents

# Our field <- accepted column names (compared case-insensitively).
_ALIASES: dict[str, tuple[str, ...]] = {
    "title": ("title", "name", "account", "site"),
    "username": ("username", "login_username", "login", "user", "email"),
    "password": ("password", "login_password", "pass"),
    "url": ("url", "login_uri", "uri", "website", "origin"),
    "notes": ("notes", "note", "extra", "comments"),
    "totp": ("totp", "login_totp", "otpauth", "otp"),
    "tags": ("tags", "group", "folder", "grouping", "category"),
}
EXPORT_COLUMNS = ("title", "username", "password", "url", "notes", "totp", "tags")
MAX_IMPORT_ROWS = 100_000


@dataclass
class ImportResult:
    added: list[Entry] = field(default_factory=list)
    renamed: list[tuple[str, str]] = field(default_factory=list)
    skipped: int = 0


def _column_map(header: list[str]) -> dict[str, int]:
    folded = [h.strip().casefold() for h in header]
    mapping: dict[str, int] = {}
    for ours, aliases in _ALIASES.items():
        for alias in aliases:
            if alias in folded:
                mapping[ours] = folded.index(alias)
                break
    return mapping


def _title_from(row: dict[str, str]) -> str:
    if row.get("title", "").strip():
        return row["title"].strip()
    try:
        host = urlsplit(row.get("url", "")).hostname
    except ValueError:  # malformed URL such as "http://[::1"
        host = None
    return host or row.get("username", "").strip() or "Untitled"


def read_csv(stream: TextIO) -> list[dict[str, str]]:
    reader = csv.reader(stream)
    try:
        header = next(reader)
        mapping = _column_map(header)
        if "password" not in mapping:
            raise ValueError("CSV has no recognizable password column")
        rows: list[dict[str, str]] = []
        for i, raw in enumerate(reader):
            if i >= MAX_IMPORT_ROWS:
                raise ValueError(f"CSV has more than {MAX_IMPORT_ROWS} rows")
            rows.append({ours: raw[idx] if idx < len(raw) else "" for ours, idx in mapping.items()})
    except StopIteration:
        return []
    except csv.Error as exc:  # e.g. a field over the size limit or a stray NUL byte
        raise ValueError(f"malformed CSV at line {reader.line_num}: {exc}") from exc
    return rows


def import_rows(contents: VaultContents, rows: Iterable[dict[str, str]]) -> ImportResult:
    result = ImportResult()
    for row in rows:
        if not any(v.strip() for v in row.values()):
            result.skipped += 1
            continue
        wanted = _title_from(row)[:240]  # room for a " (n)" suffix within the title limit
        title = contents.unique_title(wanted)
        tags = [t.strip() for t in row.get("tags", "").replace(";", ",").split(",") if t.strip()]
        entry = Entry(
            title=title,
            username=row.get("username", ""),
            password=row.get("password", ""),
            url=row.get("url", ""),
            notes=row.get("notes", ""),
            totp=row.get("totp", ""),
            tags=tags,
        )
        contents.add(entry)
        result.added.append(entry)
        if title != wanted:
            result.renamed.append((wanted, title))
    return result


def export_csv(entries: Iterable[Entry]) -> str:
    """CSV with SecureVault column names (re-importable here and into most managers).

    Cells are written verbatim. Escaping formula-like cells (``=``, ``+``, ``-``,
    ``@``) would change passwords that begin with those characters, and an
    export that corrupts credentials defeats its purpose. Do not open it in a
    spreadsheet; import it.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(EXPORT_COLUMNS)
    for e in entries:
        writer.writerow([e.title, e.username, e.password, e.url, e.notes, e.totp, ",".join(e.tags)])
    return buffer.getvalue()


def export_json(entries: Iterable[Entry]) -> str:
    """Full-fidelity JSON export, including password history and timestamps."""
    payload: dict[str, Any] = {
        "format": "securevault-export",
        "version": 1,
        "entries": [e.to_dict() for e in entries],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
