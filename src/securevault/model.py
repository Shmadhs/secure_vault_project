"""In-memory data model: entries and the collection that holds them.

Unknown fields are preserved. If a newer SecureVault adds a field and an older
one later opens and saves the vault, that field survives instead of being
silently dropped.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .errors import (
    AmbiguousEntryError,
    DuplicateEntryError,
    EntryNotFoundError,
    VaultFormatError,
)

PAYLOAD_SCHEMA = 1
MAX_HISTORY = 10
MAX_TITLE_LENGTH = 256
_MIN_ID_PREFIX = 4

_ENTRY_STR_FIELDS = ("title", "username", "password", "url", "notes", "totp", "id")
_ENTRY_KNOWN = {*_ENTRY_STR_FIELDS, "tags", "created", "modified", "history"}


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def validate_title(title: str) -> str:
    title = title.strip()
    if not title:
        raise ValueError("title must not be empty")
    if len(title) > MAX_TITLE_LENGTH:
        raise ValueError(f"title is longer than {MAX_TITLE_LENGTH} characters")
    return title


@dataclass
class HistoryItem:
    password: str = field(repr=False)
    changed: str


@dataclass
class Entry:
    """A stored credential. Secret fields are excluded from ``repr``.

    That way a stray ``print(entry)`` or a traceback never shows a password.
    """

    title: str
    username: str = ""
    password: str = field(default="", repr=False)
    url: str = ""
    notes: str = field(default="", repr=False)
    tags: list[str] = field(default_factory=list)
    totp: str = field(default="", repr=False)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created: str = field(default_factory=utc_now)
    modified: str = field(default_factory=utc_now)
    history: list[HistoryItem] = field(default_factory=list, repr=False)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.title = validate_title(self.title)

    def touch(self) -> None:
        self.modified = utc_now()

    def set_password(self, new_password: str) -> None:
        """Change the password, keeping the previous one in the history."""
        if new_password == self.password:
            return
        if self.password:
            self.history.insert(0, HistoryItem(self.password, utc_now()))
            del self.history[MAX_HISTORY:]
        self.password = new_password
        self.touch()

    def matches(self, term: str) -> bool:
        needle = term.casefold()
        haystack = (self.title, self.username, self.url, self.notes, *self.tags)
        return any(needle in value.casefold() for value in haystack)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = dict(self.extra)
        data.update(
            {
                "id": self.id,
                "title": self.title,
                "username": self.username,
                "password": self.password,
                "url": self.url,
                "notes": self.notes,
                "tags": list(self.tags),
                "totp": self.totp,
                "created": self.created,
                "modified": self.modified,
                "history": [{"password": h.password, "changed": h.changed} for h in self.history],
            }
        )
        return data

    @classmethod
    def from_dict(cls, data: Any) -> Entry:
        if not isinstance(data, dict):
            raise VaultFormatError("entry must be an object")
        for key in _ENTRY_STR_FIELDS:
            if key in data and not isinstance(data[key], str):
                raise VaultFormatError(f"entry field {key!r} must be a string")
        tags = data.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
            raise VaultFormatError("entry tags must be a list of strings")
        history: list[HistoryItem] = []
        for item in data.get("history", []):
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("password"), str)
                or not isinstance(item.get("changed"), str)
            ):
                raise VaultFormatError("malformed password history")
            history.append(HistoryItem(item["password"], item["changed"]))
        try:
            entry = cls(
                title=data.get("title", ""),
                username=data.get("username", ""),
                password=data.get("password", ""),
                url=data.get("url", ""),
                notes=data.get("notes", ""),
                tags=list(tags),
                totp=data.get("totp", ""),
                history=history,
                extra={k: v for k, v in data.items() if k not in _ENTRY_KNOWN},
            )
        except ValueError as exc:
            raise VaultFormatError(f"invalid entry: {exc}") from exc
        for key in ("created", "modified"):
            if key in data:
                try:
                    parse_timestamp(data[key])
                except (TypeError, ValueError) as exc:
                    raise VaultFormatError(f"entry field {key!r} is not an ISO-8601 timestamp") from exc
        for key in ("id", "created", "modified"):
            if key in data:
                setattr(entry, key, data[key])
        return entry


@dataclass
class VaultContents:
    """The decrypted contents of a vault. Titles are unique, compared case-insensitively."""

    entries: list[Entry] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def __iter__(self) -> Iterator[Entry]:
        return iter(sorted(self.entries, key=lambda e: e.title.casefold()))

    def __len__(self) -> int:
        return len(self.entries)

    def _title_taken(self, title: str, *, ignore: Entry | None = None) -> bool:
        folded = title.casefold()
        return any(e.title.casefold() == folded and e is not ignore for e in self.entries)

    def add(self, entry: Entry) -> Entry:
        if self._title_taken(entry.title):
            raise DuplicateEntryError(f"an entry titled {entry.title!r} already exists")
        self.entries.append(entry)
        return entry

    def rename(self, entry: Entry, new_title: str) -> None:
        new_title = validate_title(new_title)
        if self._title_taken(new_title, ignore=entry):
            raise DuplicateEntryError(f"an entry titled {new_title!r} already exists")
        entry.title = new_title
        entry.touch()

    def remove(self, entry: Entry) -> None:
        self.entries.remove(entry)

    def find(self, query: str, *, fuzzy: bool = True) -> Entry:
        """Resolve ``query`` as an exact title (case-insensitive), then as an id prefix.

        With ``fuzzy`` (the default) a search term matching exactly one entry
        also resolves. Destructive operations pass ``fuzzy=False``.
        """
        folded = query.strip().casefold()
        for entry in self.entries:
            if entry.title.casefold() == folded:
                return entry
        if len(folded) >= _MIN_ID_PREFIX:
            by_id = [e for e in self.entries if e.id.startswith(folded)]
            if len(by_id) == 1:
                return by_id[0]
            if len(by_id) > 1:
                raise AmbiguousEntryError(f"id prefix {query!r} matches several entries")
        if not fuzzy:
            raise EntryNotFoundError(f"no entry is titled {query!r} (use the exact title or the id)")
        candidates = self.search(query)
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            names = ", ".join(e.title for e in candidates[:5])
            raise AmbiguousEntryError(f"{query!r} matches several entries: {names}")
        raise EntryNotFoundError(f"no entry matches {query!r}")

    def search(self, term: str) -> list[Entry]:
        return [e for e in self if e.matches(term)]

    def unique_title(self, title: str) -> str:
        """``title`` or ``title (2)``, ``title (3)``... whichever is free (used by import)."""
        candidate, n = title, 2
        while self._title_taken(candidate):
            candidate, n = f"{title} ({n})", n + 1
        return candidate

    def to_payload(self) -> dict[str, Any]:
        data: dict[str, Any] = dict(self.extra)
        data["schema"] = PAYLOAD_SCHEMA
        data["entries"] = [e.to_dict() for e in self.entries]
        return data

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> VaultContents:
        schema = data.get("schema")
        if type(schema) is not int or schema < 1:
            raise VaultFormatError("payload has no valid schema version")
        if schema > PAYLOAD_SCHEMA:
            raise VaultFormatError("vault contents were written by a newer SecureVault; upgrade to open them")
        raw_entries = data.get("entries")
        if not isinstance(raw_entries, list):
            raise VaultFormatError("payload entries must be a list")
        contents = cls(extra={k: v for k, v in data.items() if k not in {"schema", "entries"}})
        for raw in raw_entries:
            entry = Entry.from_dict(raw)
            if contents._title_taken(entry.title):
                entry.title = contents.unique_title(entry.title)
            contents.entries.append(entry)
        return contents
