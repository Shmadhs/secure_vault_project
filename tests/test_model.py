from __future__ import annotations

import pytest

from securevault.errors import AmbiguousEntryError, DuplicateEntryError, EntryNotFoundError, VaultFormatError
from securevault.model import MAX_HISTORY, Entry, VaultContents


def _contents() -> VaultContents:
    c = VaultContents()
    c.add(Entry("GitHub", username="kostas", url="https://github.com", tags=["dev"]))
    c.add(Entry("GitLab", username="kostas"))
    c.add(Entry("Τράπεζα Πειραιώς", username="kp", notes="κάρτα"))
    return c


def test_repr_hides_secrets() -> None:
    entry = Entry("Bank", password="hunter2", notes="pin 1234", totp="JBSWY3DPEHPK3PXP")
    entry.set_password("hunter3")
    text = repr(entry)
    for secret in ("hunter2", "hunter3", "1234", "JBSWY3DP"):
        assert secret not in text


def test_password_history_is_bounded() -> None:
    entry = Entry("Site", password="p0")
    for i in range(1, MAX_HISTORY + 5):
        entry.set_password(f"p{i}")
    assert len(entry.history) == MAX_HISTORY
    assert entry.history[0].password == f"p{MAX_HISTORY + 3}"


def test_setting_same_password_is_noop() -> None:
    entry = Entry("Site", password="same")
    entry.set_password("same")
    assert entry.history == []


def test_title_validation() -> None:
    with pytest.raises(ValueError, match="empty"):
        Entry("   ")
    with pytest.raises(ValueError, match="longer"):
        Entry("x" * 300)


def test_titles_unique_case_insensitive() -> None:
    c = _contents()
    with pytest.raises(DuplicateEntryError):
        c.add(Entry("github"))


def test_find_exact_title_wins() -> None:
    assert _contents().find("github").title == "GitHub"


def test_find_unique_search_term() -> None:
    assert _contents().find("πειρ").title == "Τράπεζα Πειραιώς"


def test_find_ambiguous() -> None:
    with pytest.raises(AmbiguousEntryError, match="GitHub"):
        _contents().find("git")


def test_find_by_id_prefix() -> None:
    c = _contents()
    target = c.find("GitLab")
    assert c.find(target.id[:8]) is target


def test_find_missing() -> None:
    with pytest.raises(EntryNotFoundError):
        _contents().find("nothing")


def test_search_covers_fields() -> None:
    c = _contents()
    assert [e.title for e in c.search("DEV")] == ["GitHub"]
    assert [e.title for e in c.search("κάρτα")] == ["Τράπεζα Πειραιώς"]
    assert len(c.search("kostas")) == 2


def test_rename_conflict() -> None:
    c = _contents()
    with pytest.raises(DuplicateEntryError):
        c.rename(c.find("GitLab"), "GITHUB")
    c.rename(c.find("GitLab"), "GitLab CE")
    assert c.find("GitLab CE")


def test_unique_title() -> None:
    c = _contents()
    assert c.unique_title("New") == "New"
    assert c.unique_title("GitHub") == "GitHub (2)"


def test_payload_roundtrip() -> None:
    c = _contents()
    c.find("GitHub").set_password("a")
    c.find("GitHub").set_password("b")
    restored = VaultContents.from_payload(c.to_payload())
    assert [e.to_dict() for e in restored] == [e.to_dict() for e in c]


@pytest.mark.parametrize(
    "payload",
    [
        {"entries": []},
        {"schema": True, "entries": []},
        {"schema": 1, "entries": {}},
        {"schema": 1, "entries": [{"title": 5}]},
        {"schema": 1, "entries": [{"title": "x", "tags": "a,b"}]},
        {"schema": 1, "entries": [{"title": "x", "history": [{"password": 1}]}]},
        {"schema": 1, "entries": [{"title": ""}]},
        {"schema": 1, "entries": ["not an object"]},
    ],
)
def test_malformed_payload(payload: dict) -> None:
    with pytest.raises(VaultFormatError):
        VaultContents.from_payload(payload)


def test_newer_schema_refused() -> None:
    with pytest.raises(VaultFormatError, match="newer"):
        VaultContents.from_payload({"schema": 99, "entries": []})


def test_duplicate_titles_in_payload_are_renamed() -> None:
    restored = VaultContents.from_payload({"schema": 1, "entries": [{"title": "A"}, {"title": "a"}]})
    assert sorted(e.title for e in restored) == ["A", "a (2)"]


def test_find_without_fuzzy_requires_exact() -> None:
    c = _contents()
    with pytest.raises(EntryNotFoundError):
        c.find("πειρ", fuzzy=False)
    assert c.find("gitlab", fuzzy=False).title == "GitLab"


@pytest.mark.parametrize("value", [123, "yesterday", None])
def test_timestamps_validated(value: object) -> None:
    with pytest.raises(VaultFormatError, match="timestamp"):
        VaultContents.from_payload({"schema": 1, "entries": [{"title": "x", "modified": value}]})
