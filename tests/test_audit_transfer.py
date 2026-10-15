from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone

import pytest

from securevault import transfer
from securevault.audit import audit
from securevault.model import Entry, VaultContents

STRONG = "x7#Kp2!vQm9@Lr4$Wn8^"


def test_audit_findings() -> None:
    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    old = (now - timedelta(days=500)).isoformat()
    entries = [
        Entry("A", password=STRONG),
        Entry("B", password=STRONG),
        Entry("Weak", password="password1"),
        Entry("Empty"),
        Entry("Old", password="Zq8$" + STRONG, modified=old),
        Entry("Fine", password="Fine-" + STRONG),
    ]
    findings = audit(entries, now=now)
    kinds = {(f.kind, f.entry.title) for f in findings}
    assert kinds == {("reused", "A"), ("reused", "B"), ("weak", "Weak"), ("empty", "Empty"), ("stale", "Old")}
    assert findings[0].kind == "reused"


def test_audit_healthy() -> None:
    assert audit([Entry("Only", password=STRONG)]) == []


BITWARDEN = (
    "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
    "Work,,login,GitHub,,,0,https://github.com,kostas,gh-pass,JBSWY3DPEHPK3PXP\n"
    "Bank,1,login,Τράπεζα,σημείωση,,0,,kp,bank-pass,\n"
)
KEEPASSXC = (
    '"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"\n'
    '"Root/Email","Gmail","me@gmail.com","gm-pass","https://mail.google.com","","","0","",""\n'
)
FIREFOX = (
    '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\n'
    '"https://accounts.example.org","ann","ex-pass",,"https://accounts.example.org","{x}","1","1","1"\n'
)
CHROME = "name,url,username,password,note\nexample.com,https://example.com/login,bob,chrome-pass,hello\n"


def _import(text: str, contents: VaultContents | None = None) -> VaultContents:
    contents = contents or VaultContents()
    transfer.import_rows(contents, transfer.read_csv(io.StringIO(text)))
    return contents


def test_import_bitwarden() -> None:
    c = _import(BITWARDEN)
    gh = c.find("GitHub")
    assert (gh.username, gh.password, gh.url, gh.totp, gh.tags) == (
        "kostas",
        "gh-pass",
        "https://github.com",
        "JBSWY3DPEHPK3PXP",
        ["Work"],
    )
    assert c.find("Τράπεζα").notes == "σημείωση"


def test_import_keepassxc() -> None:
    gmail = _import(KEEPASSXC).find("Gmail")
    assert (gmail.username, gmail.password, gmail.tags) == ("me@gmail.com", "gm-pass", ["Root/Email"])


def test_import_firefox_derives_title_from_host() -> None:
    entry = _import(FIREFOX).find("accounts.example.org")
    assert (entry.username, entry.password) == ("ann", "ex-pass")


def test_import_chrome() -> None:
    entry = _import(CHROME).find("example.com")
    assert (entry.password, entry.notes) == ("chrome-pass", "hello")


def test_import_renames_duplicates() -> None:
    c = VaultContents()
    c.add(Entry("GitHub"))
    result = transfer.import_rows(c, transfer.read_csv(io.StringIO(BITWARDEN)))
    assert ("GitHub", "GitHub (2)") in result.renamed


def test_import_requires_password_column() -> None:
    with pytest.raises(ValueError, match="password column"):
        transfer.read_csv(io.StringIO("name,url\nx,y\n"))


def test_import_skips_empty_rows() -> None:
    c = VaultContents()
    result = transfer.import_rows(c, transfer.read_csv(io.StringIO("title,password\n,\nA,p\n")))
    assert (len(result.added), result.skipped) == (1, 1)


def test_csv_export_roundtrip() -> None:
    c = _import(BITWARDEN)
    exported = transfer.export_csv(c)
    again = _import(exported)
    assert [(e.title, e.username, e.password, e.url, e.notes, e.totp, e.tags) for e in again] == [
        (e.title, e.username, e.password, e.url, e.notes, e.totp, e.tags) for e in c
    ]


def test_csv_export_keeps_formula_like_passwords_verbatim() -> None:
    c = VaultContents()
    c.add(Entry("Calc", password="=1+1"))
    assert _import(transfer.export_csv(c)).find("Calc").password == "=1+1"


def test_json_export() -> None:
    c = _import(BITWARDEN)
    data = json.loads(transfer.export_json(c))
    assert data["format"] == "securevault-export"
    assert {e["title"] for e in data["entries"]} == {"GitHub", "Τράπεζα"}
