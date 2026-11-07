"""Password health audit: reused, weak and stale passwords.

Everything runs locally on the decrypted entries. Nothing is sent anywhere. A
breach check against Have I Been Pwned is planned as an *offline* lookup in a
downloaded hash list, so it also never needs the network.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from .generator import estimate_strength
from .model import Entry, parse_timestamp

WEAK_BITS = 60.0
DEFAULT_MAX_AGE_DAYS = 365


@dataclass(frozen=True)
class Finding:
    kind: str  # "reused" | "weak" | "stale" | "empty"
    entry: Entry
    detail: str


def audit(
    entries: Iterable[Entry],
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    weak_bits: float = WEAK_BITS,
    now: datetime | None = None,
) -> list[Finding]:
    current = now or datetime.now(UTC)
    findings: list[Finding] = []
    by_password: dict[str, list[Entry]] = defaultdict(list)

    for entry in entries:
        if not entry.password:
            findings.append(Finding("empty", entry, "no password stored"))
            continue
        by_password[entry.password].append(entry)
        bits = estimate_strength(entry.password)
        if bits < weak_bits:
            findings.append(Finding("weak", entry, f"estimated {bits:.0f} bits (< {weak_bits:.0f})"))
        try:
            age = (current - parse_timestamp(entry.modified)).days
        except ValueError:
            continue
        if age > max_age_days:
            findings.append(Finding("stale", entry, f"unchanged for {age} days"))

    for group in by_password.values():
        if len(group) > 1:
            for entry in group:
                others = ", ".join(e.title for e in group if e is not entry)
                findings.append(Finding("reused", entry, f"same password as: {others}"))

    order = {"reused": 0, "weak": 1, "empty": 2, "stale": 3}
    findings.sort(key=lambda f: (order[f.kind], f.entry.title.casefold()))
    return findings
