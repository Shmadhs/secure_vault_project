"""Password and passphrase generation, plus entropy estimates.

All randomness comes from :mod:`secrets` (the OS CSPRNG). The character
generator uses rejection sampling to guarantee every enabled class appears.
Inserting one character of each class at a fixed position would bias the
output.
"""

from __future__ import annotations

import hashlib
import math
import re
import secrets
import string
from functools import lru_cache
from importlib import resources

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
AMBIGUOUS = frozenset("Il1|O0o`'\"")

MIN_LENGTH = 4
MAX_LENGTH = 1024
MAX_WORDS = 64

# SHA-256 of the 7776 EFF words joined with "\n". It pins the wordlist so that
# a corrupted or tampered copy (fewer or duplicated words) is caught.
_EFF_WORDLIST_SHA256 = "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522"
EFF_WORDLIST_SIZE = 7776


@lru_cache(maxsize=1)
def wordlist() -> tuple[str, ...]:
    """The EFF large wordlist (CC BY 3.0 US, Electronic Frontier Foundation)."""
    text = resources.files("securevault.data").joinpath("eff_large_wordlist.txt").read_text("ascii")
    words = tuple(text.split())
    digest = hashlib.sha256(("\n".join(words) + "\n").encode("ascii")).hexdigest()
    if len(words) != EFF_WORDLIST_SIZE or len(set(words)) != EFF_WORDLIST_SIZE or digest != _EFF_WORDLIST_SHA256:
        raise RuntimeError("bundled wordlist failed its integrity check; reinstall SecureVault")
    return words


def build_alphabet(
    *,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> list[str]:
    """The enabled character classes, each as a string."""
    classes = [c for c, on in ((LOWER, lower), (UPPER, upper), (DIGITS, digits), (SYMBOLS, symbols)) if on]
    if exclude_ambiguous:
        classes = ["".join(ch for ch in c if ch not in AMBIGUOUS) for c in classes]
    if not classes:
        raise ValueError("enable at least one character class")
    return classes


def generate_password(
    length: int = 24,
    *,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    classes = build_alphabet(
        lower=lower, upper=upper, digits=digits, symbols=symbols, exclude_ambiguous=exclude_ambiguous
    )
    if not max(MIN_LENGTH, len(classes)) <= length <= MAX_LENGTH:
        raise ValueError(f"length must be between {max(MIN_LENGTH, len(classes))} and {MAX_LENGTH}")
    alphabet = "".join(classes)
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(ch in cls for ch in candidate) for cls in classes):
            return candidate


def password_entropy(length: int, alphabet_size: int) -> float:
    """Upper bound in bits for a uniformly random string (class rejection removes a sliver)."""
    return length * math.log2(alphabet_size)


def generate_passphrase(words: int = 6, separator: str = "-", *, capitalize: bool = False) -> str:
    if not 1 <= words <= MAX_WORDS:
        raise ValueError(f"word count must be between 1 and {MAX_WORDS}")
    chosen = [secrets.choice(wordlist()) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    return separator.join(chosen)


def passphrase_entropy(words: int) -> float:
    return words * math.log2(EFF_WORDLIST_SIZE)


# --------------------------------------------------------------------------- strength

_SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm")


def estimate_strength(password: str) -> float:
    """Conservative heuristic entropy estimate, in bits, for a human-chosen password.

    This is *not* zxcvbn. It applies the character-pool estimate, then penalizes
    the patterns crackers try first: dictionary words, repeats and keyboard or
    alphabet runs. It is meant for flagging weak passwords in an audit, not for
    certifying strong ones.
    """
    if not password:
        return 0.0
    pool = 0
    pool += 26 if any(c in LOWER for c in password) else 0
    pool += 26 if any(c in UPPER for c in password) else 0
    pool += 10 if any(c in DIGITS for c in password) else 0
    pool += len(SYMBOLS) if any(c in SYMBOLS for c in password) else 0
    pool += 100 if any(ord(c) > 127 for c in password) else 0
    bits = len(password) * math.log2(max(pool, 2))

    folded = password.casefold()
    # Dictionary word plus a decoration: "Dragon2024!", "password1".
    core = re.sub(r"[^a-z]", "", folded)
    if core and core in _word_set():
        bits = min(bits, math.log2(EFF_WORDLIST_SIZE) + 3 * (len(password) - len(core)) + 1)
    # Few distinct characters: "aaaaaaa", "121212".
    if len(set(folded)) <= max(2, len(folded) // 4):
        bits = min(bits, len(set(folded)) * 4.0 + 4)
    # Alphabet, digit and keyboard runs such as "abcd", "4321" and "qwerty".
    # A run of n characters is worth about one character plus a little.
    run = _longest_run(folded)
    if run >= 4:
        bits -= (run - 1) * math.log2(max(pool, 2)) - 2
    return max(bits, 0.0)


def _longest_run(text: str) -> int:
    """Length of the longest substring of ``text`` that occurs in a known sequence."""
    longest = 0
    for seq in _SEQUENCES:
        for ordered in (seq, seq[::-1]):
            for start in range(len(text)):
                end = start + longest + 1
                while end <= len(text) and text[start:end] in ordered:
                    longest = end - start
                    end += 1
    return longest


@lru_cache(maxsize=1)
def _word_set() -> frozenset[str]:
    return frozenset(wordlist())
