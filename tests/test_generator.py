from __future__ import annotations

import math
import string

import pytest

from securevault import generator


def test_wordlist_integrity() -> None:
    words = generator.wordlist()
    assert len(words) == 7776
    assert len(set(words)) == 7776
    assert words[0] == "abacus"
    assert words[-1] == "zoom"


@pytest.mark.parametrize("length", [4, 12, 24, 64, 200])
def test_password_length_and_classes(length: int) -> None:
    for _ in range(50):
        pw = generator.generate_password(length)
        assert len(pw) == length
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in generator.SYMBOLS for c in pw)


def test_class_toggles() -> None:
    pw = generator.generate_password(40, upper=False, symbols=False)
    assert set(pw) <= set(string.ascii_lowercase + string.digits)


def test_exclude_ambiguous() -> None:
    pw = "".join(generator.generate_password(100, exclude_ambiguous=True) for _ in range(20))
    assert not set(pw) & generator.AMBIGUOUS


@pytest.mark.parametrize("length", [0, 3, 2000])
def test_invalid_lengths(length: int) -> None:
    with pytest.raises(ValueError, match="length"):
        generator.generate_password(length)


def test_no_classes() -> None:
    with pytest.raises(ValueError, match="at least one"):
        generator.generate_password(10, lower=False, upper=False, digits=False, symbols=False)


def test_passwords_are_not_repeated() -> None:
    assert len({generator.generate_password(16) for _ in range(500)}) == 500


def test_character_distribution_is_roughly_uniform() -> None:
    """Coarse sanity check that no symbol is grossly over- or under-represented."""
    alphabet = string.ascii_lowercase
    sample = "".join(generator.generate_password(100, upper=False, digits=False, symbols=False) for _ in range(200))
    expected = len(sample) / len(alphabet)
    for ch in alphabet:
        assert 0.75 * expected < sample.count(ch) < 1.25 * expected


def test_passphrase() -> None:
    words = generator.wordlist()
    phrase = generator.generate_passphrase(6, ".")
    parts = phrase.split(".")
    assert len(parts) == 6
    assert all(p in words for p in parts)
    assert generator.generate_passphrase(3, capitalize=True)[0].isupper()


def test_passphrase_word_bounds() -> None:
    with pytest.raises(ValueError, match="word count"):
        generator.generate_passphrase(0)


def test_entropy_math() -> None:
    assert generator.passphrase_entropy(6) == pytest.approx(77.55, abs=0.01)
    assert generator.password_entropy(24, 94) == pytest.approx(24 * math.log2(94))


@pytest.mark.parametrize(
    "weak",
    ["", "password", "Password1!", "dragon2024", "aaaaaaaaaaaaaaaa", "qwertyuiop123", "123456789012", "abcdefghijkl"],
)
def test_strength_flags_weak_passwords(weak: str) -> None:
    assert generator.estimate_strength(weak) < 60


@pytest.mark.parametrize("strong", ["correct-horse-battery-staple-orbit-lumen", "x7#Kp2!vQm9@Lr4$Wn8^"])
def test_strength_accepts_strong_passwords(strong: str) -> None:
    assert generator.estimate_strength(strong) >= 60


def test_generated_passwords_score_strong() -> None:
    for _ in range(50):
        assert generator.estimate_strength(generator.generate_password(20)) >= 60
