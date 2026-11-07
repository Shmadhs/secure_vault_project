from __future__ import annotations

import base64

import pytest

from securevault import totp

# RFC 6238 Appendix B. The seeds are ASCII digits, repeated to the hash's block size.
SEEDS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}
RFC6238 = [
    (59, "SHA1", "94287082"),
    (59, "SHA256", "46119246"),
    (59, "SHA512", "90693936"),
    (1111111109, "SHA1", "07081804"),
    (1111111109, "SHA256", "68084774"),
    (1111111109, "SHA512", "25091201"),
    (1111111111, "SHA1", "14050471"),
    (1111111111, "SHA256", "67062674"),
    (1111111111, "SHA512", "99943326"),
    (1234567890, "SHA1", "89005924"),
    (1234567890, "SHA256", "91819424"),
    (1234567890, "SHA512", "93441116"),
    (2000000000, "SHA1", "69279037"),
    (2000000000, "SHA256", "90698825"),
    (2000000000, "SHA512", "38618901"),
    (20000000000, "SHA1", "65353130"),
    (20000000000, "SHA256", "77737706"),
    (20000000000, "SHA512", "47863826"),
]
# RFC 4226 Appendix D, counters 0..9.
RFC4226 = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]


@pytest.mark.parametrize(("t", "algorithm", "expected"), RFC6238)
def test_rfc6238_vectors(t: int, algorithm: str, expected: str) -> None:
    config = totp.TotpConfig(secret=SEEDS[algorithm], digits=8, period=30, algorithm=algorithm)
    assert totp.now(config, at=t)[0] == expected


@pytest.mark.parametrize(("counter", "expected"), list(enumerate(RFC4226)))
def test_rfc4226_vectors(counter: int, expected: str) -> None:
    assert totp.hotp(SEEDS["SHA1"], counter) == expected


def test_remaining_seconds() -> None:
    config = totp.TotpConfig(secret=SEEDS["SHA1"])
    assert totp.now(config, at=60)[1] == 30
    assert totp.now(config, at=89)[1] == 1


def test_parse_bare_secret_with_spaces_and_lowercase() -> None:
    secret = base64.b32encode(SEEDS["SHA1"]).decode().rstrip("=").lower()
    spaced = " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))
    assert totp.parse(spaced).secret == SEEDS["SHA1"]


def test_parse_otpauth_uri() -> None:
    secret = base64.b32encode(SEEDS["SHA256"]).decode().rstrip("=")
    uri = f"otpauth://totp/Example:alice@example.com?secret={secret}&issuer=Example&algorithm=SHA256&digits=8&period=60"
    config = totp.parse(uri)
    assert (config.secret, config.algorithm, config.digits, config.period) == (SEEDS["SHA256"], "SHA256", 8, 60)


@pytest.mark.parametrize(
    "bad",
    [
        "not base32 !!",
        "JBSWY3DP",  # 40 bits: too short
        "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
        "otpauth://totp/x?issuer=nosecret",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=six",
    ],
)
def test_parse_rejects(bad: str) -> None:
    with pytest.raises(totp.TotpError):
        totp.parse(bad)


def test_config_repr_hides_secret() -> None:
    assert "1234" not in repr(totp.TotpConfig(secret=SEEDS["SHA1"]))
