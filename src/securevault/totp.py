"""Time-based one-time passwords: RFC 6238 (TOTP) over RFC 4226 (HOTP).

Standard library only. Verified against the RFC 6238 Appendix B test vectors
in ``tests/test_totp.py``.

Storing TOTP secrets next to passwords trades some of 2FA's protection for
convenience: whoever unlocks the vault has both factors. It is a common choice
(KeePassXC and Bitwarden offer it), but the README states the trade-off.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

_ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


class TotpError(ValueError):
    """The stored TOTP value cannot be parsed."""


@dataclass(frozen=True)
class TotpConfig:
    secret: bytes = field(repr=False)
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"


def _decode_base32(value: str) -> bytes:
    cleaned = value.replace(" ", "").replace("-", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        secret = base64.b32decode(cleaned, casefold=False)
    except (binascii.Error, ValueError) as exc:
        raise TotpError("TOTP secret is not valid base32") from exc
    # RFC 4226 asks for 128 bits, but many real services issue 80-bit secrets
    # (16 base32 characters). Accept those rather than make the feature useless.
    if len(secret) < 10:
        raise TotpError("TOTP secret is too short (minimum 80 bits)")
    return secret


def parse(value: str) -> TotpConfig:
    """Accept an ``otpauth://totp/...`` URI (as in QR codes) or a bare base32 secret."""
    value = value.strip()
    if not value.lower().startswith("otpauth://"):
        return TotpConfig(secret=_decode_base32(value))
    parts = urlsplit(value)
    if parts.netloc.lower() != "totp":
        raise TotpError("only otpauth://totp URIs are supported (not HOTP)")
    query = {k.lower(): v[-1] for k, v in parse_qs(parts.query).items()}
    if "secret" not in query:
        raise TotpError("otpauth URI has no secret")
    try:
        digits = int(query.get("digits", "6"))
        period = int(query.get("period", "30"))
    except ValueError as exc:
        raise TotpError("otpauth digits/period must be integers") from exc
    algorithm = unquote(query.get("algorithm", "SHA1")).upper()
    if algorithm not in _ALGORITHMS:
        raise TotpError(f"unsupported TOTP algorithm {algorithm!r}")
    if not 6 <= digits <= 10:
        raise TotpError("TOTP digits must be between 6 and 10")
    if not 1 <= period <= 3600:
        raise TotpError("TOTP period must be between 1 and 3600 seconds")
    return TotpConfig(_decode_base32(query["secret"]), digits, period, algorithm)


def hotp(secret: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    """RFC 4226 section 5.3: HMAC, then dynamic truncation, then modulo 10^digits."""
    mac = hmac.new(secret, struct.pack(">Q", counter), _ALGORITHMS[algorithm]).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack_from(">I", mac, offset)[0] & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)


def now(config: TotpConfig, at: float | None = None) -> tuple[str, int]:
    """Current code and the seconds until it expires."""
    timestamp = time.time() if at is None else at
    counter, elapsed = divmod(int(timestamp), config.period)
    code = hotp(config.secret, counter, config.digits, config.algorithm)
    return code, config.period - elapsed
