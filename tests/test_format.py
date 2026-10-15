from __future__ import annotations

import json
import struct

import pytest

from securevault.crypto import KdfParams
from securevault.errors import UnsupportedVersionError, VaultFormatError
from securevault.vault_format import (
    FORMAT_VERSION,
    MAGIC,
    MAX_HEADER_SIZE,
    PAD_BLOCK,
    PREAMBLE,
    Header,
    KeySlot,
    decode_payload,
    encode_payload,
    parse_file,
    strict_json_loads,
)

KDF = KdfParams(salt=b"\x01" * 32, memory_kib=65536, iterations=3, lanes=4)
SLOT = KeySlot(kdf=KDF, keyfile=False, wrapped_key=b"\x02" * 60)
HEADER = Header(vault_id="a" * 32, slots=(SLOT,))


def _header_dict() -> dict:
    return json.loads(HEADER.encode())


def _decode(obj: object) -> Header:
    return Header.decode(json.dumps(obj).encode())


def test_header_roundtrip_is_canonical() -> None:
    raw = HEADER.encode()
    assert Header.decode(raw) == HEADER
    assert Header.decode(raw).encode() == raw


def test_slot_aad_binds_kdf_and_vault() -> None:
    other_kdf = KeySlot(KdfParams(b"\x01" * 32, 65536, 4, 4), False, SLOT.wrapped_key)
    assert SLOT.aad("a" * 32) != SLOT.aad("b" * 32)
    assert SLOT.aad("a" * 32) != other_kdf.aad("a" * 32)
    assert SLOT.aad("a" * 32) != KeySlot(KDF, True, SLOT.wrapped_key).aad("a" * 32)


def test_duplicate_json_keys_rejected() -> None:
    with pytest.raises(VaultFormatError, match="duplicate"):
        strict_json_loads('{"a": 1, "a": 2}')


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_json_constants_rejected(constant: str) -> None:
    with pytest.raises(VaultFormatError):
        strict_json_loads(f'{{"a": {constant}}}')


def test_unknown_header_field_rejected() -> None:
    d = _header_dict()
    d["extra"] = 1
    with pytest.raises(VaultFormatError):
        _decode(d)


def test_bool_is_not_an_integer() -> None:
    d = _header_dict()
    d["slots"][0]["kdf"]["iterations"] = True
    with pytest.raises(VaultFormatError, match="integer"):
        _decode(d)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("cipher",), "chacha20"),
        (("vault_id",), "not-hex"),
        (("slots",), []),
        (("slots", 0, "keyfile"), "yes"),
        (("slots", 0, "wrapped_key"), "!!!notbase64"),
        (("slots", 0, "wrapped_key"), "AAAA"),
        (("slots", 0, "kdf", "name"), "scrypt"),
        (("slots", 0, "kdf", "version"), 16),
    ],
)
def test_invalid_header_values_rejected(path: tuple, value: object) -> None:
    d = _header_dict()
    target = d
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(VaultFormatError):
        _decode(d)


def test_too_many_slots_rejected() -> None:
    d = _header_dict()
    d["slots"] = d["slots"] * 9
    with pytest.raises(VaultFormatError):
        _decode(d)


def _file(
    header: bytes = b"", version: int = FORMAT_VERSION, magic: bytes = MAGIC, payload: bytes = b"\0" * 40
) -> bytes:
    header = header or HEADER.encode()
    return PREAMBLE.pack(magic, version, len(header)) + header + payload


def test_parse_file_roundtrip() -> None:
    parsed = parse_file(_file())
    assert parsed.header == HEADER
    assert parsed.header_block == HEADER.block()
    assert parsed.payload == b"\0" * 40


def test_bad_magic() -> None:
    with pytest.raises(VaultFormatError, match="not a SecureVault"):
        parse_file(_file(magic=b"SQLi"))


def test_future_version() -> None:
    with pytest.raises(UnsupportedVersionError):
        parse_file(_file(version=FORMAT_VERSION + 1))


def test_version_zero() -> None:
    with pytest.raises(VaultFormatError):
        parse_file(_file(version=0))


def test_header_length_overflow() -> None:
    data = struct.pack(">4sHI", MAGIC, FORMAT_VERSION, MAX_HEADER_SIZE + 1) + b"{}"
    with pytest.raises(VaultFormatError, match="header length"):
        parse_file(data)


def test_truncated_payload() -> None:
    with pytest.raises(VaultFormatError, match="truncated"):
        parse_file(_file(payload=b"\0" * 10))


@pytest.mark.parametrize("size", range(0, 10))
def test_short_files(size: int) -> None:
    with pytest.raises(VaultFormatError):
        parse_file(_file()[:size])


def test_payload_roundtrip_and_padding() -> None:
    obj = {"schema": 1, "entries": [{"title": "Τράπεζα", "password": "π" * 100}]}
    encoded = encode_payload(obj)
    assert len(encoded) % PAD_BLOCK == 0
    assert decode_payload(encoded) == obj


def test_payload_padding_hides_exact_size() -> None:
    small = encode_payload({"schema": 1, "entries": [], "x": "a"})
    larger = encode_payload({"schema": 1, "entries": [], "x": "a" * 500})
    assert len(small) == len(larger)


def test_payload_nonzero_padding_rejected() -> None:
    encoded = bytearray(encode_payload({"schema": 1}))
    encoded[-1] = 1
    with pytest.raises(VaultFormatError):
        decode_payload(bytes(encoded))


def test_payload_length_overflow_rejected() -> None:
    encoded = bytearray(encode_payload({"schema": 1}))
    encoded[0:4] = struct.pack(">I", len(encoded))
    with pytest.raises(VaultFormatError):
        decode_payload(bytes(encoded))


def test_payload_must_be_object() -> None:
    raw = b"[]"
    with pytest.raises(VaultFormatError):
        decode_payload(struct.pack(">I", len(raw)) + raw)
