from __future__ import annotations

from .crypto_primitives import double_sha256


_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = bytearray()
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_ALPHABET[rem])
    out.reverse()
    zeros = len(raw) - len(raw.lstrip(b"\x00"))
    return (b"1" * zeros + bytes(out or b"")).decode("ascii")


def b58decode(encoded: str) -> bytes:
    n = 0
    for c in encoded.encode("ascii"):
        idx = _ALPHABET.find(bytes([c]))
        if idx < 0:
            raise ValueError("invalid base58 character")
        n = n * 58 + idx
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    zeros = len(encoded) - len(encoded.lstrip("1"))
    return b"\x00" * zeros + raw


def b58check_encode(payload: bytes) -> str:
    return b58encode(payload + double_sha256(payload)[:4])


def b58check_decode(text: str) -> bytes:
    data = b58decode(text)
    if len(data) < 4:
        raise ValueError("invalid base58check length")
    payload, checksum = data[:-4], data[-4:]
    if double_sha256(payload)[:4] != checksum:
        raise ValueError("invalid base58check checksum")
    return payload
