from __future__ import annotations

from dataclasses import dataclass

from .base58 import b58check_encode
from .crypto_primitives import hash160, hmac_sha512
from .secp256k1 import G, N, Point, point_add, scalar_mult, ser_p


XPRV = bytes.fromhex("0488ADE4")
XPUB = bytes.fromhex("0488B21E")


@dataclass
class ExtendedPrivateKey:
    depth: int
    parent_fingerprint: bytes
    child_number: int
    chain_code: bytes
    private_key: int

    @classmethod
    def from_seed(cls, seed: bytes) -> "ExtendedPrivateKey":
        i = hmac_sha512(b"Bitcoin seed", seed)
        il, ir = i[:32], i[32:]
        k = int.from_bytes(il, "big")
        if k == 0 or k >= N:
            raise ValueError("invalid master key generated")
        return cls(0, b"\x00\x00\x00\x00", 0, ir, k)

    @property
    def public_point(self) -> Point:
        return scalar_mult(self.private_key, G)

    @property
    def fingerprint(self) -> bytes:
        return hash160(ser_p(self.public_point))[:4]

    def serialize(self) -> bytes:
        return (
            XPRV
            + bytes([self.depth])
            + self.parent_fingerprint
            + self.child_number.to_bytes(4, "big")
            + self.chain_code
            + b"\x00"
            + self.private_key.to_bytes(32, "big")
        )

    def to_base58(self) -> str:
        return b58check_encode(self.serialize())

    def to_public(self) -> "ExtendedPublicKey":
        return ExtendedPublicKey(
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_number=self.child_number,
            chain_code=self.chain_code,
            public_key=self.public_point,
        )

    def child(self, index: int) -> "ExtendedPrivateKey":
        if not 0 <= index <= 0xFFFFFFFF:
            raise ValueError("child index out of range")
        hardened = index >= 0x80000000
        if hardened:
            data = b"\x00" + self.private_key.to_bytes(32, "big") + index.to_bytes(4, "big")
        else:
            data = ser_p(self.public_point) + index.to_bytes(4, "big")

        i = hmac_sha512(self.chain_code, data)
        il, ir = i[:32], i[32:]
        child_k = (int.from_bytes(il, "big") + self.private_key) % N
        if int.from_bytes(il, "big") >= N or child_k == 0:
            raise ValueError("invalid derived key, increment index and retry")
        return ExtendedPrivateKey(
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint,
            child_number=index,
            chain_code=ir,
            private_key=child_k,
        )


@dataclass
class ExtendedPublicKey:
    depth: int
    parent_fingerprint: bytes
    child_number: int
    chain_code: bytes
    public_key: Point

    @property
    def fingerprint(self) -> bytes:
        return hash160(ser_p(self.public_key))[:4]

    def serialize(self) -> bytes:
        return (
            XPUB
            + bytes([self.depth])
            + self.parent_fingerprint
            + self.child_number.to_bytes(4, "big")
            + self.chain_code
            + ser_p(self.public_key)
        )

    def to_base58(self) -> str:
        return b58check_encode(self.serialize())

    def child(self, index: int) -> "ExtendedPublicKey":
        if index >= 0x80000000:
            raise ValueError("cannot derive hardened child from extended public key")
        data = ser_p(self.public_key) + index.to_bytes(4, "big")
        i = hmac_sha512(self.chain_code, data)
        il, ir = i[:32], i[32:]
        tweak = int.from_bytes(il, "big")
        if tweak >= N:
            raise ValueError("invalid derived key, increment index and retry")
        child_point = point_add(scalar_mult(tweak, G), self.public_key)
        if child_point.inf:
            raise ValueError("invalid derived public key, increment index and retry")
        return ExtendedPublicKey(
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint,
            child_number=index,
            chain_code=ir,
            public_key=child_point,
        )


def parse_path(path: str) -> list[int]:
    if path in ("m", "M", ""):
        return []
    if not path.startswith(("m/", "M/")):
        raise ValueError("path must start with m/")
    result = []
    for piece in path[2:].split("/"):
        hardened = piece.endswith("'") or piece.endswith("h") or piece.endswith("H")
        if hardened:
            piece = piece[:-1]
        idx = int(piece)
        if idx < 0 or idx >= 0x80000000:
            raise ValueError("invalid index")
        if hardened:
            idx += 0x80000000
        result.append(idx)
    return result


def derive_path(root: ExtendedPrivateKey, path: str) -> ExtendedPrivateKey:
    key = root
    for idx in parse_path(path):
        key = key.child(idx)
    return key
