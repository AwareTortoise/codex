from __future__ import annotations

from dataclasses import dataclass


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424


@dataclass(frozen=True)
class Point:
    x: int
    y: int
    inf: bool = False


INF = Point(0, 0, True)
G = Point(GX, GY)


def _inv_mod(x: int, m: int) -> int:
    return pow(x, -1, m)


def point_add(p: Point, q: Point) -> Point:
    if p.inf:
        return q
    if q.inf:
        return p
    if p.x == q.x and (p.y != q.y or p.y == 0):
        return INF
    if p.x == q.x:
        lam = (3 * p.x * p.x + A) * _inv_mod(2 * p.y % P, P) % P
    else:
        lam = (q.y - p.y) * _inv_mod((q.x - p.x) % P, P) % P
    xr = (lam * lam - p.x - q.x) % P
    yr = (lam * (p.x - xr) - p.y) % P
    return Point(xr, yr)


def scalar_mult(k: int, p: Point = G) -> Point:
    if k % N == 0 or p.inf:
        return INF
    if k < 0:
        return scalar_mult(-k, Point(p.x, (-p.y) % P))
    result = INF
    addend = p
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def ser_p(point: Point, compressed: bool = True) -> bytes:
    if point.inf:
        raise ValueError("cannot serialize point at infinity")
    if compressed:
        prefix = 0x02 if (point.y % 2 == 0) else 0x03
        return bytes([prefix]) + point.x.to_bytes(32, "big")
    return b"\x04" + point.x.to_bytes(32, "big") + point.y.to_bytes(32, "big")


def parse_p(data: bytes) -> Point:
    if len(data) == 33 and data[0] in (2, 3):
        x = int.from_bytes(data[1:], "big")
        alpha = (pow(x, 3, P) + B) % P
        beta = pow(alpha, (P + 1) // 4, P)
        y = beta if (beta % 2 == data[0] % 2) else (P - beta)
        return Point(x, y)
    if len(data) == 65 and data[0] == 4:
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:], "big")
        return Point(x, y)
    raise ValueError("invalid SEC1 encoded point")
