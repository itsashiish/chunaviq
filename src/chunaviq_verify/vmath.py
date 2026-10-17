"""Primitive operations for the independent verifier.

INDEPENDENCE RULE: nothing in chunaviq_verify may import from the `chunaviq`
package (enforced by tests/test_verifier_independence.py). Everything here is
re-implemented from spec/protocol.md and spec/record-format.md so that a bug in
the election code is not silently shared by the code that checks it.
Third-party dependencies: `cryptography` (Ed25519 only) and optionally gmpy2.
"""

from __future__ import annotations

import hashlib
import json
import secrets

try:
    import gmpy2

    def powmod(b: int, e: int, m: int) -> int:
        return int(gmpy2.powmod(b, e, m))
except ImportError:  # pragma: no cover
    powmod = pow  # type: ignore[assignment]

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# ------------------------------------------------------------------ encodings
def cjson(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def hx(s) -> int:
    if not isinstance(s, str) or not s or (len(s) > 1 and s[0] == "0") or any(c not in "0123456789abcdef" for c in s):
        raise ValueError("bad hex integer")
    return int(s, 16)


def _item(x) -> bytes:
    if isinstance(x, bool):
        raise TypeError
    if isinstance(x, int):
        b = x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")
        return b"i" + len(b).to_bytes(4, "big") + b
    if isinstance(x, str):
        b = x.encode()
        return b"s" + len(b).to_bytes(4, "big") + b
    if isinstance(x, list):
        return b"l" + len(x).to_bytes(4, "big") + b"".join(_item(y) for y in x)
    raise TypeError(type(x))


def challenge(q: int, domain: str, *items) -> int:
    data = b"chunaviq/v1/" + domain.encode() + b"\x00" + _item(list(items))
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % q


# ------------------------------------------------------------------ group
class G:
    def __init__(self, p: int, q: int, g: int) -> None:
        self.p, self.q, self.g = p, q, g

    def member(self, x) -> bool:
        return isinstance(x, int) and 1 <= x < self.p and powmod(x, self.q, self.p) == 1

    def rng(self, *xs) -> bool:
        return all(isinstance(x, int) and 1 <= x < self.p for x in xs)

    def sc(self, *xs) -> bool:
        return all(isinstance(x, int) and 0 <= x < self.q for x in xs)

    def e(self, b: int, x: int) -> int:
        return powmod(b, x % self.q, self.p)


def schnorr_ok(G_: G, X: int, h: int, v: int, ctx: list) -> bool:
    if not (G_.member(X) and G_.rng(h) and G_.sc(v)):
        return False
    c = challenge(G_.q, "schnorr", ctx, X, h)
    return G_.e(G_.g, v) == h * G_.e(X, c) % G_.p


def cp_ok(G_: G, H: int, X: int, Y: int, a: int, b: int, v: int, domain: str, ctx: list) -> bool:
    if not (G_.member(H) and G_.member(X) and G_.member(Y) and G_.rng(a, b) and G_.sc(v)):
        return False
    c = challenge(G_.q, domain, ctx, H, X, Y, a, b)
    return G_.e(G_.g, v) == a * G_.e(X, c) % G_.p and G_.e(H, v) == b * G_.e(Y, c) % G_.p


def zero_or_one_ok(G_: G, K: int, al: int, be: int, pr: dict, ctx: list) -> bool:
    a0, b0, a1, b1, c0, c1, v0, v1 = (hx(pr[k]) for k in ("a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1"))
    if not (G_.member(al) and G_.member(be) and G_.rng(a0, b0, a1, b1) and G_.sc(c0, c1, v0, v1)):
        return False
    if (c0 + c1) % G_.q != challenge(G_.q, "selection-0or1", ctx, K, al, be, a0, b0, a1, b1):
        return False
    p = G_.p
    bg = be * pow(G_.g, -1, p) % p
    return (
        G_.e(G_.g, v0) == a0 * G_.e(al, c0) % p
        and G_.e(K, v0) == b0 * G_.e(be, c0) % p
        and G_.e(G_.g, v1) == a1 * G_.e(al, c1) % p
        and G_.e(K, v1) == b1 * G_.e(bg, c1) % p
    )


# ------------------------------------------------------------------ RSA FDH
def rsa_fdh_ok(n: int, e: int, message: bytes, sig: int) -> bool:
    if not 0 < sig < n:
        return False
    k = (n.bit_length() + 7) // 8
    seed, out, ctr = b"chunaviq/v1/credential-fdh\x00" + message, b"", 0
    while len(out) < k - 1:
        out += hashlib.sha256(seed + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return powmod(sig, e, n) == int.from_bytes(out[: k - 1], "big")


# ------------------------------------------------------------------ Ed25519
def ed_ok(body: dict, pub_hex: str, role: str) -> bool:
    try:
        if body.get("signer") != role:
            return False
        unsigned = {k: v for k, v in body.items() if k != "signature"}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(body["signature"]), b"chunaviq/v1/signed-body\x00" + cjson(unsigned))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError, AttributeError):
        return False


# ------------------------------------------------------------------ Merkle (RFC 9162)
def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf(data: bytes) -> bytes:
    return _h(b"\x00" + data)


def roots_at(leaves: list[bytes], sizes: set[int]) -> dict[int, bytes]:
    """Root of every requested prefix, computed with an RFC 6962 stack (O(n log n))."""
    out = {}
    if 0 in sizes:
        out[0] = _h(b"")
    stack: list[tuple[int, bytes]] = []  # (height, hash) -- perfect subtrees, left to right
    for i, lf in enumerate(leaves):
        stack.append((0, lf))
        while len(stack) >= 2 and stack[-1][0] == stack[-2][0]:
            hgt, r = stack.pop()
            _, left = stack.pop()
            stack.append((hgt + 1, _h(b"\x01" + left + r)))
        if i + 1 in sizes:
            acc = stack[-1][1]
            for _, hsh in reversed(stack[:-1]):
                acc = _h(b"\x01" + hsh + acc)
            out[i + 1] = acc
    return out


def inclusion_ok(leaf_h: bytes, index: int, size: int, path: list[bytes], root: bytes) -> bool:
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf_h
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _h(b"\x01" + p + r)
            if not fn & 1:
                while not fn & 1 and fn:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _h(b"\x01" + r + p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_ok(m: int, n: int, r1: bytes, r2: bytes, proof: list[bytes]) -> bool:
    if m < 1 or m > n:
        return False
    if m == n:
        return not proof and r1 == r2
    if not proof:
        return False
    path = ([r1] if m & (m - 1) == 0 else []) + list(proof)
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _h(b"\x01" + c + fr)
            sr = _h(b"\x01" + c + sr)
            if not fn & 1:
                while not fn & 1 and fn:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _h(b"\x01" + sr + c)
        fn >>= 1
        sn >>= 1
    return fr == r1 and sr == r2 and sn == 0


# ------------------------------------------------------------------ group derivation
def probable_prime(n: int, rounds: int = 32) -> bool:
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % sp == 0:
            return n == sp
    d, s = n - 1, 0
    while not d & 1:
        d >>= 1
        s += 1
    for _ in range(rounds):
        x = powmod(2 + secrets.randbelow(n - 3), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rederive(seed: str, pbits: int, qbits: int) -> tuple[int, int, int]:
    def ex(label: bytes, nbits: int) -> int:
        nb = (nbits + 7) // 8
        o = hashlib.shake_256(b"chunaviq/v1/group-derivation\x00" + seed.encode() + b"\x00" + label).digest(nb)
        return int.from_bytes(o, "big") >> (nb * 8 - nbits)

    q = ex(b"q", qbits) | (1 << (qbits - 1)) | 1
    while not probable_prime(q):
        q += 2
    lo = ((1 << (pbits - 1)) + q - 1) // q
    hi = ((1 << pbits) - 1) // q
    r = lo + ex(b"r", pbits - qbits) % (hi - lo)
    r += r & 1
    while not probable_prime(q * r + 1):
        r += 2
    p = q * r + 1
    h = 2
    while powmod(h, r, p) == 1:
        h += 1
    return p, q, powmod(h, r, p)
