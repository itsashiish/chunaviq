"""Prime-order subgroup of Z_p^* used for ElGamal and the zero-knowledge proofs."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from . import params

try:  # Optional GMP acceleration (pip install "verifiable-election-lab[fast]").
    import gmpy2 as _gmpy2

    def powmod(b: int, e: int, m: int) -> int:
        return int(_gmpy2.powmod(b, e, m))

    BACKEND = "gmpy2"
except ImportError:  # pragma: no cover - exercised in the no-extras CI job
    powmod = pow  # type: ignore[assignment]
    BACKEND = "python"


@dataclass(frozen=True)
class Group:
    name: str
    p: int
    q: int
    g: int
    secure: bool
    _fb_g: FixedBase | None = field(default=None, compare=False, repr=False)

    # --- element / scalar helpers -------------------------------------------------
    def is_element(self, x: object) -> bool:
        """True iff x is in the order-q subgroup (rejects 0, 1-outside-range, and
        elements of small-order subgroups that would leak information)."""
        return isinstance(x, int) and not isinstance(x, bool) and 1 <= x < self.p and powmod(x, self.q, self.p) == 1

    def is_scalar(self, x: object) -> bool:
        return isinstance(x, int) and not isinstance(x, bool) and 0 <= x < self.q

    def rand_scalar(self) -> int:
        return 1 + secrets.randbelow(self.q - 1)

    def g_pow(self, e: int) -> int:
        fb = self._fb_g
        return fb.pow(e % self.q) if fb is not None else powmod(self.g, e % self.q, self.p)

    def pow(self, base: int, e: int) -> int:
        return powmod(base, e % self.q, self.p)

    def mul(self, *xs: int) -> int:
        r = 1
        for x in xs:
            r = r * x % self.p
        return r

    def inv(self, x: int) -> int:
        return pow(x, -1, self.p)

    def div(self, a: int, b: int) -> int:
        return a * pow(b, -1, self.p) % self.p

    def fixed_base(self, base: int) -> FixedBase:
        return FixedBase(base, self.p, self.q.bit_length())

    def describe(self) -> dict:
        from .encoding import to_hex

        return {"name": self.name, "p": to_hex(self.p), "q": to_hex(self.q), "g": to_hex(self.g)}


class FixedBase:
    """Precomputed window table for exponentiation of one fixed base.

    pow(e) costs ~bits/w multiplications instead of ~1.5*bits, which makes
    g^x and K^x roughly 10x faster. Pure performance; results are identical
    to the builtin pow (asserted by tests/test_crypto_group.py).
    """

    __slots__ = ("p", "w", "table", "nbits")

    def __init__(self, base: int, p: int, nbits: int, w: int = 8) -> None:
        self.p, self.w, self.nbits = p, w, nbits
        self.table: list[list[int]] = []
        b = base % p
        for _ in range((nbits + w - 1) // w):
            row = [1] * (1 << w)
            acc = 1
            for j in range(1, 1 << w):
                acc = acc * b % p
                row[j] = acc
            self.table.append(row)
            b = acc * b % p

    def pow(self, e: int) -> int:
        if e < 0 or e.bit_length() > self.nbits:
            raise ValueError("exponent out of range for fixed-base table")
        p, w, mask, r, i = self.p, self.w, (1 << self.w) - 1, 1, 0
        while e:
            d = e & mask
            if d:
                r = r * self.table[i][d] % p
            e >>= w
            i += 1
        return r


def _make(name: str, p: int, q: int, g: int, secure: bool) -> Group:
    grp = Group(name, p, q, g, secure)
    object.__setattr__(grp, "_fb_g", FixedBase(g, p, q.bit_length()))
    return grp


_CACHE: dict[str, Group] = {}


def get_group(name: str) -> Group:
    if name not in _CACHE:
        if name == "EVLAB-2048-256-V1":
            _CACHE[name] = _make(name, params.P_2048, params.Q_2048, params.G_2048, True)
        elif name == "TEST-INSECURE-512-160":
            _CACHE[name] = _make(name, params.P_TEST, params.Q_TEST, params.G_TEST, False)
        else:
            raise KeyError(f"unknown group {name!r}")
    return _CACHE[name]


DEFAULT_GROUP = "EVLAB-2048-256-V1"
TEST_GROUP = "TEST-INSECURE-512-160"
