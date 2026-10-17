"""Exponential ElGamal over the election group.

Enc(m; r) = (alpha, beta) = (g^r, g^m * K^r). Ciphertexts multiply component-wise
to add plaintexts, which is what makes a tally possible without decrypting any
individual ballot.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isqrt

from .encoding import from_hex, to_hex
from .group import FixedBase, Group


@dataclass(frozen=True)
class Ciphertext:
    alpha: int
    beta: int

    def to_dict(self) -> dict:
        return {"alpha": to_hex(self.alpha), "beta": to_hex(self.beta)}

    @staticmethod
    def from_dict(d: dict) -> Ciphertext:
        return Ciphertext(from_hex(d["alpha"]), from_hex(d["beta"]))


class PublicKey:
    """Joint election public key K with a fixed-base table for fast K^x."""

    def __init__(self, group: Group, K: int) -> None:
        if not group.is_element(K) or K == 1:
            raise ValueError("public key is not a valid non-identity group element")
        self.group = group
        self.K = K
        self._fb = FixedBase(K, group.p, group.q.bit_length())

    def k_pow(self, e: int) -> int:
        return self._fb.pow(e % self.group.q)

    def encrypt(self, m: int, r: int) -> Ciphertext:
        grp = self.group
        return Ciphertext(grp.g_pow(r), grp.g_pow(m) * self.k_pow(r) % grp.p)

    def is_valid_ciphertext(self, ct: Ciphertext) -> bool:
        return self.group.is_element(ct.alpha) and self.group.is_element(ct.beta)


def add(group: Group, cts: list[Ciphertext]) -> Ciphertext:
    a, b = 1, 1
    for ct in cts:
        a = a * ct.alpha % group.p
        b = b * ct.beta % group.p
    return Ciphertext(a, b)


def dlog_bounded(group: Group, gm: int, bound: int) -> int:
    """Return m in [0, bound] with g^m == gm, or raise.

    Baby-step giant-step: O(sqrt(bound)) time and memory. A national-scale
    constituency (~6 million votes for one option) needs ~2,450 baby steps
    instead of 6 million sequential multiplications."""
    if bound < 0:
        raise ValueError("negative bound")
    p = group.p
    n = isqrt(bound) + 1
    baby: dict[int, int] = {}
    acc = 1
    for j in range(n):
        baby.setdefault(acc, j)
        acc = acc * group.g % p
    giant = pow(acc, -1, p)  # g^-n
    gamma = gm % p
    for i in range(n + 1):
        j = baby.get(gamma)
        if j is not None:
            m = i * n + j
            if m <= bound:
                return m
            break
        gamma = gamma * giant % p
    raise ValueError("plaintext outside expected range (inconsistent tally)")
