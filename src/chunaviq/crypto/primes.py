"""Primality testing and deterministic, nothing-up-my-sleeve group derivation.

The election group is *derived* from a public seed string so that anyone can
re-run the derivation and confirm that the parameters contain no hidden
structure chosen by the project authors. See spec/protocol.md section 2.
"""

from __future__ import annotations

import hashlib
import secrets

_SMALL_PRIMES: list[int] = []


def _small_primes(limit: int = 20000) -> list[int]:
    if _SMALL_PRIMES:
        return _SMALL_PRIMES
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i * i :: i] = bytearray(len(sieve[i * i :: i]))
    _SMALL_PRIMES.extend(i for i, v in enumerate(sieve) if v)
    return _SMALL_PRIMES


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin with trial division. Error probability <= 4**-rounds."""
    if n < 2:
        return False
    for sp in _small_primes():
        if n == sp:
            return True
        if n % sp == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _expand(seed: bytes, label: bytes, nbits: int) -> int:
    nbytes = (nbits + 7) // 8
    out = hashlib.shake_256(b"chunaviq/v1/group-derivation\x00" + seed + b"\x00" + label).digest(nbytes)
    return int.from_bytes(out, "big") >> (nbytes * 8 - nbits)


def derive_group(seed: str, pbits: int, qbits: int) -> tuple[int, int, int]:
    """Derive a Schnorr group (p, q, g) with p = q*r + 1 deterministically from seed.

    q: smallest prime >= expand(seed, "q") with its top bit forced.
    r: even cofactor starting from expand(seed, "r") within the range that
       makes p exactly pbits long; incremented by 2 until p is prime.
    g: h^r mod p for the smallest h >= 2 with g != 1, so g has order q.
    """
    sb = seed.encode()
    q = _expand(sb, b"q", qbits) | (1 << (qbits - 1)) | 1
    while not is_probable_prime(q):
        q += 2
    if q.bit_length() != qbits:
        raise ValueError("q overflowed its bit length; choose another seed")

    lo = ((1 << (pbits - 1)) + q - 1) // q
    hi = ((1 << pbits) - 1) // q
    r = lo + _expand(sb, b"r", pbits - qbits) % (hi - lo)
    if r % 2:
        r += 1
    while True:
        p = q * r + 1
        if p.bit_length() != pbits:
            raise ValueError("p left its bit range; choose another seed")
        if is_probable_prime(p):
            break
        r += 2

    h = 2
    while True:
        g = pow(h, r, p)
        if g != 1:
            break
        h += 1
    return p, q, g
