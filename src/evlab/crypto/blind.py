"""Anonymous one-time voting credentials via RSA full-domain-hash blind signatures.

Flow (Chaum 1983):
  voter:   token T (32 random bytes); m = FDH(election, constituency, T)
           picks r, sends blinded m' = m * r^e mod n          -> issuer
  issuer:  checks eligibility, records "credential issued" for the voter,
           returns s' = m'^d mod n                            -> voter
  voter:   s = s' * r^-1 mod n ; (T, s) is a valid credential
  ballot box: accepts (T, s) once if s^e == FDH(...)

The issuer never sees T or s, so it cannot link the credential it signed to the
ballot that later uses it. Security of RSA-FDH blind signatures rests on the
one-more-RSA-inversion assumption (Bellare et al. 2003).

Research note: RFC 9474 standardises RSA blind signatures (RSABSSA, PSS-based).
This FDH variant is simpler to read and verify by hand; a deployment would use
an audited RFC 9474 implementation. Key generation uses the `cryptography`
library; only the blinding arithmetic is implemented here.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa

from .encoding import from_hex, to_hex
from .group import powmod

FDH_DOMAIN = b"evlab/v1/credential-fdh\x00"


def _mgf1_sha256(seed: bytes, length: int) -> bytes:
    out, counter = b"", 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def credential_message(election_id: str, constituency: str, token: bytes) -> bytes:
    if len(token) != 32:
        raise ValueError("token must be 32 bytes")
    return election_id.encode() + b"\x00" + constituency.encode() + b"\x00" + token


def fdh(n: int, message: bytes) -> int:
    """Full-domain hash into [0, 2^(8(k-1))) which is < n for a k-byte modulus."""
    k = (n.bit_length() + 7) // 8
    return int.from_bytes(_mgf1_sha256(FDH_DOMAIN + message, k - 1), "big")


@dataclass(frozen=True)
class RSAPublic:
    n: int
    e: int

    def to_dict(self) -> dict:
        return {"n": to_hex(self.n), "e": to_hex(self.e)}

    @staticmethod
    def from_dict(d: dict) -> RSAPublic:
        return RSAPublic(from_hex(d["n"]), from_hex(d["e"]))

    def verify(self, message: bytes, sig: int) -> bool:
        return 0 < sig < self.n and powmod(sig, self.e, self.n) == fdh(self.n, message)


class RSABlindSigner:
    def __init__(self, bits: int = 3072) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        nums = key.private_numbers()
        self._p, self._q = nums.p, nums.q
        self._dp, self._dq, self._qinv = nums.dmp1, nums.dmq1, nums.iqmp
        self.public = RSAPublic(nums.public_numbers.n, nums.public_numbers.e)

    def sign_blinded(self, blinded: int) -> int:
        n = self.public.n
        if not 0 < blinded < n:
            raise ValueError("blinded message out of range")
        m1 = powmod(blinded, self._dp, self._p)
        m2 = powmod(blinded, self._dq, self._q)
        h = self._qinv * (m1 - m2) % self._p
        s = m2 + h * self._q
        # Fault-attack countermeasure: never release an unchecked CRT result.
        if powmod(s, self.public.e, n) != blinded:
            raise RuntimeError("RSA-CRT self-check failed")
        return s


@dataclass
class BlindingState:
    message: bytes
    r: int


def blind(pub: RSAPublic, message: bytes) -> tuple[int, BlindingState]:
    n = pub.n
    while True:
        r = secrets.randbelow(n - 2) + 2
        if math.gcd(r, n) == 1:
            break
    blinded = fdh(n, message) * powmod(r, pub.e, n) % n
    return blinded, BlindingState(message, r)


def unblind(pub: RSAPublic, state: BlindingState, blind_sig: int) -> int:
    s = blind_sig * pow(state.r, -1, pub.n) % pub.n
    if not pub.verify(state.message, s):
        raise ValueError("issuer returned an invalid blind signature")
    return s
