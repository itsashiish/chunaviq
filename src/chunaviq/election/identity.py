"""Identity verification for registration: Aadhaar OR PAN, synthetic services only.

What a real deployment would connect to, and what stands in for it here:

  Aadhaar  UIDAI authentication through a licensed AUA/KUA, using OTP to the
           Aadhaar-registered mobile or face authentication. Returns a UID
           token, never the Aadhaar number. Roll linkage uses the Aadhaar number
           the elector chose to give under s.23(5) RP Act 1950 (Form 6B).
           Here: ``SyntheticUIDAI``.
  PAN      Income Tax Department PAN verification (the Protean "Online PAN
           Verification" service): checks that a PAN exists and that a name and
           date of birth match. It involves no OTP or biometric of the holder, so
           on its own it only proves someone *knows* a PAN and a birth date. The
           PAN path therefore also requires an OTP to the mobile on the electoral
           roll AND a face match against the roll photograph.
           Here: ``SyntheticPANService``.

None of these synthetic services accept, generate or resemble real Aadhaar,
PAN or phone numbers (see ``roll.py``). Raw identifiers are never stored by the
eligibility authority: it keeps keyed hashes (HMAC) only, in line with the
Aadhaar Act's limits on storing and sharing Aadhaar numbers.

Whichever document is used, it resolves to ONE electoral-roll entry, and the
roll entry -- not the document -- is the unit that gets one voting credential.
Someone who has both Aadhaar and PAN cannot register twice.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass

from .roll import SyntheticVoter

OTP_TTL_ATTEMPTS = 3
FACE_MATCH_MIN_BITS = 240  # of 256 bits must agree (synthetic stand-in for a match score)


class IdentityError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SyntheticPhoneNetwork:
    """Delivers OTP messages to synthetic phones (tests read the inbox)."""

    def __init__(self) -> None:
        self._inbox: dict[str, list[str]] = {}
        self._lock = threading.Lock()

    def deliver(self, mobile_ref: str, text: str) -> None:
        with self._lock:
            self._inbox.setdefault(mobile_ref, []).append(text)

    def last(self, mobile_ref: str) -> str:
        with self._lock:
            return self._inbox[mobile_ref][-1]


def _otp() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def live_capture(face: bytes, genuine: bool = True) -> bytes:
    """Synthetic camera: a genuine capture differs from the template in a few bits;
    an impostor's capture is unrelated."""
    if not genuine:
        return secrets.token_bytes(len(face))
    flip = bytearray(face)
    for _ in range(4):
        i = secrets.randbelow(len(flip) * 8)
        flip[i // 8] ^= 1 << (i % 8)
    return bytes(flip)


def face_match(template: bytes, capture: bytes) -> bool:
    if len(template) != len(capture):
        return False
    same = sum(8 - bin(a ^ b).count("1") for a, b in zip(template, capture, strict=True))
    return same >= FACE_MATCH_MIN_BITS


@dataclass
class _Txn:
    ref: str
    otp: str
    attempts: int = 0


class SyntheticUIDAI:
    """Stand-in for UIDAI authentication (OTP and face). Returns a per-AUA UID
    token instead of the Aadhaar number."""

    def __init__(self, phones: SyntheticPhoneNetwork) -> None:
        self.phones = phones
        self._people: dict[str, SyntheticVoter] = {}
        self._txn: dict[str, _Txn] = {}
        self._token_key = secrets.token_bytes(32)
        self._lock = threading.Lock()

    def enrol(self, people: list[SyntheticVoter]) -> None:
        for v in people:
            self._people[v.aadhaar_ref] = v

    def _uid_token(self, ref: str) -> str:
        return hmac.new(self._token_key, ref.encode(), hashlib.sha256).hexdigest()

    def uid_token_for_linkage(self, ref: str) -> str:
        """What the roll stores for an elector who gave their Aadhaar under Form 6B
        (simulated: the same token an authentication would return)."""
        return self._uid_token(ref)

    def request_otp(self, ref: str) -> str:
        v = self._people.get(ref)
        if v is None:
            raise IdentityError("AADHAAR_NOT_FOUND")
        txn = secrets.token_hex(8)
        code = _otp()
        with self._lock:
            self._txn[txn] = _Txn(ref, code)
        self.phones.deliver(v.mobile_ref, code)
        return txn

    def verify_otp(self, txn: str, otp: str) -> str:
        with self._lock:
            t = self._txn.get(txn)
            if t is None:
                raise IdentityError("OTP_EXPIRED")
            t.attempts += 1
            if t.attempts > OTP_TTL_ATTEMPTS:
                del self._txn[txn]
                raise IdentityError("OTP_EXPIRED")
            if not hmac.compare_digest(t.otp, otp):
                raise IdentityError("OTP_MISMATCH")
            del self._txn[txn]
        return self._uid_token(t.ref)

    def face_auth(self, ref: str, capture: bytes) -> str:
        v = self._people.get(ref)
        if v is None:
            raise IdentityError("AADHAAR_NOT_FOUND")
        if not face_match(v.face, capture):
            raise IdentityError("FACE_MISMATCH")
        return self._uid_token(ref)


class SyntheticPANService:
    """Stand-in for PAN verification: existence + name and date-of-birth match."""

    def __init__(self) -> None:
        self._people: dict[str, SyntheticVoter] = {}

    def enrol(self, people: list[SyntheticVoter]) -> None:
        for v in people:
            if v.pan_ref:
                self._people[v.pan_ref] = v

    def verify(self, ref: str, name: str, dob: str) -> dict:
        v = self._people.get(ref)
        if v is None:
            return {"status": "not_found", "name_match": False, "dob_match": False}
        return {"status": "valid", "name_match": v.name == name, "dob_match": v.dob == dob}


@dataclass
class IdentityHub:
    """The eligibility authority's view of the identity services."""

    uidai: SyntheticUIDAI
    pan: SyntheticPANService
    phones: SyntheticPhoneNetwork

    @staticmethod
    def synthetic(people: list[SyntheticVoter]) -> IdentityHub:
        phones = SyntheticPhoneNetwork()
        hub = IdentityHub(SyntheticUIDAI(phones), SyntheticPANService(), phones)
        hub.uidai.enrol(people)
        hub.pan.enrol(people)
        return hub


__all__ = [
    "IdentityError",
    "IdentityHub",
    "SyntheticPhoneNetwork",
    "SyntheticUIDAI",
    "SyntheticPANService",
    "live_capture",
    "face_match",
]
