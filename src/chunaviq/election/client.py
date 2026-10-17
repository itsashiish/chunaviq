"""Simulated voter device (protocol v2).

Real deployments would run this logic in an audited client on the voter's own
device. The device is the least trustworthy component in remote voting: it can
be malware-infected or watched by a coercer. Two defences live here:

  * Benaloh cast-or-challenge (``spoil_and_audit``) catches a device that
    encrypts a different choice from the one the voter picked.
  * Revoting and re-registration (``prepare`` again, ``register`` again) let a
    voter who was watched, pressured or paid vote again later in private. Only
    the last ballot under a currently valid tag counts, and the public record
    never shows which one that was.

``t`` (the tag secret) never leaves the device. ``check_counted`` verifies the
ballot box's designated-verifier proof that this device's latest ballot is the
one that counts -- a proof that convinces only the holder of ``t`` and so cannot
be shown to a coercer as evidence.
"""

from __future__ import annotations

from ..crypto import sigma
from ..crypto.elgamal import Ciphertext, PublicKey
from ..crypto.encoding import to_hex
from ..crypto.proofs import schnorr_prove
from .ballot import PreparedBallot, benaloh_audit, encrypt_ballot, fast_pows, make_link
from .eligibility import register_context
from .identity import live_capture
from .roll import SyntheticVoter

METHODS = ("aadhaar-otp", "aadhaar-face", "pan")


def dv_context(mhash: str, tracking: str) -> list:
    return [mhash, "dv-final", tracking]


class VoterDevice:
    def __init__(self, voter: SyntheticVoter, election_id: str, mhash: str, pk: PublicKey, option_ids: list[str]) -> None:
        self.voter = voter
        self.election_id = election_id
        self.mhash = mhash
        self.pk = pk
        self.option_ids = option_ids
        self.t: int | None = None
        self.T: int | None = None
        self.registration: dict | None = None
        self.cast: list[str] = []  # tracking codes of ballots cast, oldest first

    # -------------------------------------------------------------- registration
    def authenticate(self, elig, method: str = "aadhaar-otp", genuine_face: bool = True) -> str:
        v = self.voter
        phones = elig.identity.phones
        if method == "aadhaar-otp":
            txn = elig.aadhaar_otp_start(v.aadhaar_ref)
            return elig.aadhaar_otp_finish(v.aadhaar_ref, txn, phones.last(v.mobile_ref))
        if method == "aadhaar-face":
            return elig.aadhaar_face(v.aadhaar_ref, live_capture(v.face, genuine_face))
        if method == "pan":
            if v.pan_ref is None:
                raise ValueError("this synthetic person has no PAN")
            txn = elig.pan_start(v.pan_ref, v.name, v.dob)
            return elig.pan_finish(v.pan_ref, txn, phones.last(v.mobile_ref), live_capture(v.face, genuine_face))
        raise ValueError(f"unknown method {method}")

    def register(self, elig, method: str = "aadhaar-otp") -> dict:
        """Verify identity and register a fresh tag. Calling it again re-registers:
        the previous tag (and every ballot cast with it) stops counting."""
        session = self.authenticate(elig, method)
        grp = self.pk.group
        t = grp.rand_scalar()
        T = grp.g_pow(t)
        proof = schnorr_prove(grp, t, T, register_context(self.election_id, self.voter.constituency, session))
        self.registration = elig.register(session, to_hex(T), proof.to_dict())
        self.t, self.T = t, T
        return self.registration

    # -------------------------------------------------------------------- voting
    def prepare(self, choice: str) -> PreparedBallot:
        if self.t is None:
            raise RuntimeError("not registered")
        return encrypt_ballot(self.pk, self.mhash, self.election_id, self.voter.constituency, self.option_ids, choice, self.t)

    def submission(self, prepared: PreparedBallot) -> dict:
        assert self.T is not None
        return {"ballot": prepared.ballot, "tag": to_hex(self.T), "link": make_link(self.pk, self.mhash, prepared, self.T)}

    def spoil_and_audit(self, prepared: PreparedBallot) -> bool:
        return benaloh_audit(self.pk, prepared, self.option_ids)

    # -------------------------------------------------------------- after close
    def check_counted(self, flag_ct: dict, dv_proof: dict, tracking: str | None = None) -> bool:
        """Is my latest ballot the one that counts? Verifies the ballot box's
        designated-verifier proof about the finalization flag of that ballot."""
        if not self.cast or self.T is None:
            return False
        F = Ciphertext.from_dict(flag_ct)
        br = sigma.dv_branches(self.pk.group, self.pk.K, (F.alpha, F.beta), self.T)
        return sigma.verify_or(self.pk.group, br, dv_proof, "dv-final", dv_context(self.mhash, tracking or self.cast[-1]), fast_pows(self.pk))

    def fake_counted_proof(self, flag_ct: dict, tracking: str) -> dict:
        """What makes the proof worthless to a coercer: with t, the voter can produce
        an equally valid 'proof' for ANY ballot, counted or not."""
        assert self.t is not None and self.T is not None
        F = Ciphertext.from_dict(flag_ct)
        br = sigma.dv_branches(self.pk.group, self.pk.K, (F.alpha, F.beta), self.T)
        return sigma.prove_or(self.pk.group, br, 1, [self.t], "dv-final", dv_context(self.mhash, tracking), fast_pows(self.pk))
