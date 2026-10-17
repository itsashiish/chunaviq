"""Simulated voter device.

Real deployments would run this logic in an audited client on the voter's own
device. The device is the least trustworthy component in remote voting: it can
be malware-infected or observed by a coercer. The Benaloh challenge
(``spoil_and_audit``) gives voters a way to catch a device that encrypts the
wrong choice; it cannot stop coercion or a device that leaks the choice.
"""

from __future__ import annotations

import secrets

from ..crypto.blind import RSAPublic, blind, credential_message, unblind
from ..crypto.elgamal import PublicKey
from ..crypto.encoding import from_hex, to_hex
from .ballot import PreparedBallot, benaloh_audit, encrypt_ballot
from .roll import SyntheticVoter


class VoterDevice:
    def __init__(self, voter: SyntheticVoter, election_id: str, mhash: str, pk: PublicKey, issuer_key: RSAPublic, option_ids: list[str]) -> None:
        self.voter = voter
        self.election_id = election_id
        self.mhash = mhash
        self.pk = pk
        self.issuer_key = issuer_key
        self.option_ids = option_ids
        self.token: bytes | None = None
        self.signature: int | None = None
        self.participation_receipt: dict | None = None

    def obtain_credential(self, eligibility) -> None:
        token = secrets.token_bytes(32)
        msg = credential_message(self.election_id, self.voter.constituency, token)
        blinded, state = blind(self.issuer_key, msg)
        resp = eligibility.issue_credential(self.voter.voter_id, self.voter.auth_secret, to_hex(blinded))
        self.signature = unblind(self.issuer_key, state, from_hex(resp["blind_signature"]))
        self.token = token
        self.participation_receipt = {"commitment": resp["commitment"], "salt": resp["participation_salt"]}

    def prepare(self, choice: str) -> PreparedBallot:
        if self.token is None or self.signature is None:
            raise RuntimeError("no credential")
        return encrypt_ballot(self.pk, self.mhash, self.election_id, self.voter.constituency, self.option_ids, choice, self.token.hex(), to_hex(self.signature))

    def spoil_and_audit(self, prepared: PreparedBallot) -> bool:
        return benaloh_audit(self.pk, prepared, self.option_ids)
