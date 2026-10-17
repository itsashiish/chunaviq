"""Encrypted ballot format and the ballot box's acceptance checks.

A ballot for a constituency with options [C1, ..., Cm, NOTA] carries one
ciphertext per option, each with a proof that it encrypts 0 or 1, plus a proof
that the product of all ciphertexts encrypts exactly 1. Together these prove
"exactly one option selected" without revealing which.

Every proof's challenge binds the manifest hash, the constituency, the option
and the credential token, so a ballot (or any part of it) copied from the board
cannot be re-cast with another credential.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.blind import RSAPublic, credential_message
from ..crypto.elgamal import Ciphertext, PublicKey, add
from ..crypto.encoding import canonical_json, from_hex, sha256_hex
from ..crypto.proofs import ChaumPedersenProof, DisjunctiveProof, cp_prove, cp_verify, disjunctive_prove, disjunctive_verify

SELECTION_LIMIT = 1
CT_KEYS = {"alpha", "beta"}
DISJ_KEYS = {"a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1"}
CP_KEYS = {"a", "b", "v"}


def selection_context(mhash: str, constituency: str, option_id: str, token_hex: str) -> list:
    return [mhash, "selection", constituency, option_id, token_hex]


def limit_context(mhash: str, constituency: str, token_hex: str) -> list:
    return [mhash, "contest-limit", constituency, token_hex]


def tracking_code(ballot: dict) -> str:
    return sha256_hex(canonical_json(ballot))


@dataclass
class PreparedBallot:
    """Client-side ballot plus the secrets needed for a Benaloh challenge."""

    ballot: dict
    choice: str
    nonces: list[int]

    @property
    def tracking_code(self) -> str:
        return tracking_code(self.ballot)


def encrypt_ballot(
    pk: PublicKey, mhash: str, election_id: str, constituency: str, option_ids: list[str], choice: str, token_hex: str, signature_hex: str
) -> PreparedBallot:
    if choice not in option_ids:
        raise ValueError("choice is not an option on this ballot")
    grp = pk.group
    sels, nonces, cts = [], [], []
    for oid in option_ids:
        m = 1 if oid == choice else 0
        r = grp.rand_scalar()
        ct = pk.encrypt(m, r)
        pr = disjunctive_prove(pk, ct, m, r, selection_context(mhash, constituency, oid, token_hex))
        sels.append({"option_id": oid, "ciphertext": ct.to_dict(), "proof": pr.to_dict()})
        nonces.append(r)
        cts.append(ct)
    agg = add(grp, cts)
    R = sum(nonces) % grp.q
    lp = cp_prove(
        grp, R, pk.K, agg.alpha, grp.div(agg.beta, grp.g_pow(SELECTION_LIMIT)), "contest-limit", limit_context(mhash, constituency, token_hex), h_pow=pk.k_pow
    )
    ballot = {
        "election_id": election_id,
        "constituency": constituency,
        "credential": {"token": token_hex, "signature": signature_hex},
        "selections": sels,
        "limit_proof": lp.to_dict(),
    }
    return PreparedBallot(ballot, choice, nonces)


class BallotRejected(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def check_ballot(ballot: dict, *, pk: PublicKey, mhash: str, election_id: str, options: dict[str, list[str]], issuer_keys: dict[str, RSAPublic]) -> None:
    """Stateless validity checks. Raises BallotRejected(code). Order: cheap first."""
    grp = pk.group
    try:
        if set(ballot) != {"election_id", "constituency", "credential", "selections", "limit_proof"}:
            raise BallotRejected("MALFORMED")
        if ballot["election_id"] != election_id:
            raise BallotRejected("WRONG_ELECTION")
        cons = ballot["constituency"]
        if cons not in options:
            raise BallotRejected("UNKNOWN_CONSTITUENCY")
        cred = ballot["credential"]
        if set(cred) != {"token", "signature"}:
            raise BallotRejected("MALFORMED")
        token_hex = cred["token"]
        if not isinstance(token_hex, str) or len(token_hex) != 64:
            raise BallotRejected("MALFORMED")
        token = bytes.fromhex(token_hex)
        if token.hex() != token_hex:
            raise BallotRejected("MALFORMED")
        if not issuer_keys[cons].verify(credential_message(election_id, cons, token), from_hex(cred["signature"])):
            raise BallotRejected("BAD_CREDENTIAL")
        sels = ballot["selections"]
        if [s.get("option_id") for s in sels] != options[cons]:
            raise BallotRejected("WRONG_BALLOT_STYLE")
        cts = []
        for s in sels:
            if set(s) != {"option_id", "ciphertext", "proof"} or set(s["ciphertext"]) != CT_KEYS or set(s["proof"]) != DISJ_KEYS:
                # Exact schemas everywhere: a free-form field would let a voter mark
                # their ballot and prove it to a vote buyer (receipt-freeness).
                raise BallotRejected("MALFORMED")
            ct = Ciphertext.from_dict(s["ciphertext"])
            if not pk.is_valid_ciphertext(ct):
                raise BallotRejected("INVALID_CIPHERTEXT")
            pr = DisjunctiveProof.from_dict(s["proof"])
            if not disjunctive_verify(pk, ct, pr, selection_context(mhash, cons, s["option_id"], token_hex)):
                raise BallotRejected("BAD_SELECTION_PROOF")
            cts.append(ct)
        agg = add(grp, cts)
        if set(ballot["limit_proof"]) != CP_KEYS:
            raise BallotRejected("MALFORMED")
        lp = ChaumPedersenProof.from_dict(ballot["limit_proof"])
        if not cp_verify(
            grp, pk.K, agg.alpha, grp.div(agg.beta, grp.g_pow(SELECTION_LIMIT)), lp, "contest-limit", limit_context(mhash, cons, token_hex), h_pow=pk.k_pow
        ):
            raise BallotRejected("BAD_LIMIT_PROOF")
    except BallotRejected:
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        raise BallotRejected("MALFORMED") from None


def benaloh_audit(pk: PublicKey, prepared: PreparedBallot, option_ids: list[str]) -> bool:
    """Cast-or-challenge audit: given the revealed choice and nonces of a ballot
    the voter chose to SPOIL, re-encrypt and compare. A device that encrypted a
    different choice than the voter selected is caught with probability equal to
    the fraction of ballots challenged. A spoiled ballot is never cast; the voter
    prepares a fresh one (new nonces) afterwards."""
    sels = prepared.ballot["selections"]
    if len(sels) != len(option_ids) or len(prepared.nonces) != len(option_ids):
        return False
    for oid, s, r in zip(option_ids, sels, prepared.nonces, strict=True):
        expect = pk.encrypt(1 if oid == prepared.choice else 0, r)
        if Ciphertext.from_dict(s["ciphertext"]) != expect:
            return False
    return True
