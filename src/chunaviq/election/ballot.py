"""Encrypted ballot format (protocol v2) and the ballot box's stateless checks.

A ballot for a constituency with options [C1, ..., Cm, NOTA] carries:

  tag         Enc(T; r_T) -- the voter's registered tag T = g^t, encrypted, so the
              public record never shows which ballots share a voter -- plus a
              proof of knowledge of (r_T, t). Only the holder of t can make a
              ballot for T; the ballot box and the eligibility authority, who
              both see T, cannot.
  selections  one ciphertext per option with a 0/1 proof
  limit_proof the product of the selections encrypts exactly 1

Selection and limit proofs are bound to the tag ciphertext, and the tag proof
is bound to all selections, so no part of a ballot can be lifted into another.

The ballot box also receives, privately and never published, the plaintext T
and a proof that the tag ciphertext encrypts it (``link``), which it needs to
know which ballots are revotes of one another.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto import sigma
from ..crypto.elgamal import Ciphertext, PublicKey, add
from ..crypto.encoding import canonical_json, from_hex, sha256_hex, to_hex
from ..crypto.proofs import ChaumPedersenProof, DisjunctiveProof, cp_prove, cp_verify, disjunctive_prove, disjunctive_verify

SELECTION_LIMIT = 1
CT_KEYS = {"alpha", "beta"}
DISJ_KEYS = {"a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1"}
CP_KEYS = {"a", "b", "v"}
BALLOT_KEYS = {"election_id", "constituency", "tag", "selections", "limit_proof"}


def selection_context(mhash: str, constituency: str, option_id: str, tag_alpha: str) -> list:
    return [mhash, "selection", constituency, option_id, tag_alpha]


def limit_context(mhash: str, constituency: str, tag_alpha: str) -> list:
    return [mhash, "contest-limit", constituency, tag_alpha]


def tag_context(mhash: str, constituency: str, body_digest: str) -> list:
    return [mhash, "ballot-tag", constituency, body_digest]


def link_context(mhash: str, tracking: str) -> list:
    return [mhash, "tag-link", tracking]


def body_digest(selections: list, limit_proof: dict) -> str:
    return sha256_hex(canonical_json({"selections": selections, "limit_proof": limit_proof}))


def tracking_code(ballot: dict) -> str:
    return sha256_hex(canonical_json(ballot))


def fast_pows(pk: PublicKey) -> dict:
    return {pk.group.g: pk.group.g_pow, pk.K: pk.k_pow}


@dataclass
class PreparedBallot:
    """Client-side ballot plus the secrets needed for a Benaloh challenge and the tag link."""

    ballot: dict
    choice: str
    nonces: list[int]
    tag_r: int

    @property
    def tracking_code(self) -> str:
        return tracking_code(self.ballot)


def encrypt_ballot(pk: PublicKey, mhash: str, election_id: str, constituency: str, option_ids: list[str], choice: str, t: int) -> PreparedBallot:
    if choice not in option_ids:
        raise ValueError("choice is not an option on this ballot")
    grp = pk.group
    r_T = grp.rand_scalar()
    tag_ct = Ciphertext(grp.g_pow(r_T), grp.g_pow(t) * pk.k_pow(r_T) % grp.p)
    ta = to_hex(tag_ct.alpha)
    sels, nonces, cts = [], [], []
    for oid in option_ids:
        m = 1 if oid == choice else 0
        r = grp.rand_scalar()
        ct = pk.encrypt(m, r)
        pr = disjunctive_prove(pk, ct, m, r, selection_context(mhash, constituency, oid, ta))
        sels.append({"option_id": oid, "ciphertext": ct.to_dict(), "proof": pr.to_dict()})
        nonces.append(r)
        cts.append(ct)
    agg = add(grp, cts)
    R = sum(nonces) % grp.q
    lp = cp_prove(
        grp, R, pk.K, agg.alpha, grp.div(agg.beta, grp.g_pow(SELECTION_LIMIT)), "contest-limit", limit_context(mhash, constituency, ta), h_pow=pk.k_pow
    )
    lpd = lp.to_dict()
    st = sigma.tag_statement(grp, pk.K, tag_ct.alpha, tag_ct.beta)
    tproof = sigma.prove(grp, st, [r_T, t], "ballot-tag", tag_context(mhash, constituency, body_digest(sels, lpd)), fast_pows(pk))
    ballot = {
        "election_id": election_id,
        "constituency": constituency,
        "tag": {"ciphertext": tag_ct.to_dict(), "proof": tproof},
        "selections": sels,
        "limit_proof": lpd,
    }
    return PreparedBallot(ballot, choice, nonces, r_T)


def make_link(pk: PublicKey, mhash: str, prepared: PreparedBallot, T: int) -> dict:
    """Private proof for the ballot box that the tag ciphertext encrypts T."""
    grp = pk.group
    tc = Ciphertext.from_dict(prepared.ballot["tag"]["ciphertext"])
    st = sigma.link_statement(grp, pk.K, tc.alpha, tc.beta, T)
    return sigma.prove(grp, st, [prepared.tag_r], "tag-link", link_context(mhash, prepared.tracking_code), fast_pows(pk))


class BallotRejected(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def check_ballot(ballot: dict, *, pk: PublicKey, mhash: str, election_id: str, options: dict[str, list[str]]) -> None:
    """Stateless validity checks. Raises BallotRejected(code). Order: cheap first."""
    grp = pk.group
    try:
        if set(ballot) != BALLOT_KEYS:
            raise BallotRejected("MALFORMED")
        if ballot["election_id"] != election_id:
            raise BallotRejected("WRONG_ELECTION")
        cons = ballot["constituency"]
        if cons not in options:
            raise BallotRejected("UNKNOWN_CONSTITUENCY")
        tag = ballot["tag"]
        if set(tag) != {"ciphertext", "proof"} or set(tag["ciphertext"]) != CT_KEYS:
            raise BallotRejected("MALFORMED")
        tct = Ciphertext.from_dict(tag["ciphertext"])
        if not pk.is_valid_ciphertext(tct):
            raise BallotRejected("INVALID_CIPHERTEXT")
        ta = tag["ciphertext"]["alpha"]
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
            if not disjunctive_verify(pk, ct, pr, selection_context(mhash, cons, s["option_id"], ta)):
                raise BallotRejected("BAD_SELECTION_PROOF")
            cts.append(ct)
        agg = add(grp, cts)
        if set(ballot["limit_proof"]) != CP_KEYS:
            raise BallotRejected("MALFORMED")
        lp = ChaumPedersenProof.from_dict(ballot["limit_proof"])
        if not cp_verify(
            grp, pk.K, agg.alpha, grp.div(agg.beta, grp.g_pow(SELECTION_LIMIT)), lp, "contest-limit", limit_context(mhash, cons, ta), h_pow=pk.k_pow
        ):
            raise BallotRejected("BAD_LIMIT_PROOF")
        st = sigma.tag_statement(grp, pk.K, tct.alpha, tct.beta)
        if not sigma.verify(grp, st, tag["proof"], "ballot-tag", tag_context(mhash, cons, body_digest(sels, ballot["limit_proof"])), fast_pows(pk)):
            raise BallotRejected("BAD_TAG_PROOF")
    except BallotRejected:
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        raise BallotRejected("MALFORMED") from None


def check_link(pk: PublicKey, mhash: str, ballot: dict, T_hex: str, link: dict) -> int:
    """Verify the private tag link; returns T. Raises BallotRejected('BAD_TAG_LINK')."""
    grp = pk.group
    try:
        T = from_hex(T_hex)
        tc = Ciphertext.from_dict(ballot["tag"]["ciphertext"])
        if T == 1 or not grp.is_element(T):
            raise ValueError
        st = sigma.link_statement(grp, pk.K, tc.alpha, tc.beta, T)
        if not sigma.verify(grp, st, link, "tag-link", link_context(mhash, tracking_code(ballot)), fast_pows(pk)):
            raise ValueError
        return T
    except (KeyError, TypeError, ValueError, AttributeError):
        raise BallotRejected("BAD_TAG_LINK") from None


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
