"""Non-interactive zero-knowledge proofs (Fiat-Shamir, SHA-256).

* SchnorrProof         -- knowledge of x with X = g^x (trustee coefficients)
* ChaumPedersenProof   -- log_g(X) == log_H(Y) (contest limit, decryption shares)
* DisjunctiveProof     -- a ciphertext encrypts 0 or 1 (CDS OR-proof)

Every challenge is domain-separated and bound to a caller-supplied context
(election manifest hash, contest, selection, credential binding) so a proof
cannot be replayed in another place. These are textbook constructions
(Schnorr 1991; Chaum-Pedersen 1992; Cramer-Damgard-Schoenmakers 1994), as used
by ElectionGuard and Helios. They are implemented here for research and have
NOT been independently audited.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .elgamal import Ciphertext, PublicKey
from .encoding import from_hex, hash_to_scalar, to_hex
from .group import Group


def _in_range(grp: Group, *xs: int) -> bool:
    """Range check for proof commitments (a, b, h). Full subgroup membership is
    not needed for these: each verification equation pins the commitment to a
    product of values already known to be in the subgroup, so a commitment that
    passes the equation is necessarily in the subgroup. Values that are raised
    to the challenge (X, Y, ciphertext components) DO get full membership
    checks: x^c can hide a small-order component when c is even."""
    return all(isinstance(x, int) and not isinstance(x, bool) and 1 <= x < grp.p for x in xs)


# --------------------------------------------------------------------------- Schnorr
@dataclass(frozen=True)
class SchnorrProof:
    commitment: int
    response: int

    def to_dict(self) -> dict:
        return {"h": to_hex(self.commitment), "v": to_hex(self.response)}

    @staticmethod
    def from_dict(d: dict) -> SchnorrProof:
        return SchnorrProof(from_hex(d["h"]), from_hex(d["v"]))


def schnorr_prove(grp: Group, x: int, X: int, context: list[Any]) -> SchnorrProof:
    u = grp.rand_scalar()
    h = grp.g_pow(u)
    c = hash_to_scalar(grp.q, "schnorr", context, X, h)
    return SchnorrProof(h, (u + c * x) % grp.q)


def schnorr_verify(grp: Group, X: int, proof: SchnorrProof, context: list[Any]) -> bool:
    if not (grp.is_element(X) and _in_range(grp, proof.commitment) and grp.is_scalar(proof.response)):
        return False
    c = hash_to_scalar(grp.q, "schnorr", context, X, proof.commitment)
    return grp.g_pow(proof.response) == proof.commitment * grp.pow(X, c) % grp.p


# --------------------------------------------------------------------- Chaum-Pedersen
@dataclass(frozen=True)
class ChaumPedersenProof:
    a: int
    b: int
    response: int

    def to_dict(self) -> dict:
        return {"a": to_hex(self.a), "b": to_hex(self.b), "v": to_hex(self.response)}

    @staticmethod
    def from_dict(d: dict) -> ChaumPedersenProof:
        return ChaumPedersenProof(from_hex(d["a"]), from_hex(d["b"]), from_hex(d["v"]))


def cp_prove(grp: Group, x: int, H: int, X: int, Y: int, domain: str, context: list[Any], h_pow=None) -> ChaumPedersenProof:
    """Prove X = g^x and Y = H^x. h_pow optionally supplies a fast H^e."""
    u = grp.rand_scalar()
    a = grp.g_pow(u)
    b = h_pow(u) if h_pow else grp.pow(H, u)
    c = hash_to_scalar(grp.q, domain, context, H, X, Y, a, b)
    return ChaumPedersenProof(a, b, (u + c * x) % grp.q)


def cp_verify(grp: Group, H: int, X: int, Y: int, proof: ChaumPedersenProof, domain: str, context: list[Any], h_pow=None) -> bool:
    if not all(grp.is_element(v) for v in (H, X, Y)) or not _in_range(grp, proof.a, proof.b) or not grp.is_scalar(proof.response):
        return False
    c = hash_to_scalar(grp.q, domain, context, H, X, Y, proof.a, proof.b)
    v = proof.response
    if grp.g_pow(v) != proof.a * grp.pow(X, c) % grp.p:
        return False
    hv = h_pow(v) if h_pow else grp.pow(H, v)
    return hv == proof.b * grp.pow(Y, c) % grp.p


# --------------------------------------------------------------------- 0/1 OR-proof
@dataclass(frozen=True)
class DisjunctiveProof:
    a0: int
    b0: int
    a1: int
    b1: int
    c0: int
    c1: int
    v0: int
    v1: int

    def to_dict(self) -> dict:
        names = ("a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1")
        return {n: to_hex(getattr(self, n)) for n in names}

    @staticmethod
    def from_dict(d: dict) -> DisjunctiveProof:
        return DisjunctiveProof(*(from_hex(d[n]) for n in ("a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1")))


def _disj_challenge(pk: PublicKey, ct: Ciphertext, a0, b0, a1, b1, context) -> int:
    return hash_to_scalar(pk.group.q, "selection-0or1", context, pk.K, ct.alpha, ct.beta, a0, b0, a1, b1)


def disjunctive_prove(pk: PublicKey, ct: Ciphertext, m: int, r: int, context: list[Any]) -> DisjunctiveProof:
    grp = pk.group
    q, p = grp.q, grp.p
    if m not in (0, 1):
        raise ValueError("plaintext must be 0 or 1")
    beta_over_g = grp.div(ct.beta, grp.g)
    u = grp.rand_scalar()
    if m == 0:
        c1, v1 = grp.rand_scalar(), grp.rand_scalar()
        a1 = grp.g_pow(v1) * grp.pow(ct.alpha, q - c1) % p
        b1 = pk.k_pow(v1) * grp.pow(beta_over_g, q - c1) % p
        a0, b0 = grp.g_pow(u), pk.k_pow(u)
        c = _disj_challenge(pk, ct, a0, b0, a1, b1, context)
        c0 = (c - c1) % q
        v0 = (u + c0 * r) % q
    else:
        c0, v0 = grp.rand_scalar(), grp.rand_scalar()
        a0 = grp.g_pow(v0) * grp.pow(ct.alpha, q - c0) % p
        b0 = pk.k_pow(v0) * grp.pow(ct.beta, q - c0) % p
        a1, b1 = grp.g_pow(u), pk.k_pow(u)
        c = _disj_challenge(pk, ct, a0, b0, a1, b1, context)
        c1 = (c - c0) % q
        v1 = (u + c1 * r) % q
    return DisjunctiveProof(a0, b0, a1, b1, c0, c1, v0, v1)


def disjunctive_verify(pk: PublicKey, ct: Ciphertext, pr: DisjunctiveProof, context: list[Any]) -> bool:
    grp = pk.group
    p = grp.p
    if not (grp.is_element(ct.alpha) and grp.is_element(ct.beta) and _in_range(grp, pr.a0, pr.b0, pr.a1, pr.b1)):
        return False
    if not all(grp.is_scalar(x) for x in (pr.c0, pr.c1, pr.v0, pr.v1)):
        return False
    c = _disj_challenge(pk, ct, pr.a0, pr.b0, pr.a1, pr.b1, context)
    if (pr.c0 + pr.c1) % grp.q != c:
        return False
    beta_over_g = grp.div(ct.beta, grp.g)
    return (
        grp.g_pow(pr.v0) == pr.a0 * grp.pow(ct.alpha, pr.c0) % p
        and pk.k_pow(pr.v0) == pr.b0 * grp.pow(ct.beta, pr.c0) % p
        and grp.g_pow(pr.v1) == pr.a1 * grp.pow(ct.alpha, pr.c1) % p
        and pk.k_pow(pr.v1) == pr.b1 * grp.pow(beta_over_g, pr.c1) % p
    )


__all__ = [
    "SchnorrProof",
    "schnorr_prove",
    "schnorr_verify",
    "ChaumPedersenProof",
    "cp_prove",
    "cp_verify",
    "DisjunctiveProof",
    "disjunctive_prove",
    "disjunctive_verify",
]
