"""Generic Sigma-protocol proofs of linear relations, and OR-composition.

A *statement* is a list of equations, each of the form

    value = prod_k  base_k ^ w[idx_k]          (in the order-q subgroup)

over a shared witness vector w. The prover shows it knows w; Fiat-Shamir makes
it non-interactive. Proofs are stored in compact form -- the challenge and the
responses -- and the verifier recomputes the commitments:

    A_e = prod_k base_k ^ s[idx_k]  *  value_e ^ (-c)

An OR-proof over several statements (Cramer-Damgard-Schoenmakers 1994) shows
that the prover knows a witness for at least one of them without revealing
which: every branch but the real one is simulated with a chosen challenge, and
the challenges must add up to the Fiat-Shamir hash.

Used for (spec/protocol.md, protocol v2):

  * ballot tag proof     -- knowledge of (r, t) with tag = Enc(g^t; r)
  * tag link proof       -- tag encrypts a stated T (sent privately to the ballot box)
  * finalization proof   -- [flag = 1 and masked = re-encryption of the vote]
                            OR [flag = 0 and masked = encryption of zero]
  * designated-verifier  -- [flag = 1] OR [I know t with T = g^t]; convinces only
                            the voter who holds t, so it cannot be shown to a coercer

Research implementation; not independently audited.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .encoding import from_hex, hash_to_scalar, to_hex
from .group import Group

Eq = tuple[int, list[tuple[int, int]]]  # (value, [(base, witness_index), ...])


@dataclass(frozen=True)
class Statement:
    eqs: list[Eq]
    n_witness: int

    def encode(self) -> list:
        return [[v, [b for b, _ in terms], [str(i) for _, i in terms]] for v, terms in self.eqs]


def _pow_fn(grp: Group, fast: dict[int, Callable[[int], int]] | None) -> Callable[[int, int], int]:
    fast = fast or {}

    def pw(base: int, e: int) -> int:
        f = fast.get(base)
        return f(e % grp.q) if f is not None else grp.pow(base, e)

    return pw


def _commit(grp: Group, st: Statement, s: Sequence[int], c: int, pw) -> list[int]:
    """Recompute commitments from responses s and challenge c."""
    p, q = grp.p, grp.q
    out = []
    for value, terms in st.eqs:
        acc = pw(value, q - c % q) if c % q else 1
        for base, idx in terms:
            acc = acc * pw(base, s[idx]) % p
        out.append(acc)
    return out


def _challenge(grp: Group, domain: str, context: list, stmts: list[Statement], commits: list[list[int]]) -> int:
    return hash_to_scalar(grp.q, domain, context, [st.encode() for st in stmts], commits)


# --------------------------------------------------------------------------- single
def prove(grp: Group, st: Statement, w: Sequence[int], domain: str, context: list, fast=None) -> dict:
    pw = _pow_fn(grp, fast)
    rho = [grp.rand_scalar() for _ in range(st.n_witness)]
    A = []
    for _, terms in st.eqs:
        acc = 1
        for base, idx in terms:
            acc = acc * pw(base, rho[idx]) % grp.p
        A.append(acc)
    c = _challenge(grp, domain, context, [st], [A])
    return {"c": to_hex(c), "s": [to_hex((rho[i] + c * w[i]) % grp.q) for i in range(st.n_witness)]}


def verify(grp: Group, st: Statement, proof: dict, domain: str, context: list, fast=None) -> bool:
    try:
        if set(proof) != {"c", "s"} or len(proof["s"]) != st.n_witness:
            return False
        c = from_hex(proof["c"])
        s = [from_hex(x) for x in proof["s"]]
    except (TypeError, ValueError, KeyError):
        return False
    if not grp.is_scalar(c) or not all(grp.is_scalar(x) for x in s):
        return False
    if not all(grp.is_element(v) for v, _ in st.eqs):
        return False
    A = _commit(grp, st, s, c, _pow_fn(grp, fast))
    return _challenge(grp, domain, context, [st], [A]) == c


# --------------------------------------------------------------------------- OR
def prove_or(grp: Group, branches: list[Statement], real: int, w: Sequence[int], domain: str, context: list, fast=None) -> dict:
    pw = _pow_fn(grp, fast)
    q = grp.q
    cs: list[int] = [0] * len(branches)
    ss: list[list[int]] = [[] for _ in branches]
    A: list[list[int]] = [[] for _ in branches]
    for b, st in enumerate(branches):
        if b == real:
            continue
        cs[b] = grp.rand_scalar()
        ss[b] = [grp.rand_scalar() for _ in range(st.n_witness)]
        A[b] = _commit(grp, st, ss[b], cs[b], pw)
    st = branches[real]
    rho = [grp.rand_scalar() for _ in range(st.n_witness)]
    for _, terms in st.eqs:
        acc = 1
        for base, idx in terms:
            acc = acc * pw(base, rho[idx]) % grp.p
        A[real].append(acc)
    c = _challenge(grp, domain, context, branches, A)
    cs[real] = (c - sum(cs)) % q
    ss[real] = [(rho[i] + cs[real] * w[i]) % q for i in range(st.n_witness)]
    return {"c": [to_hex(x) for x in cs], "s": [[to_hex(x) for x in sb] for sb in ss]}


def verify_or(grp: Group, branches: list[Statement], proof: dict, domain: str, context: list, fast=None) -> bool:
    try:
        if set(proof) != {"c", "s"} or len(proof["c"]) != len(branches) or len(proof["s"]) != len(branches):
            return False
        cs = [from_hex(x) for x in proof["c"]]
        ss = [[from_hex(x) for x in sb] for sb in proof["s"]]
    except (TypeError, ValueError, KeyError):
        return False
    if any(len(sb) != st.n_witness for sb, st in zip(ss, branches, strict=True)):
        return False
    if not all(grp.is_scalar(x) for x in cs) or not all(grp.is_scalar(x) for sb in ss for x in sb):
        return False
    if not all(grp.is_element(v) for st in branches for v, _ in st.eqs):
        return False
    pw = _pow_fn(grp, fast)
    A = [_commit(grp, st, sb, cb, pw) for st, sb, cb in zip(branches, ss, cs, strict=True)]
    return _challenge(grp, domain, context, branches, A) == sum(cs) % grp.q


# --------------------------------------------------------------------------- statements used by the protocol
def dh_pair(grp: Group, g: int, K: int, x: int, y: int, idx: int) -> list[Eq]:
    """x = g^w, y = K^w for witness w[idx] (a Diffie-Hellman pair / encryption of zero)."""
    return [(x, [(g, idx)]), (y, [(K, idx)])]


def tag_statement(grp: Group, K: int, alpha: int, beta: int) -> Statement:
    """Knowledge of (r, t): alpha = g^r, beta = g^t K^r. Witnesses [r, t]."""
    return Statement([(alpha, [(grp.g, 0)]), (beta, [(grp.g, 1), (K, 0)])], 2)


def link_statement(grp: Group, K: int, alpha: int, beta: int, T: int) -> Statement:
    """(alpha, beta / T) is an encryption of zero, i.e. the ciphertext encrypts T. Witness [r]."""
    return Statement(dh_pair(grp, grp.g, K, alpha, grp.div(beta, T), 0), 1)


def finalize_branches(grp: Group, K: int, flag: tuple[int, int], votes: list[tuple[int, int]], masked: list[tuple[int, int]]) -> list[Statement]:
    """Branch 0: flag encrypts 0 and every masked ciphertext encrypts 0.
    Branch 1: flag encrypts 1 and every masked ciphertext re-encrypts the vote.
    Witnesses: [u (flag randomness), w_1 .. w_L (masking randomness)]."""
    g, p = grp.g, grp.p
    fa, fb = flag
    n = 1 + len(votes)
    b0 = dh_pair(grp, g, K, fa, fb, 0)
    b1 = dh_pair(grp, g, K, fa, fb * pow(g, -1, p) % p, 0)
    for j, ((va, vb), (ma, mb)) in enumerate(zip(votes, masked, strict=True)):
        b0 += dh_pair(grp, g, K, ma, mb, j + 1)
        b1 += dh_pair(grp, g, K, ma * pow(va, -1, p) % p, mb * pow(vb, -1, p) % p, j + 1)
    return [Statement(b0, n), Statement(b1, n)]


def dv_branches(grp: Group, K: int, flag: tuple[int, int], T: int) -> list[Statement]:
    """Branch 0: flag encrypts 1 (witness u). Branch 1: T = g^t (witness t).
    The ballot box proves branch 0; the voter, who knows t, could have produced
    an identical-looking proof of branch 1, so the proof convinces only them."""
    fa, fb = flag
    return [Statement(dh_pair(grp, grp.g, K, fa, fb * pow(grp.g, -1, grp.p) % grp.p, 0), 1), Statement([(T, [(grp.g, 0)])], 1)]


__all__ = [
    "Statement",
    "prove",
    "verify",
    "prove_or",
    "verify_or",
    "tag_statement",
    "link_statement",
    "finalize_branches",
    "dv_branches",
]
