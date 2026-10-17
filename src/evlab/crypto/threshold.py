"""k-of-n threshold key ceremony (Feldman VSS, Pedersen-style DKG) and decryption.

Each trustee i picks a random polynomial f_i of degree k-1, publishes
commitments C_ij = g^{a_ij} with a Schnorr proof for each coefficient, and
privately sends f_i(l) to every other trustee l. Trustee l checks each share
against the commitments, then holds s_l = sum_i f_i(l).

    joint public key   K   = prod_i C_i0             (secret s = sum_i a_i0)
    public share of l  K_l = prod_i prod_j C_ij^(l^j) (= g^{s_l}, computable by anyone)

No single trustee -- and no coalition smaller than k -- ever holds s. Decryption
of an aggregate ciphertext uses k partial decryptions M_l = alpha^{s_l}, each with
a Chaum-Pedersen proof against K_l, combined with Lagrange coefficients.

In this prototype the "private channel" for shares is an in-memory call. A real
ceremony needs authenticated, encrypted channels and witnessed procedures; see
docs/key-ceremony.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .elgamal import Ciphertext
from .encoding import from_hex, to_hex
from .group import Group
from .proofs import ChaumPedersenProof, SchnorrProof, cp_prove, cp_verify, schnorr_prove, schnorr_verify


class CeremonyError(Exception):
    pass


@dataclass
class TrusteeCommitment:
    index: int
    commitments: list[int]
    proofs: list[SchnorrProof]

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "commitments": [to_hex(c) for c in self.commitments],
            "proofs": [p.to_dict() for p in self.proofs],
        }

    @staticmethod
    def from_dict(d: dict) -> TrusteeCommitment:
        return TrusteeCommitment(
            int(d["index"]),
            [from_hex(c) for c in d["commitments"]],
            [SchnorrProof.from_dict(p) for p in d["proofs"]],
        )


def coefficient_context(manifest_hash: str, index: int, j: int) -> list:
    return [manifest_hash, "trustee-coefficient", str(index), str(j)]


def verify_commitment(grp: Group, manifest_hash: str, tc: TrusteeCommitment, k: int) -> bool:
    if len(tc.commitments) != k or len(tc.proofs) != k:
        return False
    return all(
        schnorr_verify(grp, C, pr, coefficient_context(manifest_hash, tc.index, j)) for j, (C, pr) in enumerate(zip(tc.commitments, tc.proofs, strict=True))
    )


def eval_commitments(grp: Group, commitments: list[int], x: int) -> int:
    """prod_j C_j^(x^j) -- the public image g^{f(x)} of a committed polynomial."""
    acc, xj = 1, 1
    for C in commitments:
        acc = acc * grp.pow(C, xj) % grp.p
        xj = xj * x % grp.q
    return acc


@dataclass
class Trustee:
    index: int  # 1..n (0 is reserved: f(0) is the secret)
    group: Group
    k: int
    manifest_hash: str
    _coeffs: list[int] = field(default_factory=list, repr=False)
    _received: dict[int, int] = field(default_factory=dict, repr=False)
    secret_share: int | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.index < 1:
            raise ValueError("trustee indices start at 1")
        self._coeffs = [self.group.rand_scalar() for _ in range(self.k)]

    def commitment(self) -> TrusteeCommitment:
        grp = self.group
        Cs = [grp.g_pow(a) for a in self._coeffs]
        proofs = [
            schnorr_prove(grp, a, C, coefficient_context(self.manifest_hash, self.index, j)) for j, (a, C) in enumerate(zip(self._coeffs, Cs, strict=True))
        ]
        return TrusteeCommitment(self.index, Cs, proofs)

    def share_for(self, other_index: int) -> int:
        x, acc, xj = other_index, 0, 1
        for a in self._coeffs:
            acc = (acc + a * xj) % self.group.q
            xj = xj * x % self.group.q
        return acc

    def receive_share(self, from_tc: TrusteeCommitment, share: int) -> None:
        """Verify a dealer's share against its public commitments (Feldman check)."""
        grp = self.group
        if not grp.is_scalar(share) or grp.g_pow(share) != eval_commitments(grp, from_tc.commitments, self.index):
            raise CeremonyError(f"trustee {self.index}: invalid share from trustee {from_tc.index}")
        self._received[from_tc.index] = share

    def finalize(self, n: int) -> None:
        if sorted(self._received) != list(range(1, n + 1)):
            raise CeremonyError(f"trustee {self.index}: missing shares")
        self.secret_share = sum(self._received.values()) % self.group.q
        # Coefficients are no longer needed; drop them (key destruction step).
        self._coeffs = []

    def decryption_share(self, ct: Ciphertext, context: list) -> tuple[int, ChaumPedersenProof]:
        if self.secret_share is None:
            raise CeremonyError("ceremony not finalized")
        grp = self.group
        M = grp.pow(ct.alpha, self.secret_share)
        Ki = grp.g_pow(self.secret_share)
        proof = cp_prove(grp, self.secret_share, ct.alpha, Ki, M, "decryption-share", context)
        return M, proof


def joint_public_key(grp: Group, commitments: list[TrusteeCommitment]) -> int:
    return grp.mul(*(tc.commitments[0] for tc in commitments))


def public_share(grp: Group, commitments: list[TrusteeCommitment], index: int) -> int:
    return grp.mul(*(eval_commitments(grp, tc.commitments, index) for tc in commitments))


def lagrange_at_zero(q: int, indices: list[int], i: int) -> int:
    num, den = 1, 1
    for m in indices:
        if m != i:
            num = num * m % q
            den = den * (m - i) % q
    return num * pow(den, -1, q) % q


def verify_decryption_share(grp: Group, ct: Ciphertext, Ki: int, M: int, proof: ChaumPedersenProof, context: list) -> bool:
    return cp_verify(grp, ct.alpha, Ki, M, proof, "decryption-share", context)


def combine(grp: Group, ct: Ciphertext, shares: dict[int, int]) -> int:
    """Return g^m for ct from >= k verified partial decryptions {index: M_i}."""
    idx = sorted(shares)
    if len(set(idx)) != len(idx):
        raise CeremonyError("duplicate trustee in quorum")
    alpha_s = 1
    for i in idx:
        alpha_s = alpha_s * grp.pow(shares[i], lagrange_at_zero(grp.q, idx, i)) % grp.p
    return grp.div(ct.beta, alpha_s)


def run_ceremony(grp: Group, n: int, k: int, manifest_hash: str) -> tuple[list[Trustee], list[TrusteeCommitment]]:
    """Simulated ceremony: every trustee verifies every commitment and share."""
    if not 1 <= k <= n:
        raise ValueError("need 1 <= k <= n")
    trustees = [Trustee(i, grp, k, manifest_hash) for i in range(1, n + 1)]
    commitments = [t.commitment() for t in trustees]
    for tc in commitments:
        if not verify_commitment(grp, manifest_hash, tc, k):
            raise CeremonyError(f"invalid commitment from trustee {tc.index}")
    for dealer, tc in zip(trustees, commitments, strict=True):
        for t in trustees:
            t.receive_share(tc, dealer.share_for(t.index))
    for t in trustees:
        t.finalize(n)
    return trustees, commitments
