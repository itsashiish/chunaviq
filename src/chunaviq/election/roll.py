"""Synthetic electoral roll.

Identifiers deliberately do NOT follow the EPIC (3 letters + 7 digits) or
Aadhaar (12 digits) formats, so synthetic data can never be mistaken for, or
collide with, a real Indian identity document. No names, addresses, ages,
genders or phone numbers are generated: the prototype needs none of them.
"""

from __future__ import annotations

import random
import secrets
from dataclasses import dataclass

from .manifest import NOTA_ID, Candidate, Constituency

SYN_PARTIES = ["Synthetic Party A", "Synthetic Party B", "Synthetic Party C", "Synthetic Party D", "Independent (synthetic)"]


@dataclass(frozen=True)
class SyntheticVoter:
    voter_id: str  # e.g. "syn-v-0000042" -- not a real ID format
    constituency: str
    auth_secret: bytes  # stands in for the authority's real authentication factors


def make_constituencies(count: int, candidates_per: int, eligible: list[int], seed: int) -> list[Constituency]:
    rng = random.Random(seed)
    out = []
    for i in range(count):
        cands = [Candidate(f"C{j + 1}", f"Synthetic Candidate {i + 1}.{j + 1}", rng.choice(SYN_PARTIES)) for j in range(candidates_per)]
        cands.append(Candidate(NOTA_ID, "None of the Above", "-"))
        out.append(Constituency(f"SYN-AC-{i + 1:02d}", f"Synthetic Constituency {i + 1}", tuple(cands), eligible[i]))
    return out


def make_roll(constituencies: list[Constituency]) -> list[SyntheticVoter]:
    roll, n = [], 0
    for c in constituencies:
        for _ in range(c.eligible_voters):
            n += 1
            roll.append(SyntheticVoter(f"syn-v-{n:07d}", c.id, secrets.token_bytes(16)))
    return roll


def split_eligible(total: int, count: int, seed: int) -> list[int]:
    rng = random.Random(seed)
    weights = [rng.uniform(0.7, 1.3) for _ in range(count)]
    s = sum(weights)
    sizes = [int(total * w / s) for w in weights]
    sizes[0] += total - sum(sizes)
    return sizes
