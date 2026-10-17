"""Synthetic electoral roll and synthetic identity attributes.

Identifiers deliberately do NOT follow any real format -- not EPIC (3 letters +
7 digits), not Aadhaar (12 digits), not PAN (5 letters, 4 digits, 1 letter), not
an Indian mobile number -- so synthetic data can never be mistaken for, or
collide with, a real identity document. ``tools/scan_pii.py`` enforces this in CI.

Each synthetic person carries what the identity layer needs to exercise the
Aadhaar and PAN paths (``identity.py``): a synthetic Aadhaar reference, a PAN
reference for most people, a synthetic phone, a face template standing in for
the roll photograph, and a synthetic name and date of birth for PAN matching.
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
    aadhaar_ref: str  # "syn-uid-0000042"
    pan_ref: str | None  # "syn-pan-0000042"; about 1 in 5 synthetic people have none
    mobile_ref: str  # "syn-mob-0000042"
    face: bytes  # 32-byte template standing in for the roll photograph
    name: str
    dob: str


def make_constituencies(count: int, candidates_per: int, eligible: list[int], seed: int, start: int = 1, prefix: str = "SYN-AC") -> list[Constituency]:
    rng = random.Random(seed)
    out = []
    for i in range(count):
        cands = [Candidate(f"C{j + 1}", f"Synthetic Candidate {i + 1}.{j + 1}", rng.choice(SYN_PARTIES)) for j in range(candidates_per)]
        cands.append(Candidate(NOTA_ID, "None of the Above", "-"))
        n = start + i
        out.append(Constituency(f"{prefix}-{n:02d}" if prefix == "SYN-AC" else f"{prefix}-{n:03d}", f"Synthetic Constituency {n}", tuple(cands), eligible[i]))
    return out


def make_roll(constituencies: list[Constituency], start: int = 1, seed: int = 0) -> list[SyntheticVoter]:
    rng = random.Random(seed ^ 0x5EED)
    roll, n = [], start - 1
    for c in constituencies:
        for _ in range(c.eligible_voters):
            n += 1
            roll.append(
                SyntheticVoter(
                    voter_id=f"syn-v-{n:07d}",
                    constituency=c.id,
                    aadhaar_ref=f"syn-uid-{n:07d}",
                    pan_ref=f"syn-pan-{n:07d}" if rng.random() < 0.8 else None,
                    mobile_ref=f"syn-mob-{n:07d}",
                    face=secrets.token_bytes(32),
                    name=f"Synthetic Person {n}",
                    dob=f"19{50 + n % 50:02d}-{1 + n % 12:02d}-{1 + n % 28:02d}",
                )
            )
    return roll


def split_eligible(total: int, count: int, seed: int) -> list[int]:
    rng = random.Random(seed)
    weights = [rng.uniform(0.7, 1.3) for _ in range(count)]
    s = sum(weights)
    sizes = [int(total * w / s) for w in weights]
    sizes[0] += total - sum(sizes)
    return sizes
