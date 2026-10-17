"""Election manifest: the frozen, officer-signed configuration of one election.

Modelled on an Indian first-past-the-post contest: each constituency elects one
member, each voter has exactly one vote in their own constituency, and the
ballot includes NOTA ("None of the Above"). All names are synthetic.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from ..crypto.encoding import canonical_json, sha256_hex

NOTA_ID = "NOTA"

SYNTHETIC_NOTICE = (
    "SYNTHETIC RESEARCH ELECTION. All voters, candidates, parties and results are artificial. "
    "This record has no legal effect and was not produced under the authority of the Election "
    "Commission of India or any State Election Commission."
)


@dataclass(frozen=True)
class Candidate:
    id: str
    name: str
    party: str

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "party": self.party}


@dataclass(frozen=True)
class Constituency:
    id: str
    name: str
    candidates: tuple[Candidate, ...]
    eligible_voters: int

    @property
    def option_ids(self) -> list[str]:
        return [c.id for c in self.candidates]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "eligible_voters": self.eligible_voters,
            "options": [c.to_dict() for c in self.candidates],
        }


def source_digest(root: Path | None = None) -> str:
    """SHA-256 over the sorted (path, content) pairs of the election package.
    Published in the manifest so observers can match the record to a release."""
    root = root or Path(__file__).resolve().parents[1]
    h = hashlib.sha256()
    for f in sorted(root.rglob("*.py")):
        rel = f.relative_to(root).as_posix().encode()
        h.update(len(rel).to_bytes(4, "big") + rel)
        data = f.read_bytes()
        h.update(len(data).to_bytes(8, "big") + data)
    return h.hexdigest()


def build_manifest(
    *,
    election_id: str,
    title: str,
    group_name: str,
    constituencies: list[Constituency],
    opens_at: str,
    closes_at: str,
    threshold: int,
    trustee_keys: list[str],
    officer_key: str,
    board_key: str,
    eligibility_key: str,
    software_version: str,
    federation: dict | None = None,
) -> dict:
    for c in constituencies:
        ids = c.option_ids
        if len(set(ids)) != len(ids) or ids[-1] != NOTA_ID or ids.count(NOTA_ID) != 1:
            raise ValueError(f"{c.id}: options must be unique and end with exactly one NOTA")
        if len(ids) < 2:
            raise ValueError(f"{c.id}: at least one contesting candidate required")
    if len({c.id for c in constituencies}) != len(constituencies):
        raise ValueError("duplicate constituency id")
    if not 1 <= threshold <= len(trustee_keys):
        raise ValueError("threshold must satisfy 1 <= k <= n")
    out = {
        "spec_version": "chunaviq-record/1",
        "election_id": election_id,
        "title": title,
        "notice": SYNTHETIC_NOTICE,
        "voting_rule": "FPTP-single-member; one selection per ballot; NOTA counted but cannot win",
        "group": group_name,
        "window": {"opens_at": opens_at, "closes_at": closes_at},
        "constituencies": [c.to_dict() for c in constituencies],
        "trustees": {
            "threshold": threshold,
            "members": [{"index": i + 1, "role": f"trustee-{i + 1}", "public_key": k} for i, k in enumerate(trustee_keys)],
        },
        "keys": {"officer": officer_key, "board": board_key, "eligibility": eligibility_key},
        "software": {"name": "chunaviq", "version": software_version, "source_digest": source_digest()},
    }
    if federation is not None:
        out["federation"] = federation
    return out


def manifest_hash(manifest: dict) -> str:
    return sha256_hex(canonical_json(manifest))
