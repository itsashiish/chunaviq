"""National-scale election as a federation of constituency shards.

Why this shape: every credential is bound to one constituency (it is part of
the signed credential message), so "has this credential voted?" never needs to
look outside the voter's own constituency. Each constituency can therefore run
as an independent election -- its own sequencer, ballot box, public record and
tally -- with no cross-shard coordination on the voting path. National scale
is reached by adding shards, not by making one log faster.

    national/manifest.json      signed by the national officer: window, group,
                                trustee committee, list of constituencies
    national/shard-index.json   signed: each shard's manifest hash, role keys
                                and final checkpoint root
    national/results.json       signed: per-constituency winners, seats by
                                party, national vote totals
    shards/<PC>/record/         a complete chunaviq-record/1 per constituency

The trustee committee is national (the same k-of-n people), but each shard has
its own key ceremony, so a compromise of one constituency's key material does
not expose any other. Each constituency's officer stands in for its Returning
Officer.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import random
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .. import __version__
from ..crypto.encoding import canonical_json, sha256_hex
from ..crypto.signing import RoleKey
from .manifest import NOTA_ID, SYNTHETIC_NOTICE
from .roll import SYN_PARTIES
from .simulate import SimConfig, run

FED_SPEC = "chunaviq-federation/1"
OPENS_AT = "2026-11-02T01:30:00Z"  # matches simulate.run's fixed synthetic window
CLOSES_AT = "2026-11-02T12:30:00Z"


@dataclass
class FedConfig:
    shards: int = 24
    voters_per_shard: int = 300
    candidates_min: int = 3
    candidates_max: int = 8
    turnout: float = 0.66
    trustees: int = 5
    threshold: int = 3
    rsa_bits: int = 3072
    seed: int = 2026
    group: str = "CHUNAVIQ-2048-256-V1"
    workers: int = field(default_factory=lambda: os.cpu_count() or 1)
    national_id: str = "SYN-2026-NATIONAL"


def _run_shard(args: tuple) -> dict:
    out, cfg_dict = args
    cfg = SimConfig(**cfg_dict)
    t = time.perf_counter()
    summary = run(Path(out), cfg)
    summary["wall_s"] = time.perf_counter() - t
    return summary


def _write_signed(path: Path, key: RoleKey, body: dict) -> dict:
    signed = key.sign_body(body)
    path.write_bytes(canonical_json(signed) + b"\n")
    return signed


def run_federation(out: Path, cfg: FedConfig) -> dict:
    out = Path(out)
    (out / "national").mkdir(parents=True, exist_ok=False)
    (out / "shards").mkdir()
    rng = random.Random(cfg.seed)
    t0 = time.perf_counter()

    national = RoleKey("national-officer")
    committee = [RoleKey(f"trustee-{i + 1}") for i in range(cfg.trustees)]

    shards = []
    first_voter = 1
    for i in range(1, cfg.shards + 1):
        eligible = max(20, int(cfg.voters_per_shard * rng.uniform(0.7, 1.3)))
        cands = rng.randint(cfg.candidates_min, cfg.candidates_max)
        shards.append({"id": f"SYN-PC-{i:03d}", "number": i, "eligible_voters": eligible, "candidates": cands, "first_voter": first_voter})
        first_voter += eligible

    manifest = {
        "spec_version": FED_SPEC,
        "election_id": cfg.national_id,
        "title": "Synthetic national general election (research simulation)",
        "notice": SYNTHETIC_NOTICE,
        "voting_rule": "FPTP-single-member per constituency; NOTA counted but cannot win",
        "group": cfg.group,
        "window": {"opens_at": OPENS_AT, "closes_at": CLOSES_AT},
        "trustees": {"threshold": cfg.threshold, "members": [{"index": i + 1, "role": k.role, "public_key": k.public_hex} for i, k in enumerate(committee)]},
        "keys": {"national_officer": national.public_hex},
        "shards": [{"id": s["id"], "eligible_voters": s["eligible_voters"]} for s in shards],
        "software": {"name": "chunaviq", "version": __version__},
    }
    nhash = sha256_hex(canonical_json(manifest))
    _write_signed(out / "national" / "manifest.json", national, {"manifest": manifest, "manifest_hash": nhash})

    raws = [k.private_bytes() for k in committee]
    jobs = []
    for s in shards:
        sc = SimConfig(
            voters=s["eligible_voters"],
            constituencies=1,
            candidates_per_constituency=s["candidates"],
            turnout=cfg.turnout,
            trustees=cfg.trustees,
            threshold=cfg.threshold,
            group=cfg.group,
            rsa_bits=cfg.rsa_bits,
            seed=cfg.seed + s["number"],
            inject_attacks=s["number"] == 1,
            workers=1,
            election_id=f"SYN-2026-GE-{s['id']}",
            first_constituency=s["number"],
            first_voter=s["first_voter"],
            constituency_prefix="SYN-PC",
            federation={"national_election_id": cfg.national_id, "national_manifest_hash": nhash, "shard_id": s["id"]},
            trustee_raw_keys=raws,
        )
        jobs.append((str(out / "shards" / s["id"]), asdict(sc)))

    t1 = time.perf_counter()
    with ProcessPoolExecutor(max_workers=cfg.workers, mp_context=mp.get_context("spawn")) as ex:
        summaries = list(ex.map(_run_shard, jobs))
    shard_wall = time.perf_counter() - t1

    index, results, oracle = [], {}, {}
    seats: Counter[str] = Counter()
    totals: Counter[str] = Counter()
    for s, summ in zip(shards, summaries, strict=True):
        rec = out / "shards" / s["id"] / "record"
        first = json.loads((rec / "entries.jsonl").open("rb").readline())
        keys = first["body"]["manifest"]["keys"]
        cps = [json.loads(x) for x in (rec / "checkpoints.jsonl").read_bytes().split(b"\n") if x]
        index.append(
            {
                "shard_id": s["id"],
                "election_id": first["body"]["manifest"]["election_id"],
                "manifest_hash": summ["manifest_hash"],
                "officer_key": keys["officer"],
                "board_key": keys["board"],
                "eligibility_key": keys["eligibility"],
                "final_tree_size": cps[-1]["tree_size"],
                "final_root": cps[-1]["root"],
            }
        )
        res_entry = next(json.loads(x) for x in reversed((rec / "entries.jsonl").read_bytes().split(b"\n")) if x and b'"type":"result"' in x)
        body = res_entry["body"]
        counts = {c["option_id"]: c["votes"] for c in body["counts"]}
        party = {o["id"]: o["party"] for o in first["body"]["manifest"]["constituencies"][0]["options"]}
        results[s["id"]] = {
            "counts": counts,
            "winner": body["winner"],
            "tied": body["tied"],
            "winner_party": party.get(body["winner"]) if body["winner"] else None,
        }
        if body["winner"]:
            seats[party[body["winner"]]] += 1
        for oid, v in counts.items():
            totals["NOTA" if oid == NOTA_ID else party[oid]] += v
        oracle[s["id"]] = json.loads((out / "shards" / s["id"] / "oracle.json").read_text())[s["id"]]

    _write_signed(out / "national" / "shard-index.json", national, {"national_manifest_hash": nhash, "shards": index})
    _write_signed(
        out / "national" / "results.json",
        national,
        {
            "national_manifest_hash": nhash,
            "constituencies": results,
            "seats_by_party": dict(sorted(seats.items())),
            "votes_by_party": dict(sorted(totals.items())),
            "undecided_ties": sorted(k for k, r in results.items() if r["tied"]),
        },
    )
    (out / "oracle.json").write_text(json.dumps(oracle, indent=2, sort_keys=True))
    summary = {
        "config": asdict(cfg),
        "national_manifest_hash": nhash,
        "shards": len(shards),
        "eligible_voters": sum(s["eligible_voters"] for s in shards),
        "ballots": sum(x["ballots_accepted"] for x in summaries),
        "seats_by_party": dict(seats),
        "attacks_shard_1": summaries[0]["attacks"],
        "timings": {
            "shards_wall_s": round(shard_wall, 2),
            "total_s": round(time.perf_counter() - t0, 2),
            "slowest_shard_s": round(max(x["wall_s"] for x in summaries), 2),
        },
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))
    return summary


__all__ = ["FedConfig", "run_federation", "FED_SPEC", "SYN_PARTIES"]
