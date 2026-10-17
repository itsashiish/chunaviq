"""National-scale election as a federation of constituency shards.

Why this shape: every registration tag is bound to one constituency (it is
registered there and every ballot proof is bound to it), so "which ballot of
this voter is the last?" never needs to look outside the voter's own
constituency. Each constituency can therefore run
as an independent election -- its own sequencer, ballot box, public record and
tally -- with no cross-shard coordination on the voting path. National scale
is reached by adding shards, not by making one log faster.

    national/manifest.json      signed by the national officer: window, group,
                                trustee committee, list of constituencies
    national/shard-index.json   signed: each shard's manifest hash, role keys
                                and final checkpoint root
    national/results.json       signed: per-constituency winners, seats by
                                party, national vote totals
    shards/<PC>/record/         a complete chunaviq-record/2 per constituency

The trustee committee and its key are national: ONE key ceremony, held in the
trustees' HSMs and bound to the national manifest, produces the key every
constituency encrypts under. Each trustee's HSM therefore holds one share, not
one per constituency (separate keys would add nothing: the same five people
would hold them all). Every shard record carries a copy of the national
ceremony so it can be verified on its own; the federation verifier checks all
shards use the same national key. Each constituency's officer stands in for
its Returning Officer.

    national/ceremony.json      signed by the national officer: the trustees'
                                commitments and acknowledgements, joint key
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
from ..crypto.encoding import canonical_json, sha256_hex, to_hex
from ..crypto.group import get_group
from ..crypto.signing import RoleKey
from ..crypto.threshold import joint_public_key
from ..custody import CustodyPolicy, hsm_kek
from .administration import Observer, TrusteeHost, ceremony_entries, run_hsm_ceremony
from .manifest import NOTA_ID, SYNTHETIC_NOTICE
from .roll import SYN_PARTIES
from .simulate import SimConfig, run

FED_SPEC = "chunaviq-federation/2"
OPENS_AT = "2026-11-02T01:30:00Z"  # matches simulate.run's fixed synthetic window (seven days)
CLOSES_AT = "2026-11-08T12:30:00Z"


@dataclass
class FedConfig:
    shards: int = 24
    voters_per_shard: int = 300
    candidates_min: int = 3
    candidates_max: int = 8
    turnout: float = 0.66
    trustees: int = 5
    threshold: int = 3
    min_mixers: int = 3
    mix_batch: int = 2048
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
    grp = get_group(cfg.group)
    hosts = [TrusteeHost(i + 1, grp, cfg.threshold) for i in range(cfg.trustees)]
    observers = [Observer() for _ in range(3)]

    shards = []
    first_voter = 1
    for i in range(1, cfg.shards + 1):
        eligible = max(20, int(cfg.voters_per_shard * rng.uniform(0.7, 1.3)))
        cands = rng.randint(cfg.candidates_min, cfg.candidates_max)
        shards.append(
            {
                "id": f"SYN-PC-{i:03d}",
                "number": i,
                "eligible_voters": eligible,
                "candidates": cands,
                "first_voter": first_voter,
                "officer": RoleKey("officer"),
                "election_id": f"SYN-2026-GE-SYN-PC-{i:03d}",
            }
        )
        first_voter += eligible

    manifest = {
        "spec_version": FED_SPEC,
        "election_id": cfg.national_id,
        "title": "Synthetic national general election (research simulation)",
        "notice": SYNTHETIC_NOTICE,
        "voting_rule": "FPTP-single-member per constituency; NOTA counted but cannot win; only a voter's last ballot under a valid registration counts",
        "group": cfg.group,
        "window": {"opens_at": OPENS_AT, "closes_at": CLOSES_AT},
        "trustees": {"threshold": cfg.threshold, "members": [{"index": h.index, "role": h.key.role, "public_key": h.key.public_hex} for h in hosts]},
        "mixing": {"min_mixers": cfg.min_mixers, "batch_size": cfg.mix_batch},
        "keys": {"national_officer": national.public_hex},
        "shards": [{"id": s["id"], "eligible_voters": s["eligible_voters"], "officer_key": s["officer"].public_hex} for s in shards],
        "software": {"name": "chunaviq", "version": __version__},
    }
    nhash = sha256_hex(canonical_json(manifest))
    _write_signed(out / "national" / "manifest.json", national, {"manifest": manifest, "manifest_hash": nhash})

    # ONE national key ceremony, inside the trustees' HSMs, bound to the national manifest.
    budget = 4 * cfg.shards * int(cfg.voters_per_shard * 1.3) + 64 * cfg.shards
    for h in hosts:
        h.install(
            CustodyPolicy(
                [s["election_id"] for s in shards],
                [s["officer"].public_hex for s in shards],
                h.operator_keys,
                2,
                [o.key.public_hex for o in observers],
                2,
                budget,
            )
        )
    comms = run_hsm_ceremony(hosts, nhash, cfg.threshold)
    entries = ceremony_entries(hosts, comms)
    K = joint_public_key(grp, comms)
    _write_signed(
        out / "national" / "ceremony.json",
        national,
        {"national_manifest_hash": nhash, "entries": [{"type": t, "body": b} for t, b in entries], "joint_public_key": to_hex(K)},
    )
    keks = [hsm_kek() for _ in hosts]
    national_material = {  # simulation only: each shard process gets a copy of every trustee's sealed HSM state
        "entries": entries,
        "commitments": [c.to_dict() for c in comms],
        "sealed": [h.applet.seal(kk).hex() for h, kk in zip(hosts, keks, strict=True)],  # type: ignore[union-attr]
        "kek": [kk.hex() for kk in keks],
        "operators": [[o.private_bytes().hex() for o in h.operators] for h in hosts],
        "observers": [o.key.private_bytes().hex() for o in observers],
    }

    raws = [h.key.private_bytes() for h in hosts]
    jobs = []
    for s in shards:
        sc = SimConfig(
            voters=s["eligible_voters"],
            constituencies=1,
            candidates_per_constituency=s["candidates"],
            turnout=cfg.turnout,
            trustees=cfg.trustees,
            threshold=cfg.threshold,
            min_mixers=cfg.min_mixers,
            mix_batch=cfg.mix_batch,
            group=cfg.group,
            seed=cfg.seed + s["number"],
            inject_attacks=s["number"] == 1,
            workers=1,
            election_id=s["election_id"],
            first_constituency=s["number"],
            first_voter=s["first_voter"],
            constituency_prefix="SYN-PC",
            federation={"national_election_id": cfg.national_id, "national_manifest_hash": nhash, "shard_id": s["id"]},
            officer_raw_key=s["officer"].private_bytes(),
            trustee_raw_keys=raws,
            national=national_material,
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
        "national_joint_key": to_hex(K),
        "national_manifest_hash": nhash,
        "shards": len(shards),
        "eligible_voters": sum(s["eligible_voters"] for s in shards),
        "ballots": sum(x["ballots_accepted"] for x in summaries),
        "counted": sum(x["finalization"]["final"] for x in summaries),
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
