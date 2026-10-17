"""Independent verification of a national election federated by constituency.

    python -m chunaviq_verify.federation DIR [--expect-national-hash H] [--json OUT]

Verifies the signed national manifest and shard index, runs the full single-
election verifier on every constituency record in parallel, checks that every
shard is bound to this national election (same window, group and trustee
committee; listed keys and final roots), and recomputes the national result.
A missing, extra or unverifiable shard fails the whole election.
Shares no code with the `chunaviq` package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from .verifier import Report, verify_record
from .vmath import cjson, ed_ok


def _load_signed(path: Path) -> dict:
    line = path.read_bytes().rstrip(b"\n")
    body = json.loads(line)
    if cjson(body) != line:
        raise ValueError(f"{path.name} is not canonical JSON")
    return body


def _verify_shard(args: tuple[str, str]) -> dict:
    rec, pin = args
    rep = verify_record(rec, expect_manifest_hash=pin, workers=1)
    d = rep.to_dict()
    return {"status": d["status"], "failed": [c["id"] for c in d["checks"] if c["status"] == "FAIL"], "results": d["results"], "facts": d["facts"]}


def _national_key(d: Path, nhash: str, nkey: str, members: list[dict], k: int) -> tuple[bool, str | None, str]:
    """National ceremony file: signed, bound to the manifest, by the declared committee; returns its joint key."""
    cer = _load_signed(d / "national" / "ceremony.json")
    if not ed_ok(cer, nkey, "national-officer") or cer["national_manifest_hash"] != nhash:
        return False, None, "ceremony file unsigned or not bound to this manifest"
    comm = [e["body"] for e in cer["entries"] if e["type"] == "trustee_commitment"]
    if [b["commitment"]["index"] for b in comm] != [m["index"] for m in members]:
        return False, None, "ceremony commitments do not match the committee"
    for b, m in zip(comm, members, strict=True):
        if not ed_ok(b, m["public_key"], m["role"]) or len(b["commitment"]["commitments"]) != k:
            return False, None, f"commitment of {m['role']} invalid"
    return True, cer["joint_public_key"], ""


def verify_federation(directory: str | Path, *, expect_national_hash: str | None = None, workers: int | None = None) -> Report:
    d = Path(directory)
    rep = Report()
    try:
        _run(d, rep, expect_national_hash, workers or os.cpu_count() or 1)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as e:
        rep.add("federation.parse", "National files are present and well-formed", False, f"{type(e).__name__}: {e}")
    return rep


def _run(d: Path, rep: Report, pin: str | None, workers: int) -> None:
    mb = _load_signed(d / "national" / "manifest.json")
    man = mb["manifest"]
    nhash = hashlib.sha256(cjson(man)).hexdigest()
    nkey = man["keys"]["national_officer"]
    rep.add("national.spec", "National manifest uses the federation format", man.get("spec_version") == "chunaviq-federation/2")
    rep.add("national.hash", "National manifest hash matches its content", nhash == mb["manifest_hash"], nhash)
    rep.add("national.signature", "National manifest signed by the national officer", ed_ok(mb, nkey, "national-officer"))
    if pin:
        rep.add("national.pinned", "National manifest hash equals the independently obtained value", pin == nhash)
    else:
        rep.add("national.pinned", "National manifest hash pinned to an out-of-band value", None, "Not pinned; pass --expect-national-hash.")
    rep.facts.update(election_id=man["election_id"], national_manifest_hash=nhash, shards=len(man["shards"]))

    idx = _load_signed(d / "national" / "shard-index.json")
    rep.add(
        "national.index_signature",
        "Shard index signed by the national officer and bound to this manifest",
        ed_ok(idx, nkey, "national-officer") and idx["national_manifest_hash"] == nhash,
    )
    declared = [s["id"] for s in man["shards"]]
    listed = [s["shard_id"] for s in idx["shards"]]
    present = sorted(p.name for p in (d / "shards").iterdir() if p.is_dir())
    rep.add(
        "national.coverage",
        "Every declared constituency has exactly one indexed, published shard",
        sorted(declared) == sorted(listed) == present and len(set(declared)) == len(declared),
        f"declared {len(declared)}, indexed {len(listed)}, present {len(present)}",
    )

    from .groups import APPROVED_GROUPS

    members = man["trustees"]["members"]
    cer_ok, nat_K, why = _national_key(d, nhash, nkey, members, man["trustees"]["threshold"])
    if cer_ok:
        gp = APPROVED_GROUPS.get(man["group"])
        from .vmath import hx

        K = 1
        cer = _load_signed(d / "national" / "ceremony.json")
        for e in cer["entries"]:
            if e["type"] == "trustee_commitment":
                K = K * hx(e["body"]["commitment"]["commitments"][0]) % gp["p"]
        cer_ok = format(K, "x") == nat_K
        why = why or ("" if cer_ok else "published joint key is not the product of the commitments")
    rep.add("national.key", "One national key ceremony by the declared trustee committee; joint key = product of commitments", cer_ok, why)
    by_id = {s["shard_id"]: s for s in idx["shards"]}
    eligible = {s["id"]: s["eligible_voters"] for s in man["shards"]}
    officers = {s["id"]: s["officer_key"] for s in man["shards"]}
    committee = [(m["index"], m["role"], m["public_key"]) for m in man["trustees"]["members"]]
    jobs = [(str(d / "shards" / sid / "record"), by_id[sid]["manifest_hash"]) for sid in declared if sid in by_id and sid in present]
    with ProcessPoolExecutor(max_workers=workers, mp_context=mp.get_context("spawn")) as ex:
        outcomes = dict(zip([j[0] for j in jobs], ex.map(_verify_shard, jobs, chunksize=1), strict=True))

    bad_verify, bad_bind, totals, seats, winners = [], [], Counter(), Counter(), {}
    for sid in declared:
        if sid not in by_id or sid not in present:
            continue
        rec = d / "shards" / sid / "record"
        o = outcomes[str(rec)]
        if o["status"] != "VERIFIED":
            bad_verify.append(f"{sid}: {', '.join(o['failed'])}")
            continue
        first = json.loads((rec / "entries.jsonl").open("rb").readline())
        sm = first["body"]["manifest"]
        ix = by_id[sid]
        cps = [json.loads(x) for x in (rec / "checkpoints.jsonl").read_bytes().split(b"\n") if x]
        conds = {
            "federation": sm.get("federation") == {"national_election_id": man["election_id"], "national_manifest_hash": nhash, "shard_id": sid},
            "constituency": [c["id"] for c in sm["constituencies"]] == [sid] and sm["constituencies"][0]["eligible_voters"] == eligible[sid],
            "window": sm["window"] == man["window"],
            "group": sm["group"] == man["group"],
            "committee": sm["trustees"]["threshold"] == man["trustees"]["threshold"]
            and [(m["index"], m["role"], m["public_key"]) for m in sm["trustees"]["members"]] == committee,
            "keys": (sm["keys"]["officer"], sm["keys"]["board"], sm["keys"]["eligibility"]) == (ix["officer_key"], ix["board_key"], ix["eligibility_key"])
            and sm["keys"]["officer"] == officers[sid],
            "national_key": o["facts"].get("joint_key") == nat_K,
            "mixing": sm["mixing"] == man["mixing"],
            "final_root": bool(cps) and cps[-1]["root"] == ix["final_root"] and cps[-1]["tree_size"] == ix["final_tree_size"],
        }
        if not all(conds.values()):
            bad_bind.append(f"{sid}: {[k for k, v in conds.items() if not v]}")
            continue
        r = o["results"][sid]
        party = {opt["id"]: opt["party"] for opt in sm["constituencies"][0]["options"]}
        winners[sid] = r["winner"]
        if r["winner"]:
            seats[party[r["winner"]]] += 1
        for oid, v in r["counts"].items():
            totals["NOTA" if oid == "NOTA" else party[oid]] += v
        rep.results[sid] = {"counts": r["counts"], "winner": r["winner"], "tied": r["tied"], "ballots": r["ballots"]}

    rep.add(
        "shards.verified",
        "Every constituency record passes full independent verification",
        not bad_verify,
        "; ".join(bad_verify[:5]) or f"{len(outcomes)} shards",
    )
    rep.add(
        "shards.bound",
        "Every shard is bound to this national election (window, group, committee, national key, mixing rules, keys, final root)",
        not bad_bind,
        "; ".join(bad_bind[:5]),
    )

    res = _load_signed(d / "national" / "results.json")
    posted_ok = ed_ok(res, nkey, "national-officer") and res["national_manifest_hash"] == nhash
    same = (
        {k: v["winner"] for k, v in res["constituencies"].items()} == winners
        and res["seats_by_party"] == dict(sorted(seats.items()))
        and res["votes_by_party"] == dict(sorted(totals.items()))
    )
    rep.add(
        "national.results", "Published national result equals the sum of verified constituency results", posted_ok and same and not bad_verify and not bad_bind
    )
    rep.facts.update(seats_by_party=dict(seats), votes_by_party=dict(totals), ballots=sum(v["ballots"] for v in rep.results.values()))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="chunaviq-verify-federation")
    ap.add_argument("directory")
    ap.add_argument("--expect-national-hash")
    ap.add_argument("--json")
    ap.add_argument("--workers", type=int)
    a = ap.parse_args(argv)
    rep = verify_federation(a.directory, expect_national_hash=a.expect_national_hash, workers=a.workers)
    d = rep.to_dict()
    for c in d["checks"]:
        print(f"[{c['status']:4}] {c['id']:28} {c['title']}" + (f"\n         {c['detail']}" if c["detail"] and c["status"] != "PASS" else ""))
    print(
        f"\n{d['status']}  ({d['failures']} failures, {d['warnings']} warnings)  ballots {d['facts'].get('ballots')}  seats {d['facts'].get('seats_by_party')}"
    )
    if a.json:
        Path(a.json).write_text(json.dumps(d, indent=2, sort_keys=True))
    return 0 if rep.verified else 1


if __name__ == "__main__":
    sys.exit(main())
