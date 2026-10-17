"""Dress rehearsal: a real constituency election, run end to end over HTTP, under attack.

    chunaviq rehearse smoke        # minutes, any machine (CI runs this)
    chunaviq rehearse mini-peak    # shard-peak in miniature: 16 options, 2 minutes of load, every attack kind
    chunaviq rehearse shard-peak   # the largest constituency's design rate, as far as this machine allows

What happens, in order, all with the real 2048-bit group and a real clock:

  1. election setup: manifest, trustee HSM key ceremony, synthetic roll
  2. every participating voter verifies identity (Aadhaar or PAN, synthetic) and registers a tag
  3. voter devices pre-encrypt their ballots (and some revotes) -- in a real
     election each device does this itself, so it is not server load
  4. the hardened ballot-intake server starts as its own process
  5. honest voters arrive as a Poisson stream in three phases -- baseline,
     under attack (seven kinds of flood at once), and a surge at 1.5x -- while
     the server's own metrics are sampled every second
  6. polls close; finalization, mixing by three trustees, HSM-gated decryption, result
  7. the independent verifier checks the whole record
  8. everything is written out: configuration, machine, software digest,
     per-request records, per-second server metrics, verification report, and
     a human-readable report -- nothing is summarised away

A full national rehearsal is this, times 543 constituencies, on the real
infrastructure. The scaling argument (shards are independent) is in docs/scale.md;
how to run this on many machines is in docs/dos-and-rehearsal.md.
"""

from __future__ import annotations

import asyncio
import csv
import datetime as dt
import json
import math
import multiprocessing as mp
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .. import __version__
from ..crypto.encoding import to_hex
from ..crypto.group import BACKEND, get_group
from ..crypto.signing import RoleKey
from ..custody import CustodyPolicy
from ..election.administration import Administration, Observer, TrusteeHost
from ..election.ballotbox import BallotBox
from ..election.board import Board
from ..election.client import VoterDevice
from ..election.clock import SystemClock, iso
from ..election.eligibility import EligibilityAuthority
from ..election.identity import IdentityHub
from ..election.manifest import build_manifest, source_digest
from ..election.roll import make_constituencies, make_roll
from ..election.simulate import _winit, _wprepare
from .loadgen import FLOODS, run_phases

ON_TIME_S = 30.0  # "on time": recorded within 30 s of the first attempt
DESIGN_RATE_LARGEST_SEAT = 128.0  # ballots/s: docs/scale/capacity.md, 150 crore electors, 100% turnout, 10% revotes


@dataclass
class Profile:
    name: str
    options: int
    seconds: int
    rate: float | None  # honest ballots/s; None = as close to the design rate as this machine allows
    floods: dict[str, float]
    revote_fraction: float = 0.1
    attackers: int = 20
    botnet: int = 50
    mix_batch: int = 2048
    # leave cores for the load generator, the network thread and the committer, which share this machine
    server_workers: int = field(default_factory=lambda: max(1, (os.cpu_count() or 2) - 3))


PROFILES = {
    "smoke": Profile(
        "smoke",
        options=4,
        seconds=90,
        rate=2.0,
        floods={"junk": 10, "oversize": 2, "unregistered": 10, "bad_proof": 5, "replay": 5, "slowloris": 0.5, "idle_conns": 1},
        mix_batch=256,
    ),
    "mini-peak": Profile(
        "mini-peak",
        options=16,
        seconds=120,
        rate=None,
        floods={"junk": 60, "oversize": 6, "unregistered": 60, "bad_proof": 12, "replay": 30, "slowloris": 1, "idle_conns": 4},
        mix_batch=512,
    ),
    "shard-peak": Profile(
        "shard-peak",
        options=16,
        seconds=600,
        rate=None,
        floods={"junk": 300, "oversize": 30, "unregistered": 300, "bad_proof": 60, "replay": 150, "slowloris": 5, "idle_conns": 20},
    ),
}


def _phases(p: Profile, rate: float) -> list[dict]:
    a, b = round(p.seconds * 0.3), round(p.seconds * 0.4)
    return [
        {"name": "1-baseline", "seconds": a, "rate": rate, "floods": {}},
        {"name": "2-under-attack", "seconds": b, "rate": rate, "floods": p.floods},
        {"name": "3-surge-1.5x", "seconds": p.seconds - a - b, "rate": rate * 1.5, "floods": {k: v / 2 for k, v in p.floods.items()}},
    ]


def _quick_costs(options: int) -> tuple[float, float]:
    from ..crypto.elgamal import PublicKey
    from ..election.ballot import check_ballot, check_link, encrypt_ballot, make_link

    grp = get_group("CHUNAVIQ-2048-256-V1")
    pk = PublicKey(grp, grp.g_pow(grp.rand_scalar()))
    opts = [f"C{i}" for i in range(1, options)] + ["NOTA"]
    t = grp.rand_scalar()
    T = grp.g_pow(t)
    s = time.perf_counter()
    for _ in range(3):
        pb = encrypt_ballot(pk, "m", "E", "X", opts, opts[0], t)
        link = make_link(pk, "m", pb, T)
    enc = (time.perf_counter() - s) / 3
    s = time.perf_counter()
    for _ in range(3):
        check_ballot(pb.ballot, pk=pk, mhash="m", election_id="E", options={"X": opts})
        check_link(pk, "m", pb.ballot, to_hex(T), link)
    return enc, (time.perf_counter() - s) / 3


def _pct(xs: list[float], q: float) -> float | None:
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def run(profile_name: str, out: Path, *, seconds: int | None = None, rate: float | None = None, workers: int | None = None) -> dict:
    p = PROFILES[profile_name]
    if seconds:
        p.seconds = seconds
    if workers:
        p.server_workers = workers
    out = Path(out)
    edir = out / "election"
    (edir / "private").mkdir(parents=True, exist_ok=False)
    stages: dict[str, float] = {}
    t_all = time.perf_counter()
    rng = random.Random(2026)

    # ------------------------------------------------------------ 0. size the run to this machine
    enc_s, ver_s = _quick_costs(p.options)
    capacity = p.server_workers / (ver_s * 1.3)  # 30% for parsing, commit and HTTP overhead
    # the surge phase runs at 1.5x, so keep it under capacity: whatever this machine can sustain, up to the design rate
    honest_rate = rate or p.rate or min(DESIGN_RATE_LARGEST_SEAT, 0.6 * capacity)
    phases = _phases(p, honest_rate)
    ballots = sum(ph["rate"] * ph["seconds"] for ph in phases)
    voters = math.ceil(ballots / (1 + p.revote_fraction) * 1.05) + p.attackers
    pregen_workers = max(1, (os.cpu_count() or 2))
    # The window must be fixed before ballots can be encrypted (it is part of the manifest they are bound to),
    # so it is sized from measured costs with a margin; the load phase refuses to start if it would not fit.
    est_setup = voters * 0.006 + ballots * enc_s * 1.5 / pregen_workers + 20
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    opens, closes = now - dt.timedelta(seconds=5), now + dt.timedelta(seconds=est_setup + p.seconds * 1.1 + 60)

    # ------------------------------------------------------------ 1. election setup
    s = time.perf_counter()
    grp = get_group("CHUNAVIQ-2048-256-V1")
    clock = SystemClock()
    officer, operator = RoleKey("officer"), RoleKey("board")
    (edir / "private" / "board.key").write_bytes(operator.private_bytes())  # rehearsal only: the server process signs checkpoints
    hosts = [TrusteeHost(i + 1, grp, 3) for i in range(5)]
    observers = [Observer() for _ in range(3)]
    cons = make_constituencies(1, p.options - 1, [voters], seed=7, prefix="SYN-PC")
    roll = make_roll(cons, seed=7)
    hub = IdentityHub.synthetic(roll)
    eid = f"SYN-REHEARSAL-{profile_name.upper()}"
    elig = EligibilityAuthority(edir / "private" / "eligibility.db", eid, [cons[0].id], clock, grp, hub)
    elig.load_roll(roll)
    board = Board(edir / "record", eid, operator, clock, durable=True)
    admin = Administration(board, officer, grp, hosts, clock, observers)
    manifest = build_manifest(
        election_id=eid,
        title=f"Synthetic dress rehearsal ({profile_name})",
        group_name=grp.name,
        constituencies=cons,
        opens_at=iso(opens),
        closes_at=iso(closes),
        threshold=3,
        trustee_keys=[h.key.public_hex for h in hosts],
        officer_key=officer.public_hex,
        board_key=operator.public_hex,
        eligibility_key=elig.key.public_hex,
        software_version=__version__,
        mix_batch=p.mix_batch,
    )
    mhash = admin.publish_manifest(manifest)
    for h in hosts:
        h.install(CustodyPolicy([eid], [officer.public_hex], h.operator_keys, 2, [o.key.public_hex for o in observers], 2, 6 * voters + 100))
    pk = admin.key_ceremony()
    admin.ready()
    elig.set_accepting(True)
    stages["setup_s"] = time.perf_counter() - s

    # ------------------------------------------------------------ 2. identity + registration
    s = time.perf_counter()
    opts = [o.id for o in cons[0].candidates]
    devices, methods = [], Counter()
    for v in roll:
        d = VoterDevice(v, eid, mhash, pk, opts)
        m = "pan" if (v.pan_ref and rng.random() < 0.2) else ("aadhaar-face" if rng.random() < 0.25 else "aadhaar-otp")
        d.register(elig, m)
        methods[m] += 1
        devices.append(d)
    attackers, honest = devices[: p.attackers], devices[p.attackers :]
    stages["registration_s"] = time.perf_counter() - s

    # ------------------------------------------------------------ 3. devices pre-encrypt ballots
    s = time.perf_counter()
    n_first = math.ceil(ballots / (1 + p.revote_fraction))
    order = list(range(min(n_first, len(honest))))
    revoters = rng.sample(order, min(len(order), int(ballots) - len(order))) if ballots > len(order) else []
    jobs = [(cons[0].id, rng.choice(opts), to_hex(honest[i].t), False) for i in order]
    jobs += [(cons[0].id, rng.choice(opts), to_hex(honest[i].t), False) for i in revoters]
    clients = [f"voter-{i}" for i in order] + [f"voter-{i}" for i in revoters]
    sub_path = edir / "private" / "submissions.jsonl"
    init = (grp.name, to_hex(pk.K), mhash, eid, {cons[0].id: opts})
    with mp.get_context("spawn").Pool(pregen_workers, initializer=_winit, initargs=init) as pool, open(sub_path, "w") as f:
        for (sub, _), client in zip(pool.imap(_wprepare, jobs, chunksize=16), clients, strict=True):
            f.write(json.dumps({"client": client, "body": sub}, separators=(",", ":")) + "\n")
    _winit(*init)
    bad = []
    for d in attackers:  # registered voters who abuse their registration: valid tags, broken proofs
        sub, _ = _wprepare((cons[0].id, opts[0], to_hex(d.t), False))
        sel = sub["ballot"]["selections"][0]["proof"]
        sel["v0"] = format((int(sel["v0"], 16) + 1) % grp.q, "x")
        bad.append(json.dumps(sub).encode())
    stranger, _ = _wprepare((cons[0].id, opts[0], to_hex(grp.rand_scalar()), False))
    attack_ctx = {"bad_proof": bad, "unregistered": json.dumps(stranger).encode(), "botnet": p.botnet}
    stages["device_encryption_s"] = time.perf_counter() - s

    # ------------------------------------------------------------ 4. open and start the server
    if dt.datetime.now(dt.UTC) + dt.timedelta(seconds=p.seconds * 1.1 + 30) > closes:
        raise RuntimeError("setup took longer than estimated; the load would run past the published closing time. Rerun.")
    admin.open()
    port_file, metrics_file = out / "server.port", out / "server-metrics.jsonl"
    server = subprocess.Popen(  # noqa: S603 - our own module
        [
            sys.executable,
            "-m",
            "chunaviq.service.sequencer",
            "--election",
            str(edir),
            "--port",
            "0",
            "--workers",
            str(p.server_workers),
            "--metrics",
            str(metrics_file),
            "--ready-file",
            str(port_file),
        ],
        stdout=open(out / "server.log", "w"),  # noqa: SIM115
        stderr=subprocess.STDOUT,
    )
    deadline = time.monotonic() + 120
    while not port_file.exists():
        if server.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError("server failed to start; see server.log")
        time.sleep(0.2)
    port = int(port_file.read_text())

    # ------------------------------------------------------------ 5. load + attacks
    def honest_iter():
        with open(sub_path, "rb") as f:
            for line in f:
                o = json.loads(line)
                yield json.dumps(o["body"], separators=(",", ":")).encode(), o["client"]

    s = time.perf_counter()
    res = asyncio.run(run_phases("127.0.0.1", port, honest_iter(), phases, attack_ctx))
    stages["load_s"] = time.perf_counter() - s
    server.terminate()
    server.wait(timeout=600)

    # ------------------------------------------------------------ 6. close and count
    wait = (closes - dt.datetime.now(dt.UTC)).total_seconds()
    if wait > 0:
        time.sleep(wait + 1)
    s = time.perf_counter()
    board = Board(edir / "record", eid, operator, clock, durable=True)  # reload what the server wrote
    admin.board = board
    snaps = [json.loads(x) for x in metrics_file.read_text().splitlines() if x]
    server_outcomes = snaps[-1]["outcomes"] if snaps else {}
    rejections = {k: v for k, v in server_outcomes.items() if k not in ("ACCEPTED", "VERIFIED_EXPENSIVE", "BATCHES", "IDEMPOTENT_REPLAY")}
    admin.close(rejections)
    elig.set_accepting(False)
    admin.publish_registration(elig.registration_entries(), {c: set(elig.valid_tags(c)) for c in elig.constituencies})
    box = BallotBox(edir / "private" / "ballotbox.db", board, manifest, mhash, pk, clock, elig.known_tag)
    fstats = box.finalize(admin.valid_tags, workers=pregen_workers, group_name=grp.name)
    stages["finalization_s"] = time.perf_counter() - s
    s = time.perf_counter()
    for h in hosts[:1]:
        h.available = False  # one trustee is unavailable on counting day
    results = admin.tally(workers=pregen_workers)
    admin.publish()
    stages["mix_and_tally_s"] = time.perf_counter() - s
    (edir / "hsm").mkdir(exist_ok=True)
    for h in hosts:
        (edir / "hsm" / f"trustee-{h.index}.json").write_text(
            json.dumps({"attestation_key": h.applet.attestation_key(), "log": h.applet.audit_log()}, indent=1, sort_keys=True)
        )

    # ------------------------------------------------------------ 7. independent verification
    from chunaviq_verify import verify_record

    s = time.perf_counter()
    rep = verify_record(edir / "record", expect_manifest_hash=mhash, expect_source_digest=source_digest(), workers=pregen_workers)
    stages["independent_verification_s"] = time.perf_counter() - s
    vd = rep.to_dict()
    (out / "verify.json").write_text(json.dumps(vd, indent=2, sort_keys=True))
    stages["total_s"] = time.perf_counter() - t_all

    # ------------------------------------------------------------ 8. transparent outputs
    summary = _summarise(p, honest_rate, capacity, ver_s, enc_s, phases, res, snaps, board, fstats, results, vd, stages, methods, voters, mhash)
    _write_outputs(out, p, res, snaps, summary)
    return summary


def _summarise(p, honest_rate, capacity, ver_s, enc_s, phases, res, snaps, board, fstats, results, vd, stages, methods, voters, mhash) -> dict:
    by_phase: dict[str, dict] = {}
    for ph in phases:
        recs = [r for r in res.records if r.phase == ph["name"]]
        hon = [r for r in recs if r.kind == "honest"]
        ok = [r for r in hon if r.status == 200]
        lat = [r.t_done - (res.started + r.t_sched) for r in ok]
        attacks = defaultdict(Counter)
        for r in recs:
            if r.kind != "honest":
                attacks[r.kind][f"{r.status} {r.code}"] += 1
        by_phase[ph["name"]] = {
            "seconds": ph["seconds"],
            "honest_rate_target_per_s": round(ph["rate"], 2),
            "honest_sent": len(hon),
            "honest_recorded": len(ok),
            "honest_recorded_pct": round(100 * len(ok) / len(hon), 3) if hon else None,
            "honest_recorded_within_30s": sum(1 for x in lat if x <= ON_TIME_S),
            "honest_recorded_within_30s_pct": round(100 * sum(1 for x in lat if x <= ON_TIME_S) / len(hon), 3) if hon else None,
            "honest_failed_codes": dict(Counter(f"{r.status} {r.code}" for r in hon if r.status != 200)),
            "latency_s": {"p50": _pct(lat, 0.5), "p95": _pct(lat, 0.95), "p99": _pct(lat, 0.99), "max": max(lat) if lat else None},
            "mean_attempts": round(statistics.mean(r.attempts for r in hon), 3) if hon else None,
            "attack_requests": {k: sum(v.values()) for k, v in attacks.items()},
            "attack_outcomes": {k: dict(v) for k, v in attacks.items()},
        }
    recorded = {r.tracking_code for r in res.records if r.kind == "honest" and r.status == 200}
    on_board = set()
    for e in board.iter_entries("ballot"):
        on_board.add(e["body"]["tracking_code"])
    last = snaps[-1] if snaps else {"outcomes": {}, "http": {}}
    return {
        "profile": p.name,
        "software": {"version": __version__, "source_digest": source_digest()},
        "machine": {
            "cores": os.cpu_count(),
            "cpu": platform.processor() or platform.machine(),
            "python": platform.python_version(),
            "backend": BACKEND,
            "os": platform.platform(),
        },
        "config": {**asdict(p), "honest_rate_per_s": honest_rate},
        "design_rate_largest_seat_per_s": DESIGN_RATE_LARGEST_SEAT,
        "measured_verify_s_per_ballot": ver_s,
        "measured_device_encrypt_s": enc_s,
        "server_capacity_estimate_per_s": capacity,
        "fraction_of_design_rate": round(honest_rate / DESIGN_RATE_LARGEST_SEAT, 4),
        "cores_for_design_rate_at_this_cost": round(DESIGN_RATE_LARGEST_SEAT * ver_s, 1),
        "voters_registered": voters,
        "identity_methods": dict(methods),
        "phases": by_phase,
        "every_receipt_is_on_the_board": recorded <= on_board,
        "ballots_on_board": len(on_board),
        "server_final_outcomes": last["outcomes"],
        "server_http_defences": last["http"],
        "expensive_checks_run": last["outcomes"].get("VERIFIED_EXPENSIVE", 0),
        "finalization": fstats,
        "results": results,
        "verification": {
            "status": vd["status"],
            "failures": vd["failures"],
            "warnings": vd["warnings"],
            "failed": [c["id"] for c in vd["checks"] if c["status"] == "FAIL"],
        },
        "manifest_hash": mhash,
        "stage_seconds": {k: round(v, 1) for k, v in stages.items()},
    }


def _write_outputs(out: Path, p: Profile, res, snaps, summary: dict) -> None:
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str))
    with open(out / "requests.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["kind", "phase", "scheduled_s", "done_s", "status", "code", "attempts"])
        for r in res.records:
            w.writerow([r.kind, r.phase, f"{r.t_sched:.4f}", f"{r.t_done - res.started:.4f}", r.status, r.code, r.attempts])
    okeys = sorted({k for sn in snaps for k in sn["outcomes"]})
    hkeys = sorted({k for sn in snaps for k in sn["http"]})
    with open(out / "server-metrics.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t", "ballots", "inflight", "connections", *okeys, *[f"http_{k}" for k in hkeys]])
        t0 = snaps[0]["t"] if snaps else 0
        for sn in snaps:
            w.writerow(
                [
                    f"{sn['t'] - t0:.1f}",
                    sn["ballots"],
                    sn["inflight"],
                    sn["connections"],
                    *[sn["outcomes"].get(k, 0) for k in okeys],
                    *[sn["http"].get(k, 0) for k in hkeys],
                ]
            )
    L = [
        f"# Dress rehearsal: {p.name}",
        "",
        f"**Verification: {summary['verification']['status']}** "
        f"({summary['verification']['failures']} failures, {summary['verification']['warnings']} warnings). "
        f"Every receipt handed to an honest voter is on the board: **{summary['every_receipt_is_on_the_board']}**.",
        "",
        f"Machine: {summary['machine']['cores']} cores, {summary['machine']['os']}, Python {summary['machine']['python']} ({summary['machine']['backend']}). "
        f"Software {summary['software']['version']}, source digest `{summary['software']['source_digest']}`.",
        "",
        f"Honest rate {summary['config']['honest_rate_per_s']:.1f} ballots/s = "
        f"{100 * summary['fraction_of_design_rate']:.1f}% of the largest constituency's design rate "
        f"({summary['design_rate_largest_seat_per_s']:.0f}/s). Verifying one {p.options}-option ballot costs "
        f"{summary['measured_verify_s_per_ballot'] * 1000:.0f} ms of one core here, "
        f"so the full design rate needs about {summary['cores_for_design_rate_at_this_cost']:.0f} cores at this cost.",
        "",
        "| Phase | Honest sent | Recorded in the end | Recorded within 30 s | p50 / p95 / p99 latency | Mean attempts | Attack requests |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, ph in summary["phases"].items():
        lat = ph["latency_s"]
        fmt = lambda x: "-" if x is None else f"{x:.2f}s"  # noqa: E731
        att_n = sum(ph["attack_requests"].values())
        L.append(
            f"| {name} | {ph['honest_sent']} | {ph['honest_recorded']} ({ph['honest_recorded_pct']}%) | "
            f"{ph['honest_recorded_within_30s']} ({ph['honest_recorded_within_30s_pct']}%) | "
            f"{fmt(lat['p50'])} / {fmt(lat['p95'])} / {fmt(lat['p99'])} | {ph['mean_attempts']} | {att_n} |"
        )
    L += ["", "## What the attacks got", ""]
    att: dict[str, Counter] = defaultdict(Counter)
    for ph in summary["phases"].values():
        for k, v in ph["attack_outcomes"].items():
            att[k].update(v)
    L += ["| Attack | Outcomes (HTTP status, code: count) |", "|---|---|"]
    for k in FLOODS:
        if k in att:
            L.append(f"| {k} | " + ", ".join(f"{c}: {n}" for c, n in att[k].most_common()) + " |")
    L += [
        "",
        f"Expensive proof checks actually run by the server: {summary['expensive_checks_run']} "
        "(honest ballots plus at most one per attacker tag per interval).",
        "",
        "## Stages",
        "",
        "| Stage | Seconds |",
        "|---|---|",
        *[f"| {k} | {v} |" for k, v in summary["stage_seconds"].items()],
        "",
        "Files: `summary.json` (everything above), `requests.csv` (every request), `server-metrics.csv` (server state every second), "
        "`verify.json` (independent verifier), `election/record/` (the public record), `election/hsm/` (trustee HSM logs).",
    ]
    (out / "report.md").write_text("\n".join(L) + "\n")


__all__ = ["run", "PROFILES", "Profile"]
