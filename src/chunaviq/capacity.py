"""Measure unit costs on this machine and model a national election (protocol v2).

    chunaviq capacity            -> docs/scale/capacity.md + docs/scale/capacity.json

Nothing here assumes a cost: every per-operation number is measured, and every
modelling assumption (voting hours, peaks, headroom, candidates per seat,
revote rate) is named in ASSUMPTIONS and printed in the report. Change an
assumption, rerun.

Protocol v2 adds work after polls close -- finalization (one OR-proof per
ballot), mixing (each of at least three trustees shuffles every ballot's
tag/flag pair with a proof), and decryption of mixed flags and tags -- and the
independent re-verification of all of it. The model counts all of it.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import os
import platform
import secrets
import statistics
import tempfile
import time
from pathlib import Path

from .crypto import sigma
from .crypto.elgamal import Ciphertext, PublicKey, add, dlog_bounded
from .crypto.encoding import canonical_json, to_hex
from .crypto.group import BACKEND, get_group
from .crypto.merkle import MerkleTree
from .crypto.shuffle import generators, shuffle_and_prove, verify_shuffle
from .crypto.signing import RoleKey
from .crypto.threshold import public_share, run_ceremony, verify_decryption_share
from .election import ballotbox as bb
from .election.ballot import check_ballot, check_link, encrypt_ballot, fast_pows, make_link
from .election.board import Board
from .election.clock import FakeClock, iso

ASSUMPTIONS = {
    "electors": {"100 crore": 1_000_000_000, "150 crore": 1_500_000_000},
    "turnout": {"65% (2024-like)": 0.65, "100% (stress)": 1.0},
    "days": 7,
    "voting_hours_per_day": 16,  # 06:00-22:00 IST; overnight traffic treated as zero
    "peak_hour_over_mean": 2.0,  # busiest hour vs mean of voting hours
    "final_day_surge": 2.0,  # last-day rush
    "headroom": 2.0,  # capacity kept spare during the worst hour
    "revote_overhead": 0.10,  # extra ballots from revotes and re-registrations, as a fraction of voters
    "options_typical": 16,  # about 15 candidates + NOTA per seat (2024 averaged ~15 candidates per seat)
    "options_worst": 50,
    "mixers": 3,
    "threshold": 3,
    "constituencies": 543,
    "largest_constituency_2024": 3_780_000,  # Malkajgiri, 2024
    "electors_2024": 968_000_000,
    "replicas": 3,
    "post_close_cores": 2_000,
}


def _timeit(fn, n: int) -> float:
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t)
    return statistics.median(samples)


def _entry_bytes(typ: str, body: dict) -> int:
    return len(canonical_json({"seq": 10**9, "type": typ, "time_bucket": "2026-11-02T01", "body": body})) + 1


def measure(options: tuple[int, ...] = (4, 16)) -> dict:
    grp = get_group("CHUNAVIQ-2048-256-V1")
    m: dict = {"backend": BACKEND, "cpu": platform.processor() or platform.machine(), "cores": os.cpu_count(), "python": platform.python_version()}
    trustees, comms = run_ceremony(grp, 5, 3, "bench")
    K = grp.mul(*(tc.commitments[0] for tc in comms))
    pk = PublicKey(grp, K)
    mh, eid, cons = "bench-mh", "BENCH", "SYN-PC-001"
    t = grp.rand_scalar()
    T = grp.g_pow(t)
    bb._finit(grp.name, to_hex(K), mh)
    per = {}
    for n in options:
        opts = [f"C{i}" for i in range(1, n)] + ["NOTA"]

        def device(opts=opts):
            pb = encrypt_ballot(pk, mh, eid, cons, opts, opts[0], t)
            return pb, make_link(pk, mh, pb, T)

        enc_t = _timeit(device, 6)
        pb, link = device()
        ballot = pb.ballot

        def server(opts=opts, ballot=ballot, link=link):
            check_ballot(ballot, pk=pk, mhash=mh, election_id=eid, options={cons: opts})
            check_link(pk, mh, ballot, to_hex(T), link)

        ver_t = _timeit(server, 6)
        votes = [(int(s["ciphertext"]["alpha"], 16), int(s["ciphertext"]["beta"], 16)) for s in ballot["selections"]]
        job = (1, "tc", cons, votes, 1)
        fin_t = _timeit(lambda job=job: bb._finalize_one(job), 6)
        item, _ = bb._finalize_one(job)
        F = (int(item["flag"]["alpha"], 16), int(item["flag"]["beta"], 16))
        masked = [(int(x["alpha"], 16), int(x["beta"], 16)) for x in item["masked"]]
        br = sigma.finalize_branches(grp, K, F, votes, masked)
        finv_t = _timeit(lambda br=br, item=item: sigma.verify_or(grp, br, item["proof"], "finalize", bb.finalize_context(mh, cons, "tc"), fast_pows(pk)), 6)
        per[n] = {
            "encrypt_s": enc_t,
            "verify_s": ver_t,
            "finalize_s": fin_t,
            "finalize_verify_s": finv_t,
            "record_bytes": _entry_bytes("ballot", {"tracking_code": "0" * 64, "ballot": ballot}),
            "finalize_bytes": len(canonical_json(item)) + 1,
        }
    m["per_options"] = per
    a, b = options
    for key in ("encrypt_s", "verify_s", "finalize_s", "finalize_verify_s", "record_bytes", "finalize_bytes"):
        slope = (per[b][key] - per[a][key]) / (b - a)
        m[f"{key}_fit"] = {"fixed": per[a][key] - slope * a, "per_option": slope}

    # mixing: rows of (tag, flag) ciphertext pairs
    N = 64
    generators(grp, N)  # one-off per process; measured separately below
    rows = [[(c.alpha, c.beta) for c in (pk.encrypt(1, grp.rand_scalar()), pk.encrypt(0, grp.rand_scalar()))] for _ in range(N)]
    t0 = time.perf_counter()
    out, proof = shuffle_and_prove(grp, K, rows, ["bench"], pk.k_pow)
    m["shuffle_prove_per_row_s"] = (time.perf_counter() - t0) / N
    t0 = time.perf_counter()
    verify_shuffle(grp, K, rows, out, proof, ["bench"], pk.k_pow)
    m["shuffle_verify_per_row_s"] = (time.perf_counter() - t0) / N
    m["shuffle_bytes_per_row"] = (len(canonical_json({"rows": [[{"alpha": to_hex(x), "beta": to_hex(y)} for x, y in r] for r in out], "proof": proof}))) / N
    from .crypto.shuffle import _derive_generator

    m["shuffle_generator_derive_s"] = _timeit(lambda: _derive_generator(grp.p, grp.q, 10**6 + secrets.randbelow(10**6)), 5)

    big = pk.encrypt(5_900_000, grp.rand_scalar())
    ctx = ["bench", "decrypt-aggregate", cons, "C1"]
    m["decryption_share_with_proof_s"] = _timeit(lambda: trustees[0].decryption_share(big, ctx), 10)
    M, pr = trustees[0].decryption_share(big, ctx)
    Ki = public_share(grp, comms, 1)
    m["decryption_share_verify_s"] = _timeit(lambda: verify_decryption_share(grp, big, Ki, M, pr, ctx), 10)
    m["decryption_share_bytes"] = len(canonical_json({"share": to_hex(M), "proof": pr.to_dict()}))
    m["bsgs_6M_s"] = _timeit(lambda: dlog_bounded(grp, grp.g_pow(5_999_999), 6_000_000), 3)
    cts = [pk.encrypt(1, grp.rand_scalar()) for _ in range(2000)]
    t0 = time.perf_counter()
    add(grp, cts)
    m["aggregate_per_ballot_option_s"] = (time.perf_counter() - t0) / len(cts)

    from .crypto.proofs import schnorr_prove, schnorr_verify

    reg_pr = schnorr_prove(grp, t, T, ["bench"])
    m["registration_proof_verify_s"] = _timeit(lambda: schnorr_verify(grp, T, reg_pr, ["bench"]), 20)

    tree = MerkleTree()
    leaves = [secrets.token_bytes(64) for _ in range(200_000)]
    t0 = time.perf_counter()
    for x in leaves:
        tree.append(x)
    m["merkle_append_s"] = (time.perf_counter() - t0) / len(leaves)
    m["ingest_ballots_per_s"] = _measure_ingest(pk, mh, eid, cons, t, options[-1])
    return m


def _measure_ingest(pk: PublicKey, mh: str, eid: str, cons: str, t: int, n: int, total: int = 4096) -> float:
    """Sequencer throughput: tag lookup + revote counting + uniqueness checks +
    canonical JSON + Merkle + SQLite + fsync per batch, for realistic-size ballots.
    Proofs are checked by the stateless verifier fleet before this step."""
    opts = [f"C{i}" for i in range(1, n)] + ["NOTA"]
    tmpl = encrypt_ballot(pk, mh, eid, cons, opts, opts[0], t).ballot
    subs, tags = [], []
    for i in range(total):
        b = copy.deepcopy(tmpl)
        b["tag"]["ciphertext"]["alpha"] = format(i * 1000 + 1, "x")
        for j, s in enumerate(b["selections"]):
            s["ciphertext"]["alpha"] = format(i * 1000 + j + 2, "x")
        subs.append({"ballot": b, "tag": "x", "link": {}})
        tags.append(format(10**6 + i % 997, "x"))  # ~4 ballots per tag: revotes included
    with tempfile.TemporaryDirectory() as d:
        clock = FakeClock(dt.datetime(2026, 11, 2, 2, tzinfo=dt.UTC))
        board = Board(Path(d) / "rec", eid, RoleKey("board"), clock, durable=True)
        board.state = "OPEN"
        man = {
            "election_id": eid,
            "window": {"opens_at": iso(clock.now() - dt.timedelta(hours=1)), "closes_at": iso(clock.now() + dt.timedelta(hours=1))},
            "constituencies": [{"id": cons, "options": [{"id": o} for o in opts]}],
        }
        box = bb.BallotBox(Path(d) / "box.db", board, man, mh, pk, clock, lambda c, tag: True)
        t0 = time.perf_counter()
        for i in range(0, total, 256):
            box.submit_batch(subs[i : i + 256], prechecked_tags=tags[i : i + 256])
        return total / (time.perf_counter() - t0)


def model(m: dict, a: dict = ASSUMPTIONS) -> list[dict]:
    rows = []
    voting_seconds = a["days"] * a["voting_hours_per_day"] * 3600
    peak_factor = a["peak_hour_over_mean"] * a["final_day_surge"]

    def cost(key: str, n: int) -> float:
        f = m[f"{key}_fit"]
        return f["fixed"] + f["per_option"] * n

    n, mx, k = a["options_typical"], a["mixers"], a["threshold"]
    for elabel, electors in a["electors"].items():
        for tlabel, turnout in a["turnout"].items():
            voters = electors * turnout
            ballots = voters * (1 + a["revote_overhead"])
            flat = ballots / (a["days"] * 86400)
            mean = ballots / voting_seconds
            peak = mean * peak_factor
            design = peak * a["headroom"]
            vcost = cost("verify_s", n)
            shard_electors = a["largest_constituency_2024"] * electors / a["electors_2024"]
            shard_design = shard_electors * turnout * (1 + a["revote_overhead"]) / voting_seconds * peak_factor * a["headroom"]
            # after close, per ballot cast
            finalize = cost("finalize_s", n)
            mixing = mx * m["shuffle_prove_per_row_s"]
            attest = mx * m["shuffle_verify_per_row_s"]  # observers check each shuffle before trustees decrypt
            decrypt = k * m["decryption_share_with_proof_s"] * (1 + voters / ballots)  # every flag, and the tag of every counted row
            post_close = finalize + mixing + attest + decrypt
            reverify = vcost + cost("finalize_verify_s", n) + attest + k * m["decryption_share_verify_s"] * (1 + voters / ballots)
            per_ballot_bytes = (
                cost("record_bytes", n) + cost("finalize_bytes", n) + mx * m["shuffle_bytes_per_row"] + k * m["decryption_share_bytes"] * (1 + voters / ballots)
            )
            rows.append(
                {
                    "electors": elabel,
                    "turnout": tlabel,
                    "voters": voters,
                    "ballots": ballots,
                    "flat_24x7_per_s": flat,
                    "voting_hours_mean_per_s": mean,
                    "peak_per_s": peak,
                    "design_per_s": design,
                    "verify_cores_at_design": design * vcost,
                    "verify_cores_worst_ballot_at_design": design * cost("verify_s", a["options_worst"]),
                    "registration_cores_at_design": design * m["registration_proof_verify_s"],
                    "ingress_gbit_s_at_design": design * cost("record_bytes", n) * 8 / 1e9,
                    "largest_shard_design_per_s": shard_design,
                    "largest_shard_ingest_headroom_x": m["ingest_ballots_per_s"] / shard_design,
                    "record_tb": ballots * per_ballot_bytes / 1e12,
                    "stored_tb_with_replicas": ballots * per_ballot_bytes * a["replicas"] / 1e12,
                    "post_close_core_h": ballots * post_close / 3600,
                    "post_close_wall_h": ballots * post_close / a["post_close_cores"] / 3600,
                    "post_close_cores_for_24h": ballots * post_close / 86400,
                    "tally_dlog_core_min": a["constituencies"] * n * m["bsgs_6M_s"] / 60,
                    "full_reverify_h": ballots * reverify / a["post_close_cores"] / 3600,
                    "continuous_verify_cores": ballots * vcost / voting_seconds,
                    "device_encrypt_s": cost("encrypt_s", n),
                }
            )
    return rows


def _fmt(x: float) -> str:
    if x >= 1e9:
        return f"{x / 1e9:.2f} billion"
    if x >= 1e7:
        return f"{x / 1e7:.1f} crore"
    if x >= 1000:
        return f"{x:,.0f}"
    if x >= 10:
        return f"{x:.0f}"
    return f"{x:.2f}"


def render(m: dict, rows: list[dict], a: dict = ASSUMPTIONS) -> str:
    L = [
        "# National-scale capacity model (protocol v2)",
        "",
        "Generated by `chunaviq capacity`. Unit costs are **measured** on the machine below; the national figures are "
        "**modelled** from them with the assumptions listed. Nothing here was run at 100-crore scale.",
        "",
        "## Measured unit costs",
        "",
        f"Machine: {m['cores']} cores, Python {m['python']}, arithmetic backend `{m['backend']}`, 2048-bit group.",
        "",
        "| Operation | Measured |",
        "|---|---|",
    ]
    for n, p in m["per_options"].items():
        L.append(f"| Voter device: encrypt + prove a {n}-option ballot, with tag proof and link (one core) | {p['encrypt_s'] * 1000:.0f} ms |")
        L.append(f"| Server: verify a {n}-option ballot and its tag link (one core) | {p['verify_s'] * 1000:.0f} ms |")
        L.append(f"| Ballot box: finalize a {n}-option ballot (flag, masked vote, OR-proof) | {p['finalize_s'] * 1000:.0f} ms |")
        L.append(f"| Verify that finalization | {p['finalize_verify_s'] * 1000:.0f} ms |")
        L.append(f"| Record size of a {n}-option ballot / its finalization | {p['record_bytes'] / 1024:.1f} KiB / {p['finalize_bytes'] / 1024:.1f} KiB |")
    L += [
        f"| One mixer: shuffle + prove, per (tag, flag) row | {m['shuffle_prove_per_row_s'] * 1000:.1f} ms |",
        f"| Verify one shuffle, per row | {m['shuffle_verify_per_row_s'] * 1000:.1f} ms |",
        f"| Shuffle output + proof, per row | {m['shuffle_bytes_per_row'] / 1024:.1f} KiB |",
        f"| Derive one independent shuffle generator (once per batch position, cached) | {m['shuffle_generator_derive_s'] * 1000:.1f} ms |",
        f"| One trustee's decryption share with proof | {m['decryption_share_with_proof_s'] * 1000:.1f} ms |",
        f"| Verify a decryption share | {m['decryption_share_verify_s'] * 1000:.1f} ms |",
        f"| Verify a registration (tag proof) | {m['registration_proof_verify_s'] * 1000:.1f} ms |",
        f"| Recover a count of up to 60 lakh (baby-step giant-step) | {m['bsgs_6M_s'] * 1000:.0f} ms |",
        f"| Merkle append, per entry | {m['merkle_append_s'] * 1e6:.0f} µs |",
        f"| Sequencer ingest, one shard, group commit with fsync | {m['ingest_ballots_per_s']:,.0f} ballots/s |",
        "",
        "## Assumptions",
        "",
        "```json",
        json.dumps(a, indent=2),
        "```",
        "",
        "## Modelled national election",
        "",
    ]
    hdr = ["", *[f"{r['electors']}, {r['turnout']}" for r in rows]]
    L.append("| " + " | ".join(hdr) + " |")
    L.append("|" + "---|" * len(hdr))
    spec = [
        ("Voters", "voters", ""),
        ("Ballots cast (incl. revotes)", "ballots", ""),
        ("Average if spread 24x7", "flat_24x7_per_s", "/s"),
        ("Mean during voting hours", "voting_hours_mean_per_s", "/s"),
        ("Busiest hour", "peak_per_s", "/s"),
        ("Design rate (busiest hour x headroom)", "design_per_s", "/s"),
        ("Verifier cores at design rate, 16-option ballots", "verify_cores_at_design", ""),
        ("Verifier cores at design rate, 50-option ballots", "verify_cores_worst_ballot_at_design", ""),
        ("Registration-proof cores at design rate", "registration_cores_at_design", ""),
        ("Ingress at design rate", "ingress_gbit_s_at_design", " Gbit/s"),
        ("Largest constituency, design rate", "largest_shard_design_per_s", "/s"),
        ("Largest constituency, sequencer headroom", "largest_shard_ingest_headroom_x", "x"),
        ("Public record size (ballots, finalization, shuffles, shares)", "record_tb", " TB"),
        ("Stored with replicas", "stored_tb_with_replicas", " TB"),
        ("After close: finalize + mix + attest + decrypt", "post_close_core_h", " core-hours"),
        (f"  ... wall time on {a['post_close_cores']:,} cores", "post_close_wall_h", " h"),
        ("  ... or cores to finish it in 24 hours", "post_close_cores_for_24h", ""),
        ("Recovering all counts", "tally_dlog_core_min", " core-min"),
        (f"Full independent re-verification on {a['post_close_cores']:,} cores", "full_reverify_h", " h"),
        ("Cores for observers to verify ballots continuously during the week", "continuous_verify_cores", ""),
        ("Voter device: encrypt a 16-option ballot", "device_encrypt_s", " s"),
    ]
    for label, key, unit in spec:
        L.append(f"| {label} | " + " | ".join(_fmt(r[key]) + unit for r in rows) + " |")
    L += [
        "",
        "Finalization proofs can be precomputed during the week and redone only for ballots later superseded or revoked, "
        "so the after-close figure is an upper bound for that part; mixing and decryption must wait for close because "
        "they start from the final flags.",
    ]
    return "\n".join(L) + "\n"


def _rounded(x):
    """Round floats for the JSON report: 4 significant decimals is far finer than the model's accuracy."""
    if isinstance(x, float):
        return round(x, 4) if abs(x) < 1000 else round(x, 1)
    if isinstance(x, dict):
        return {k: _rounded(v) for k, v in x.items()}
    if isinstance(x, list | tuple):
        return [_rounded(v) for v in x]
    return x


def main() -> int:
    m = measure()
    rows = model(m)
    out = Path("docs/scale")
    out.mkdir(parents=True, exist_ok=True)
    (out / "capacity.json").write_text(json.dumps(_rounded({"measured": m, "assumptions": ASSUMPTIONS, "model": rows}), indent=2, default=str))
    (out / "capacity.md").write_text(render(m, rows))
    print((out / "capacity.md").read_text())
    return 0


__all__ = ["measure", "model", "render", "ASSUMPTIONS", "Ciphertext"]
