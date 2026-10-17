"""Measure unit costs on this machine and model a national election.

    chunaviq capacity            -> docs/scale/capacity.md + docs/scale/capacity.json

Nothing here assumes a cost: every per-operation number is measured, and every
modelling assumption (voting hours, peaks, headroom, candidates per seat) is
named in ASSUMPTIONS and printed in the report. Change an assumption, rerun.
"""

from __future__ import annotations

import json
import math
import os
import platform
import secrets
import statistics
import tempfile
import time
from pathlib import Path

from .crypto.blind import RSABlindSigner, blind, credential_message
from .crypto.elgamal import Ciphertext, PublicKey, add, dlog_bounded
from .crypto.encoding import canonical_json, to_hex
from .crypto.group import BACKEND, get_group
from .crypto.merkle import MerkleTree
from .crypto.signing import RoleKey
from .crypto.threshold import public_share, run_ceremony, verify_decryption_share
from .election.ballot import check_ballot, encrypt_ballot
from .election.ballotbox import BallotBox
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
    "options_typical": 16,  # about 15 candidates + NOTA per seat (2024 averaged ~15 candidates per seat)
    "options_worst": 50,
    "constituencies": 543,
    "largest_constituency_2024": 3_780_000,  # Malkajgiri, 2024
    "electors_2024": 968_000_000,
    "replicas": 3,
    "post_close_verify_cores": 2_000,
}


def _timeit(fn, n: int) -> float:
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t)
    return statistics.median(samples)


def measure(options: tuple[int, ...] = (4, 16)) -> dict:
    grp = get_group("CHUNAVIQ-2048-256-V1")
    m: dict = {"backend": BACKEND, "cpu": platform.processor() or platform.machine(), "cores": os.cpu_count(), "python": platform.python_version()}
    trustees, comms = run_ceremony(grp, 5, 3, "bench")
    K = grp.mul(*(tc.commitments[0] for tc in comms))
    pk = PublicKey(grp, K)
    signer = RSABlindSigner(3072)
    mh, eid, cons = "bench-mh", "BENCH", "SYN-PC-001"

    def credential() -> tuple[str, str]:
        tok = secrets.token_bytes(32)
        msg = credential_message(eid, cons, tok)
        b, st = blind(signer.public, msg)
        s = signer.sign_blinded(b) * pow(st.r, -1, signer.public.n) % signer.public.n
        return tok.hex(), to_hex(s)

    m["rsa3072_blind_sign_s"] = _timeit(lambda: signer.sign_blinded(blind(signer.public, credential_message(eid, cons, b"\0" * 32))[0]), 30)
    per = {}
    for n in options:
        opts = [f"C{i}" for i in range(1, n)] + ["NOTA"]
        tok, sig = credential()
        enc_t = _timeit(lambda opts=opts, tok=tok, sig=sig: encrypt_ballot(pk, mh, eid, cons, opts, opts[0], tok, sig), 6)
        ballot = encrypt_ballot(pk, mh, eid, cons, opts, opts[1], tok, sig).ballot
        ver_t = _timeit(
            lambda opts=opts, ballot=ballot: check_ballot(ballot, pk=pk, mhash=mh, election_id=eid, options={cons: opts}, issuer_keys={cons: signer.public}), 6
        )
        per[n] = {
            "encrypt_s": enc_t,
            "verify_s": ver_t,
            "record_bytes": len(
                canonical_json({"seq": 10**9, "type": "ballot", "time_bucket": "2026-11-02T01", "body": {"tracking_code": "0" * 64, "ballot": ballot}})
            )
            + 1,
        }
    m["per_options"] = per
    a, b = options
    for key in ("encrypt_s", "verify_s", "record_bytes"):
        slope = (per[b][key] - per[a][key]) / (b - a)
        m[f"{key}_fit"] = {"fixed": per[a][key] - slope * a, "per_option": slope}

    cts = [pk.encrypt(1, grp.rand_scalar()) for _ in range(2000)]
    t = time.perf_counter()
    add(grp, cts)
    m["aggregate_per_ballot_option_s"] = (time.perf_counter() - t) / len(cts)

    big = pk.encrypt(5_900_000, grp.rand_scalar())
    ctx = ["bench", "decrypt-aggregate", cons, "C1"]
    m["decryption_share_with_proof_s"] = _timeit(lambda: trustees[0].decryption_share(big, ctx), 10)
    M, pr = trustees[0].decryption_share(big, ctx)
    Ki = public_share(grp, comms, 1)
    m["decryption_share_verify_s"] = _timeit(lambda: verify_decryption_share(grp, big, Ki, M, pr, ctx), 10)
    m["bsgs_6M_s"] = _timeit(lambda: dlog_bounded(grp, grp.g_pow(5_999_999), 6_000_000), 3)

    tree = MerkleTree()
    leaves = [secrets.token_bytes(64) for _ in range(200_000)]
    t = time.perf_counter()
    for x in leaves:
        tree.append(x)
    m["merkle_append_s"] = (time.perf_counter() - t) / len(leaves)

    m["ingest_ballots_per_s"] = _measure_ingest(pk, mh, eid, cons, signer, options[-1])
    return m


def _measure_ingest(pk: PublicKey, mh: str, eid: str, cons: str, signer: RSABlindSigner, n: int, total: int = 4096) -> float:
    """Sequencer throughput: uniqueness checks + canonical JSON + Merkle + SQLite +
    fsync per batch, for realistic-size ballots. Proofs are checked by the
    stateless verifier fleet before this step, so they are excluded here."""
    import copy

    opts = [f"C{i}" for i in range(1, n)] + ["NOTA"]
    tmpl = encrypt_ballot(pk, mh, eid, cons, opts, opts[0], secrets.token_hex(32), "1").ballot
    ballots = []
    for i in range(total):
        b = copy.deepcopy(tmpl)
        b["credential"]["token"] = secrets.token_hex(32)
        for j, s in enumerate(b["selections"]):
            s["ciphertext"]["alpha"] = format(i * 1000 + j + 2, "x")
        ballots.append(b)
    import datetime as dt

    with tempfile.TemporaryDirectory() as d:
        clock = FakeClock(dt.datetime(2026, 11, 2, 2, tzinfo=dt.UTC))
        board = Board(Path(d) / "rec", eid, RoleKey("board"), clock, durable=True)
        board.state = "OPEN"
        man = {
            "election_id": eid,
            "window": {"opens_at": iso(clock.now() - dt.timedelta(hours=1)), "closes_at": iso(clock.now() + dt.timedelta(hours=1))},
            "constituencies": [{"id": cons, "options": [{"id": o} for o in opts]}],
        }
        box = BallotBox(Path(d) / "box.db", board, man, mh, pk, {cons: signer.public}, clock)
        t = time.perf_counter()
        for i in range(0, total, 256):
            box.submit_batch(ballots[i : i + 256], prechecked=True)
        return total / (time.perf_counter() - t)


def model(m: dict, a: dict = ASSUMPTIONS) -> list[dict]:
    rows = []
    voting_seconds = a["days"] * a["voting_hours_per_day"] * 3600
    peak_factor = a["peak_hour_over_mean"] * a["final_day_surge"]
    fit_v, fit_e, fit_b = m["verify_s_fit"], m["encrypt_s_fit"], m["record_bytes_fit"]

    def cost(fit: dict, n: int) -> float:
        return fit["fixed"] + fit["per_option"] * n

    for elabel, electors in a["electors"].items():
        for tlabel, turnout in a["turnout"].items():
            ballots = electors * turnout
            flat = ballots / (a["days"] * 86400)
            mean = ballots / voting_seconds
            peak = mean * peak_factor
            design = peak * a["headroom"]
            n = a["options_typical"]
            vcost, bytes_ = cost(fit_v, n), cost(fit_b, n)
            shard_electors = a["largest_constituency_2024"] * electors / a["electors_2024"]
            shard_design = shard_electors * turnout / voting_seconds * peak_factor * a["headroom"]
            rows.append(
                {
                    "electors": elabel,
                    "turnout": tlabel,
                    "ballots": ballots,
                    "flat_24x7_per_s": flat,
                    "voting_hours_mean_per_s": mean,
                    "peak_per_s": peak,
                    "design_per_s": design,
                    "verify_cores_at_design": design * vcost,
                    "verify_cores_worst_ballot_at_design": design * cost(fit_v, a["options_worst"]),
                    "credential_cores_at_design": design * m["rsa3072_blind_sign_s"],
                    "ingress_gbit_s_at_design": design * bytes_ * 8 / 1e9,
                    "largest_shard_design_per_s": shard_design,
                    "largest_shard_ingest_headroom_x": m["ingest_ballots_per_s"] / shard_design,
                    "record_tb": ballots * bytes_ / 1e12,
                    "stored_tb_with_replicas": ballots * bytes_ * a["replicas"] / 1e12,
                    "tally_aggregate_core_h": ballots * n * m["aggregate_per_ballot_option_s"] / 3600,
                    "tally_decrypt_trustee_min": a["constituencies"] * n * m["decryption_share_with_proof_s"] / 60,
                    "tally_dlog_core_min": a["constituencies"] * n * m["bsgs_6M_s"] / 60,
                    "post_close_full_verify_h": ballots * vcost / a["post_close_verify_cores"] / 3600,
                    "device_encrypt_s": cost(fit_e, n),
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
        "# National-scale capacity model",
        "",
        "Generated by `chunaviq capacity`. Unit costs are **measured** on the machine below; the national figures are "
        "**modelled** from them with the assumptions listed. Nothing here was run at 100-crore scale.",
        "",
    ]
    L += [
        "## Measured unit costs",
        "",
        f"Machine: {m['cores']} cores, Python {m['python']}, arithmetic backend `{m['backend']}`, 2048-bit group, RSA-3072 credentials.",
        "",
    ]
    L += ["| Operation | Measured |", "|---|---|"]
    for n, p in m["per_options"].items():
        L.append(f"| Encrypt + prove a {n}-option ballot (voter device, one core) | {p['encrypt_s'] * 1000:.0f} ms |")
        L.append(f"| Verify a {n}-option ballot (server, one core) | {p['verify_s'] * 1000:.0f} ms |")
        L.append(f"| Record size of a {n}-option ballot | {p['record_bytes'] / 1024:.1f} KiB |")
    L += [
        f"| Blind-sign one credential (RSA-3072) | {m['rsa3072_blind_sign_s'] * 1000:.1f} ms |",
        f"| Homomorphic aggregation, per ballot-option | {m['aggregate_per_ballot_option_s'] * 1e6:.0f} µs |",
        f"| One trustee's decryption share with proof | {m['decryption_share_with_proof_s'] * 1000:.0f} ms |",
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
        ("Ballots", "ballots", ""),
        ("Average if spread 24x7 (your figure)", "flat_24x7_per_s", "/s"),
        ("Mean during voting hours", "voting_hours_mean_per_s", "/s"),
        ("Busiest hour", "peak_per_s", "/s"),
        ("Design rate (busiest hour x headroom)", "design_per_s", "/s"),
        ("Verifier cores at design rate, 16-option ballots", "verify_cores_at_design", ""),
        ("Verifier cores at design rate, 50-option ballots", "verify_cores_worst_ballot_at_design", ""),
        ("Credential-signing cores at design rate", "credential_cores_at_design", ""),
        ("Ingress at design rate", "ingress_gbit_s_at_design", " Gbit/s"),
        ("Largest constituency, design rate", "largest_shard_design_per_s", "/s"),
        ("Largest constituency, sequencer headroom", "largest_shard_ingest_headroom_x", "x"),
        ("Public record size", "record_tb", " TB"),
        ("Stored with replicas", "stored_tb_with_replicas", " TB"),
        ("Tally: aggregation", "tally_aggregate_core_h", " core-hours"),
        ("Tally: each trustee's decryption work", "tally_decrypt_trustee_min", " min"),
        ("Tally: recovering all counts", "tally_dlog_core_min", " core-min"),
        (f"Full independent re-verification on {a['post_close_verify_cores']:,} cores", "post_close_full_verify_h", " h"),
        ("Voter device: encrypt a 16-option ballot", "device_encrypt_s", " s"),
    ]
    for label, key, unit in spec:
        L.append(f"| {label} | " + " | ".join(_fmt(r[key]) + unit for r in rows) + " |")
    return "\n".join(L) + "\n"


def main() -> int:
    m = measure()
    rows = model(m)
    out = Path("docs/scale")
    out.mkdir(parents=True, exist_ok=True)
    (out / "capacity.json").write_text(json.dumps({"measured": m, "assumptions": ASSUMPTIONS, "model": rows}, indent=2, default=str))
    (out / "capacity.md").write_text(render(m, rows))
    print((out / "capacity.md").read_text())
    return 0


__all__ = ["measure", "model", "render", "ASSUMPTIONS", "Ciphertext", "math"]
