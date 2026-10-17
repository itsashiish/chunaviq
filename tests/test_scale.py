"""Scale properties, proven without casting crores of ballots.

Each test pins one property the national design depends on:
  * counting works at real constituency sizes (~60 lakh votes per option)
  * a federation of constituency shards verifies, and any shard tampering is caught
  * the sequencer and verifier use bounded memory, independent of record size
  * group commit keeps one-credential-one-ballot under duplicates within and across batches
  * one shard's sequencer ingests far faster than the largest constituency needs
Run: pytest -m scale
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import secrets
import shutil
import time
import tracemalloc
from pathlib import Path

import pytest

from chunaviq.crypto.elgamal import PublicKey, dlog_bounded
from chunaviq.crypto.group import get_group
from chunaviq.crypto.signing import RoleKey
from chunaviq.crypto.threshold import combine, joint_public_key, public_share, run_ceremony, verify_decryption_share
from chunaviq.election.ballotbox import BallotBox
from chunaviq.election.board import Board
from chunaviq.election.clock import FakeClock, iso
from chunaviq.election.federation import FedConfig, run_federation
from chunaviq.election.simulate import SimConfig, run
from chunaviq_verify import verify_record
from chunaviq_verify.federation import verify_federation
from chunaviq_verify.verifier import G as VG
from chunaviq_verify.verifier import _bsgs

pytestmark = pytest.mark.scale
G = get_group("CHUNAVIQ-2048-256-V1")
LARGEST_CONSTITUENCY_AT_150_CRORE = 5_860_000  # Malkajgiri 2024 (37.8 lakh) scaled by 150/96.8


# ------------------------------------------------------------------ counting at constituency scale
@pytest.mark.parametrize("m", [0, 1, 1_234_567, LARGEST_CONSTITUENCY_AT_150_CRORE])
def test_count_recovery_at_constituency_scale_both_implementations(m):
    bound = LARGEST_CONSTITUENCY_AT_150_CRORE
    gm = G.g_pow(m)
    t = time.perf_counter()
    assert dlog_bounded(G, gm, bound) == m
    assert _bsgs(VG(G.p, G.q, G.g), gm, bound) == m  # independent verifier's own implementation
    assert time.perf_counter() - t < 5


def test_count_outside_bound_is_rejected():
    with pytest.raises(ValueError):
        dlog_bounded(G, G.g_pow(1001), 1000)
    assert _bsgs(VG(G.p, G.q, G.g), G.g_pow(1001), 1000) is None


def test_threshold_tally_of_a_58_lakh_vote_total():
    """The aggregate of N encrypted 1s is an encryption of N; decrypting it with 3 of 5
    trustees and recovering N is exactly what the tally does for the largest seat."""
    trustees, comms = run_ceremony(G, 5, 3, "scale")
    pk = PublicKey(G, joint_public_key(G, comms))
    agg = pk.encrypt(LARGEST_CONSTITUENCY_AT_150_CRORE, G.rand_scalar())
    shares = {}
    for t in trustees[1:4]:
        M, pr = t.decryption_share(agg, ["scale"])
        assert verify_decryption_share(G, agg, public_share(G, comms, t.index), M, pr, ["scale"])
        shares[t.index] = M
    assert dlog_bounded(G, combine(G, agg, shares), LARGEST_CONSTITUENCY_AT_150_CRORE) == LARGEST_CONSTITUENCY_AT_150_CRORE


# ------------------------------------------------------------------ federation
@pytest.fixture(scope="module")
def federation(tmp_path_factory):
    out = tmp_path_factory.mktemp("fed") / "run"
    summary = run_federation(out, FedConfig(shards=6, voters_per_shard=60, rsa_bits=2048, workers=2, seed=7))
    return out, summary


def test_federation_verifies_and_matches_ground_truth(federation):
    out, summary = federation
    rep = verify_federation(out, expect_national_hash=summary["national_manifest_hash"], workers=2)
    assert rep.verified, [c for c in rep.checks if c.status == "FAIL"]
    oracle = json.loads((out / "oracle.json").read_text())
    assert {k: v["counts"] for k, v in rep.results.items()} == oracle
    assert rep.facts["ballots"] == summary["ballots"]
    assert not any(v.startswith("ACCEPTED") for v in summary["attacks_shard_1"].values())


def _failed(rep):
    return {c.id for c in rep.checks if c.status == "FAIL"}


def test_federation_missing_shard_fails(federation, tmp_path):
    out, _ = federation
    bad = shutil.copytree(out, tmp_path / "f")
    shutil.rmtree(bad / "shards" / "SYN-PC-003")
    assert "national.coverage" in _failed(verify_federation(bad, workers=2))


def test_federation_swapped_shards_fail(federation, tmp_path):
    out, _ = federation
    bad = shutil.copytree(out, tmp_path / "f")
    (bad / "shards" / "SYN-PC-001").rename(bad / "shards" / "tmp")
    (bad / "shards" / "SYN-PC-002").rename(bad / "shards" / "SYN-PC-001")
    (bad / "shards" / "tmp").rename(bad / "shards" / "SYN-PC-002")
    assert {"shards.verified"} <= _failed(verify_federation(bad, workers=2))


def test_federation_altered_national_result_fails(federation, tmp_path):
    out, _ = federation
    bad = shutil.copytree(out, tmp_path / "f")
    p = bad / "national" / "results.json"
    body = json.loads(p.read_text())
    party = next(iter(body["seats_by_party"]))
    body["seats_by_party"][party] += 1
    p.write_text(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")
    assert "national.results" in _failed(verify_federation(bad, workers=2))


# ------------------------------------------------------------------ bounded memory
def _record(tmp: Path, voters: int) -> Path:
    out = tmp / f"r{voters}"
    run(
        out,
        SimConfig(
            voters=voters,
            constituencies=1,
            candidates_per_constituency=3,
            turnout=1.0,
            group="TEST-INSECURE-512-160",
            rsa_bits=2048,
            workers=1,
            inject_attacks=False,
        ),
    )
    return out / "record"


def _verify_peak(rec: Path) -> int:
    tracemalloc.start()
    rep = verify_record(rec, allow_insecure_group=True, workers=1)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert rep.verified, [c for c in rep.checks if c.status == "FAIL"]
    return peak


def test_verifier_memory_does_not_grow_with_record_size(tmp_path):
    small, large = _record(tmp_path, 400), _record(tmp_path, 1600)
    assert large.joinpath("entries.jsonl").stat().st_size > 3.5 * small.joinpath("entries.jsonl").stat().st_size
    p_small, p_large = _verify_peak(small), _verify_peak(large)
    assert p_large < 1.5 * p_small, (p_small, p_large)  # 4x the ballots, not 4x the memory


def test_board_keeps_bodies_on_disk(tmp_path):
    clock = FakeClock(dt.datetime(2026, 11, 2, 2, tzinfo=dt.UTC))
    board = Board(tmp_path / "rec", "E", RoleKey("board"), clock, durable=False)
    board.state = "OPEN"
    body = {"tracking_code": "0" * 64, "ballot": {"blob": "a" * 50_000}}  # ~ a 16-option ballot
    tracemalloc.start()
    for _ in range(40):
        board.append_ballots([body] * 50)
    current, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert board.size == 2000 and board.count("ballot") == 2000
    assert current < 2000 * 1_000, current  # ~100 MB of bodies written, well under 2 MB held
    assert board.entry(1999)["seq"] == 1999 and sum(1 for _ in board.iter_entries("ballot")) == 2000


# ------------------------------------------------------------------ group commit
@pytest.fixture
def box(tmp_path):
    grp = get_group("TEST-INSECURE-512-160")
    clock = FakeClock(dt.datetime(2026, 11, 2, 2, tzinfo=dt.UTC))
    board = Board(tmp_path / "rec", "E", RoleKey("board"), clock, durable=True)
    board.state = "OPEN"
    man = {
        "election_id": "E",
        "window": {"opens_at": iso(clock.now() - dt.timedelta(hours=1)), "closes_at": iso(clock.now() + dt.timedelta(hours=1))},
        "constituencies": [{"id": "C", "options": [{"id": "A"}, {"id": "NOTA"}]}],
    }
    return BallotBox(tmp_path / "box.db", board, man, "mh", PublicKey(grp, grp.g_pow(5)), {}, clock)


def _fake(token: str, alphas: list[str]) -> dict:
    return {"credential": {"token": token, "signature": "1"}, "selections": [{"ciphertext": {"alpha": a, "beta": "1"}} for a in alphas], "constituency": "C"}


def test_group_commit_enforces_uniqueness_within_and_across_batches(box):
    t1, t2, t3 = (secrets.token_hex(32) for _ in range(3))
    r = box.submit_batch([_fake(t1, ["a1", "a2"]), _fake(t1, ["a3", "a4"]), _fake(t2, ["a2", "a5"]), _fake(t3, ["a6", "a7"])], prechecked=True)
    assert isinstance(r[0], dict) and r[1] == "CREDENTIAL_ALREADY_USED" and r[2] == "DUPLICATE_CIPHERTEXT" and isinstance(r[3], dict)
    r2 = box.submit_batch([_fake(t1, ["b1", "b2"]), _fake(t2, ["b3", "b4"])], prechecked=True)
    assert r2[0] == "CREDENTIAL_ALREADY_USED" and isinstance(r2[1], dict)  # t2's earlier attempt was rolled back cleanly
    assert box.board.count("ballot") == 3 and box.reconcile()["consistent"]


def test_sequencer_ingest_beats_largest_constituency_need(box):
    """Largest seat at 150 crore electors, 100% turnout, design rate (busiest hour x headroom):
    about 116 ballots/s (docs/scale/capacity.md). Require a 3x margin on this machine."""
    tmpl = {
        "credential": {"token": "", "signature": "1"},
        "constituency": "C",
        "selections": [{"ciphertext": {"alpha": "", "beta": "f" * 512}, "proof": {"x": "f" * 3000}} for _ in range(16)],
    }
    ballots = []
    for i in range(3072):
        b = copy.deepcopy(tmpl)
        b["credential"]["token"] = secrets.token_hex(32)
        for j, s in enumerate(b["selections"]):
            s["ciphertext"]["alpha"] = f"{i:x}-{j}"
        ballots.append(b)
    t = time.perf_counter()
    for i in range(0, len(ballots), 256):
        box.submit_batch(ballots[i : i + 256], prechecked=True)
    rate = len(ballots) / (time.perf_counter() - t)
    assert box.board.count("ballot") == len(ballots)
    assert rate > 3 * 116, f"{rate:.0f} ballots/s"
