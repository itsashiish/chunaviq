"""Race conditions, crash recovery, backups and interrupted counting."""

import shutil
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from chunaviq.crypto.encoding import to_hex
from chunaviq.crypto.proofs import schnorr_prove
from chunaviq.crypto.signing import RoleKey
from chunaviq.election.administration import AdministrationError
from chunaviq.election.ballot import BallotRejected
from chunaviq.election.board import Board, BoardError
from chunaviq.election.eligibility import EligibilityError, register_context
from chunaviq_verify import verify_record
from harness import CLOSES, Election

THREADS = 16


def _race(fn, n=THREADS):
    barrier = threading.Barrier(n)

    def run(_):
        barrier.wait()
        try:
            return ("ok", fn())
        except (BallotRejected, EligibilityError) as e:
            return ("rejected", e.code)

    with ThreadPoolExecutor(n) as ex:
        return list(ex.map(run, range(n)))


def test_concurrent_duplicate_ballot_submissions_record_exactly_one(election):
    """16 identical submissions racing (a device retrying): all get the same receipt,
    exactly one entry is recorded."""
    sub = election.sub(election.registered(0), "C1")
    tag = election.box.precheck(sub)
    out = _race(lambda: election.box.submit(sub, prechecked_tag=tag))
    assert all(r[0] == "ok" for r in out)
    assert len({(r[1]["tracking_code"], r[1]["seq"]) for r in out}) == 1
    assert sum(1 for r in out if not r[1].get("duplicate_submission")) == 1
    assert len(election.board.entries_of("ballot")) == 1


def test_concurrent_revotes_are_all_recorded_and_numbered(election):
    """Different ballots under one tag are revotes: all are kept, numbered 1..n without gaps."""
    d = election.registered(0)
    subs = [election.sub(d, "C1") for _ in range(8)]
    it = iter(subs)
    lock = threading.Lock()

    def submit():
        with lock:
            s = next(it)
        return election.box.submit(s)

    out = _race(submit, n=8)
    assert all(r[0] == "ok" for r in out)
    assert sorted(r[1]["revote"] for r in out) == list(range(1, 9))


def test_concurrent_registrations_of_one_voter_keep_one_valid_tag(election):
    """Racing registrations for the same roll entry: every one that succeeds bumps the
    generation; exactly one tag ends up valid."""
    v = election.roll[0]
    d = election.device(0)
    sessions = [d.authenticate(election.elig, "aadhaar-otp") for _ in range(6)]
    it = iter(sessions)
    lock = threading.Lock()

    def reg():
        with lock:
            s = next(it)
        t = election.grp.rand_scalar()
        T = election.grp.g_pow(t)
        return election.elig.register(s, to_hex(T), schnorr_prove(election.grp, t, T, register_context("SYN-TEST", v.constituency, s)).to_dict())

    out = _race(reg, n=6)
    gens = sorted(r[1]["generation"] for r in out if r[0] == "ok")
    assert gens == list(range(1, len(gens) + 1)) and len(gens) >= 1
    s = election.elig.registration_summary()["constituencies"][v.constituency]
    assert s["registered"] == 1 and len(s["valid_tags"]) == 1


def test_concurrent_distinct_voters_all_accepted(election):
    devices = [election.registered(i) for i in range(8)]
    subs = [election.sub(d, election.options[d.voter.constituency][1]) for d in devices]
    with ThreadPoolExecutor(8) as ex:
        list(ex.map(election.box.submit, subs))
    assert election.box.reconcile()["consistent"] and len(election.board.entries_of("ballot")) == 8


# ------------------------------------------------------------------ recovery
def test_board_reload_reproduces_state_and_root(election):
    election.vote(0)
    cp = election.board.checkpoint()
    again = Board(election.record, "SYN-TEST", election.operator, election.clock, durable=False)
    assert again.tree.root().hex() == cp["root"] and again.state == "OPEN" and len(again.entries) == len(election.board.entries)


def test_board_refuses_truncated_history(election):
    election.vote(0)
    election.vote(1)
    election.board.checkpoint()
    p = election.record / "entries.jsonl"
    p.write_bytes(b"\n".join(p.read_bytes().split(b"\n")[:-2]) + b"\n")
    with pytest.raises(BoardError):
        Board(election.record, "SYN-TEST", election.operator, election.clock, durable=False)


def test_board_refuses_forged_checkpoint(election):
    election.board.checkpoint()
    other = RoleKey("board")
    with pytest.raises(BoardError):
        Board(election.record, "SYN-TEST", other, election.clock, durable=False)


def test_reconcile_detects_board_index_divergence(election):
    """The board never shows tags, so the ballot box index cannot be rebuilt from it;
    a crash between board append and index commit must at least be detected."""
    d = election.registered(0)
    sub = election.sub(d, "C1")
    from chunaviq.election.ballot import tracking_code

    election.board.append("ballot", {"tracking_code": tracking_code(sub["ballot"]), "ballot": sub["ballot"]})  # "crash" before index
    assert not election.box.reconcile()["consistent"]


def test_tally_fails_safely_without_quorum(election):
    election.vote(0)
    election.clock.set(CLOSES)
    election.admin.close({})
    election.admin.publish_registration(election.elig.registration_entries(), {c: set(election.elig.valid_tags(c)) for c in election.elig.constituencies})
    election.box.finalize(election.admin.valid_tags)
    for h in election.hosts[:2]:  # 3 trustees, threshold 2 -> only 1 left
        h.available = False
    with pytest.raises(AdministrationError):
        election.admin.tally()
    assert election.board.state == "CLOSED"  # nothing published


def test_tally_succeeds_with_exactly_threshold_trustees(tmp_path):
    e = Election(tmp_path)
    for i in range(5):
        e.vote(i, i % 2)
    e.hosts[0].available = False
    e.close_and_tally()
    assert verify_record(e.record).verified


def test_finalization_refused_while_open(election):
    with pytest.raises(BallotRejected):
        election.box.finalize({})


def test_backup_restore_verifies_identically(finished, tmp_path):
    dst = shutil.copytree(finished.record, tmp_path / "restored")
    a, b = verify_record(finished.record), verify_record(dst)
    assert a.verified and b.verified and a.facts["final_root"] == b.facts["final_root"]
