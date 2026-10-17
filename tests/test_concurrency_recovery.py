"""Race conditions, crash recovery, backups and interrupted counting."""

import shutil
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from evlab.crypto.blind import blind, credential_message, unblind
from evlab.crypto.encoding import from_hex, to_hex
from evlab.crypto.signing import RoleKey
from evlab.election.administration import AdministrationError
from evlab.election.ballot import BallotRejected
from evlab.election.ballotbox import BallotBox
from evlab.election.board import Board, BoardError
from evlab.election.eligibility import EligibilityError
from evlab_verify import verify_record
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


def test_concurrent_duplicate_ballot_submissions_accept_exactly_one(election):
    b = election.credentialed(0).prepare("C1").ballot
    election.box.check(b)
    out = _race(lambda: election.box.submit(b, prechecked=True))
    assert sum(r[0] == "ok" for r in out) == 1
    assert {r[1] for r in out if r[0] == "rejected"} == {"CREDENTIAL_ALREADY_USED"}
    assert len(election.board.entries_of("ballot")) == 1


def test_concurrent_different_ballots_same_credential(election):
    d = election.credentialed(0)
    ballots = [d.prepare("C1").ballot for _ in range(THREADS)]
    it = iter(ballots)
    lock = threading.Lock()

    def submit():
        with lock:
            b = next(it)
        return election.box.submit(b)

    out = _race(submit)
    assert sum(r[0] == "ok" for r in out) == 1


def test_concurrent_credential_requests_issue_exactly_one(election):
    v = election.roll[0]
    pub = election.elig.issuer_keys()[v.constituency]

    def req():
        msg = credential_message("SYN-TEST", v.constituency, b"\x05" * 32)
        bl, _ = blind(pub, msg)
        return election.elig.issue_credential(v.voter_id, v.auth_secret, to_hex(bl))

    out = _race(req)
    assert sum(r[0] == "ok" for r in out) == 1
    assert {r[1] for r in out if r[0] == "rejected"} == {"ALREADY_ISSUED"}


def test_concurrent_distinct_voters_all_accepted(election):
    devices = [election.credentialed(i) for i in range(8)]
    ballots = [d.prepare(election.options[d.voter.constituency][1]).ballot for d in devices]
    with ThreadPoolExecutor(8) as ex:
        list(ex.map(election.box.submit, ballots))
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


def test_index_rebuilt_after_database_loss_still_blocks_reuse(election, tmp_path):
    d = election.credentialed(0)
    election.box.submit(d.prepare("C1").ballot)
    fresh = BallotBox(tmp_path / "new.db", election.board, election.manifest, election.mhash, election.pk, election.elig.issuer_keys(), election.clock)
    assert fresh.reconcile()["consistent"] is False
    assert fresh.rebuild_index() == 1 and fresh.reconcile()["consistent"]
    with pytest.raises(BallotRejected) as ei:
        fresh.submit(d.prepare("C2").ballot)
    assert ei.value.code == "CREDENTIAL_ALREADY_USED"


def test_crash_between_board_append_and_index_commit(election):
    """The board is authoritative: if the process dies after the ballot reached
    the board but before the index committed, recovery marks the token used."""
    d = election.credentialed(0)
    b = d.prepare("C1").ballot
    from evlab.election.ballot import tracking_code

    election.board.append("ballot", {"tracking_code": tracking_code(b), "ballot": b})  # "crash" before index
    assert not election.box.reconcile()["consistent"]
    election.box.rebuild_index()
    with pytest.raises(BallotRejected):
        election.box.submit(d.prepare("C2").ballot)


def test_tally_fails_safely_without_quorum(election):
    election.vote(0)
    election.clock.set(CLOSES)
    election.admin.close({})
    election.admin.publish_participation(election.elig.participation_summary())
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


def test_backup_restore_verifies_identically(finished, tmp_path):
    dst = shutil.copytree(finished.record, tmp_path / "restored")
    a, b = verify_record(finished.record), verify_record(dst)
    assert a.verified and b.verified and a.facts["final_root"] == b.facts["final_root"]


def test_unblind_rejects_corrupted_issuer_response(election):
    v = election.roll[0]
    pub = election.elig.issuer_keys()[v.constituency]
    bl, st = blind(pub, credential_message("SYN-TEST", v.constituency, b"\x09" * 32))
    resp = election.elig.issue_credential(v.voter_id, v.auth_secret, to_hex(bl))
    with pytest.raises(ValueError):
        unblind(pub, st, from_hex(resp["blind_signature"]) + 1)
