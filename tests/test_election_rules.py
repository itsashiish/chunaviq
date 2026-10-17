"""Lifecycle gates, eligibility rules and ballot acceptance rules."""

import copy
import datetime as dt
import json

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from chunaviq.crypto.elgamal import Ciphertext
from chunaviq.crypto.encoding import to_hex
from chunaviq.crypto.proofs import disjunctive_prove
from chunaviq.election.administration import AdministrationError, decide
from chunaviq.election.ballot import BallotRejected, encrypt_ballot, selection_context
from chunaviq.election.board import BoardError
from chunaviq.election.eligibility import EligibilityError
from chunaviq.election.manifest import Candidate, Constituency, build_manifest
from chunaviq_verify import verify_receipt
from harness import CLOSES, OPENS, Election


def rejected(fn) -> str:
    with pytest.raises((BallotRejected, EligibilityError)) as ei:
        fn()
    return ei.value.code


# ===================================================================== lifecycle
def test_no_ballot_before_open(tmp_path):
    e = Election(tmp_path, open_now=False)
    d = e.credentialed(0)
    assert rejected(lambda: e.box.submit(d.prepare("C1").ballot)) == "ELECTION_NOT_OPEN"


def test_cannot_open_before_published_time(tmp_path):
    e = Election(tmp_path, open_now=False)
    e.clock.set(OPENS - dt.timedelta(seconds=1))
    with pytest.raises(AdministrationError):
        e.admin.open()


def test_window_enforced_even_if_officer_never_closes(election):
    d = election.credentialed(0)
    b = d.prepare("C1").ballot
    election.clock.set(CLOSES)
    assert rejected(lambda: election.box.submit(b)) == "OUTSIDE_VOTING_WINDOW"


def test_no_ballot_after_close(election):
    d = election.credentialed(0)
    election.clock.set(CLOSES)
    election.admin.close({})
    assert rejected(lambda: election.box.submit(d.prepare("C1").ballot)) == "ELECTION_NOT_OPEN"


def test_close_before_time_requires_recorded_reason(election):
    with pytest.raises(AdministrationError):
        election.admin.close({})
    election.admin.close({}, emergency_reason="synthetic incident drill")
    assert election.board.entries[-1]["body"]["early_close_reason"] == "synthetic incident drill"


@pytest.mark.parametrize("state", ["DRAFT", "KEY_CEREMONY", "READY", "OPEN", "TALLIED", "PUBLISHED"])
def test_illegal_lifecycle_transitions_from_open(election, state):
    with pytest.raises(BoardError):
        election.board.append("lifecycle", election.officer.sign_body({"election_id": "SYN-TEST", "state": state}))


def test_cannot_reopen_after_close(election):
    election.clock.set(CLOSES)
    election.admin.close({})
    with pytest.raises(BoardError):
        election.admin._transition("OPEN")


def test_tally_requires_closed(election):
    with pytest.raises(AdministrationError):
        election.admin.tally()


def test_manifest_must_be_first(election):
    with pytest.raises(AdministrationError):
        election.admin.publish_manifest(election.manifest)


def test_manifest_validation():
    nota = Candidate("NOTA", "None of the Above", "-")
    c = Candidate("C1", "x", "y")
    kw = dict(
        election_id="E",
        title="t",
        group_name="g",
        opens_at="a",
        closes_at="b",
        trustee_keys=["k"],
        officer_key="o",
        board_key="b",
        eligibility_key="e",
        software_version="v",
    )
    with pytest.raises(ValueError):  # no NOTA
        build_manifest(constituencies=[Constituency("A", "A", (c,), 1)], threshold=1, **kw)
    with pytest.raises(ValueError):  # NOTA only
        build_manifest(constituencies=[Constituency("A", "A", (nota,), 1)], threshold=1, **kw)
    with pytest.raises(ValueError):  # threshold > n
        build_manifest(constituencies=[Constituency("A", "A", (c, nota), 1)], threshold=2, **kw)


# ===================================================================== eligibility
def test_credential_issuance_only_when_accepting(tmp_path):
    e = Election(tmp_path, open_now=False)
    e.elig.set_accepting(False)
    assert rejected(lambda: e.credentialed(0)) == "NOT_ACCEPTING"


def test_not_on_roll(election):
    assert rejected(lambda: election.elig.issue_credential("syn-v-9999999", b"x" * 16, "5")) == "NOT_ON_ROLL"


def test_wrong_secret_and_lockout(election):
    v = election.roll[0]
    for _ in range(5):
        assert rejected(lambda: election.elig.issue_credential(v.voter_id, b"wrong" * 4, "5")) == "AUTH_FAILED"
    assert rejected(lambda: election.credentialed(0)) == "LOCKED"


def test_revoked_voter_cannot_obtain_credential(election):
    election.elig.revoke(election.roll[1].voter_id)
    assert rejected(lambda: election.credentialed(1)) == "REVOKED"


def test_revocation_after_issuance_is_refused_and_reported(election):
    election.credentialed(2)
    assert rejected(lambda: election.elig.revoke(election.roll[2].voter_id)) == "ALREADY_ISSUED"


def test_one_credential_per_voter(election):
    election.credentialed(3)
    assert rejected(lambda: election.credentialed(3)) == "ALREADY_ISSUED"


def test_participation_commitment_lets_voter_confirm_they_are_counted_as_participating(election):
    d = election.credentialed(4)
    from chunaviq.election.eligibility import participation_commitment

    c = participation_commitment("SYN-TEST", d.voter.voter_id, bytes.fromhex(d.participation_receipt["salt"]))
    s = election.elig.participation_summary()["constituencies"][d.voter.constituency]
    assert c == d.participation_receipt["commitment"] and c in s["commitments"]


# ===================================================================== ballots
def test_valid_ballot_accepted_with_verifiable_receipt(election):
    r = election.vote(0)
    election.board.checkpoint()
    receipt = election.board.receipt(r["seq"])
    assert receipt["tracking_code"] == r["tracking_code"]
    assert verify_receipt(election.record, receipt)
    forged = dict(receipt, tracking_code="00" * 32)
    assert not verify_receipt(election.record, forged)


def test_identical_retry_returns_original_receipt(election):
    d = election.credentialed(0)
    b = d.prepare("C1").ballot
    first = election.box.submit(b)
    again = election.box.submit(b)
    assert again == dict(first, duplicate_submission=True)
    assert election.board.count("ballot") == 1
    election.clock.set(election.box.closes)  # even after polls close, the receipt is returned
    assert election.box.submit(b)["seq"] == first["seq"]


def test_credential_reuse_rejected(election):
    d = election.credentialed(0)
    election.box.submit(d.prepare("C1").ballot)
    assert rejected(lambda: election.box.submit(d.prepare("C2").ballot)) == "CREDENTIAL_ALREADY_USED"


def test_ballot_copying_with_own_credential_rejected(election):
    """Copying someone's encrypted selections onto your own credential would let
    you vote "the same as them" (a privacy attack). Proofs are bound to the
    credential token, so the copy fails."""
    victim = election.credentialed(0)
    vb = victim.prepare("C2").ballot
    election.box.submit(vb)
    attacker = election.credentialed(1)
    ab = attacker.prepare("C1").ballot
    ab["selections"] = copy.deepcopy(vb["selections"])
    ab["limit_proof"] = vb["limit_proof"]
    assert rejected(lambda: election.box.submit(ab)) in {"BAD_SELECTION_PROOF", "DUPLICATE_CIPHERTEXT"}


def test_ballot_for_other_constituency_rejected(election):
    d = election.credentialed(0)  # constituency 1
    other = election.cons[1]
    pb = encrypt_ballot(election.pk, election.mhash, "SYN-TEST", other.id, other.option_ids, "C1", d.token.hex(), to_hex(d.signature))
    assert rejected(lambda: election.box.submit(pb.ballot)) == "BAD_CREDENTIAL"


def test_wrong_ballot_style_rejected(election):
    d = election.credentialed(0)
    b = d.prepare("C1").ballot
    b["selections"] = b["selections"][::-1]
    assert rejected(lambda: election.box.submit(b)) == "WRONG_BALLOT_STYLE"
    b2 = d.prepare("C1").ballot
    b2["selections"] = b2["selections"][:-1]  # drop NOTA
    assert rejected(lambda: election.box.submit(b2)) == "WRONG_BALLOT_STYLE"


def _with_selection_values(election, values):
    """A ballot whose selections encrypt `values`, each with a VALID 0/1 proof,
    and the original (now wrong) limit proof."""
    d = election.credentialed(0)
    b = d.prepare("C1").ballot
    tok = b["credential"]["token"]
    for j, m in enumerate(values):
        r = election.grp.rand_scalar()
        ct = election.pk.encrypt(m, r)
        oid = b["selections"][j]["option_id"]
        b["selections"][j]["ciphertext"] = ct.to_dict()
        b["selections"][j]["proof"] = disjunctive_prove(election.pk, ct, m, r, selection_context(election.mhash, b["constituency"], oid, tok)).to_dict()
    return b


def test_overvote_rejected(election):
    assert rejected(lambda: election.box.submit(_with_selection_values(election, [1, 1, 0, 0]))) == "BAD_LIMIT_PROOF"


def test_blank_ballot_rejected(election):
    """Every ballot must make exactly one selection; abstention is expressed by
    not voting or by NOTA."""
    assert rejected(lambda: election.box.submit(_with_selection_values(election, [0, 0, 0, 0]))) == "BAD_LIMIT_PROOF"


def test_ciphertext_outside_subgroup_rejected(election):
    d = election.credentialed(0)
    b = d.prepare("C1").ballot
    ct = Ciphertext.from_dict(b["selections"][0]["ciphertext"])
    b["selections"][0]["ciphertext"] = Ciphertext(election.grp.p - ct.alpha, ct.beta).to_dict()
    assert rejected(lambda: election.box.submit(b)) == "INVALID_CIPHERTEXT"


@pytest.mark.parametrize("where", ["ciphertext", "proof", "limit_proof", "credential", "top"])
def test_marked_ballot_rejected(election, where):
    """Regression (found by the fuzzer): a voter must not be able to embed a
    free-form marker in any part of the ballot to prove their vote to a buyer."""
    b = election.credentialed(0).prepare("C1").ballot
    target = {
        "ciphertext": b["selections"][0]["ciphertext"],
        "proof": b["selections"][0]["proof"],
        "limit_proof": b["limit_proof"],
        "credential": b["credential"],
        "top": b,
    }[where]
    target["marker"] = "voter-1234"
    assert rejected(lambda: election.box.submit(b)) == "MALFORMED"


def test_rejections_are_counted_without_identity(election):
    d = election.credentialed(0)
    election.box.submit(d.prepare("C1").ballot)
    for _ in range(3):
        with pytest.raises(BallotRejected):
            election.box.submit(d.prepare("C1").ballot)
    assert election.box.rejections["CREDENTIAL_ALREADY_USED"] == 3


_mut = st.sampled_from(["drop", "type", "hex", "nest", "extra"])


@settings(max_examples=40, deadline=None)
@given(st.lists(st.tuples(_mut, st.integers(min_value=0, max_value=10_000)), min_size=1, max_size=4))
def test_fuzzed_ballots_never_crash_and_never_accepted(tmp_path_factory, muts):
    e = _fuzz_election(tmp_path_factory)
    b = json.loads(json.dumps(e._fuzz_base))
    for kind, n in muts:
        paths = [p for p in _paths(b) if p]  # never the root: every mutation must change something
        path = paths[n % len(paths)]
        _mutate(b, path, kind)
    assume(b != e._fuzz_base)  # two mutations can cancel out and restore the valid ballot
    with pytest.raises(BallotRejected):
        e.box.check(b)


_FUZZ: dict = {}


def _fuzz_election(factory):
    if "e" not in _FUZZ:
        e = Election(factory.mktemp("fuzz"))
        e._fuzz_base = e.credentialed(0).prepare("C2").ballot
        _FUZZ["e"] = e
    return _FUZZ["e"]


def _paths(obj, prefix=()):
    yield prefix
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _paths(v, prefix + (i,))


def _mutate(root, path, kind):
    if not path:
        return
    parent = root
    for p in path[:-1]:
        parent = parent[p]
    key = path[-1]
    if kind == "drop" and isinstance(parent, dict):
        parent.pop(key, None)
    elif kind == "type":
        parent[key] = 12345
    elif kind == "hex":
        v = parent[key]
        parent[key] = (v[:-1] + ("0" if v[-1] != "0" else "1")) if isinstance(v, str) and v else "zz"
    elif kind == "nest":
        parent[key] = [parent[key]]
    elif kind == "extra" and isinstance(parent, dict):
        parent["unexpected"] = "x"
    else:
        parent[key] = None


# ===================================================================== decision rule
def test_decide_rules():
    assert decide({"C1": 5, "C2": 3, "NOTA": 9}) == {"winner": "C1", "tied": [], "nota_exceeds_winner": True}
    assert decide({"C1": 4, "C2": 4, "NOTA": 0}) == {"winner": None, "tied": ["C1", "C2"], "nota_exceeds_winner": False}
    assert decide({"C1": 0, "NOTA": 0})["winner"] == "C1"
