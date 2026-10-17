"""Lifecycle gates, identity and registration rules, ballot acceptance and revoting rules."""

import copy
import datetime as dt
import json

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from chunaviq.crypto.elgamal import Ciphertext
from chunaviq.crypto.encoding import to_hex
from chunaviq.crypto.proofs import disjunctive_prove, schnorr_prove
from chunaviq.election.administration import AdministrationError, decide
from chunaviq.election.ballot import BallotRejected, encrypt_ballot, make_link, selection_context
from chunaviq.election.board import BoardError
from chunaviq.election.eligibility import EligibilityError, register_context
from chunaviq.election.identity import live_capture
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
    d = e.registered(0)
    assert rejected(lambda: e.box.submit(e.sub(d, "C1"))) == "ELECTION_NOT_OPEN"


def test_cannot_open_before_published_time(tmp_path):
    e = Election(tmp_path, open_now=False)
    e.clock.set(OPENS - dt.timedelta(seconds=1))
    with pytest.raises(AdministrationError):
        e.admin.open()


def test_window_enforced_even_if_officer_never_closes(election):
    d = election.registered(0)
    b = election.sub(d, "C1")
    election.clock.set(CLOSES)
    assert rejected(lambda: election.box.submit(b)) == "OUTSIDE_VOTING_WINDOW"


def test_no_ballot_after_close(election):
    d = election.registered(0)
    election.clock.set(CLOSES)
    election.admin.close({})
    assert rejected(lambda: election.box.submit(election.sub(d, "C1"))) == "ELECTION_NOT_OPEN"


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
    with pytest.raises(ValueError):  # more mixers than trustees
        build_manifest(constituencies=[Constituency("A", "A", (c, nota), 1)], threshold=1, min_mixers=2, **kw)
    with pytest.raises(ValueError):  # no NOTA
        build_manifest(constituencies=[Constituency("A", "A", (c,), 1)], threshold=1, **kw)
    with pytest.raises(ValueError):  # NOTA only
        build_manifest(constituencies=[Constituency("A", "A", (nota,), 1)], threshold=1, **kw)
    with pytest.raises(ValueError):  # threshold > n
        build_manifest(constituencies=[Constituency("A", "A", (c, nota), 1)], threshold=2, **kw)


# ===================================================================== identity and registration
def test_registration_only_when_accepting(tmp_path):
    e = Election(tmp_path, open_now=False)
    e.elig.set_accepting(False)
    assert rejected(lambda: e.registered(0)) == "NOT_ACCEPTING"


@pytest.mark.parametrize("method", ["aadhaar-otp", "aadhaar-face", "pan"])
def test_each_identity_method_registers(election, method):
    i = next(i for i, v in enumerate(election.roll) if v.pan_ref)
    d = election.registered(i, method)
    assert d.registration["generation"] == 1 and election.elig.known_tag(d.voter.constituency, to_hex(d.T))


def test_unknown_aadhaar(election):
    assert rejected(lambda: election.elig.aadhaar_otp_start("syn-uid-9999999")) == "AADHAAR_NOT_FOUND"


def test_aadhaar_holder_not_on_this_roll(tmp_path):
    """Valid identity, but not an elector here: authentication succeeds, registration does not."""
    e = Election(tmp_path)
    from chunaviq.election.roll import make_roll

    outsider = make_roll(e.cons[:1], start=9000, seed=1)[0]
    e.hub.uidai.enrol([outsider])
    txn = e.elig.aadhaar_otp_start(outsider.aadhaar_ref)
    assert rejected(lambda: e.elig.aadhaar_otp_finish(outsider.aadhaar_ref, txn, e.hub.phones.last(outsider.mobile_ref))) == "NOT_ON_ROLL"


def test_wrong_otp_and_lockout(election):
    v = election.roll[0]
    for _ in range(5):
        txn = election.elig.aadhaar_otp_start(v.aadhaar_ref)
        assert rejected(lambda txn=txn: election.elig.aadhaar_otp_finish(v.aadhaar_ref, txn, "000000")) in {"OTP_MISMATCH"}
    assert rejected(lambda: election.registered(0)) == "LOCKED"


def test_impostor_face_rejected(election):
    v = election.roll[0]
    assert rejected(lambda: election.elig.aadhaar_face(v.aadhaar_ref, live_capture(v.face, genuine=False))) == "FACE_MISMATCH"


def test_pan_alone_is_not_enough(election):
    """PAN verification only checks a number, a name and a birth date. Knowing those
    must not let someone register: the roll-mobile OTP and a face match are required."""
    v = next(v for v in election.roll if v.pan_ref)
    assert rejected(lambda: election.elig.pan_start(v.pan_ref, v.name, "1901-01-01")) == "PAN_MISMATCH"
    txn = election.elig.pan_start(v.pan_ref, v.name, v.dob)
    assert rejected(lambda: election.elig.pan_finish(v.pan_ref, txn, "000000", live_capture(v.face))) == "OTP_MISMATCH"
    txn = election.elig.pan_start(v.pan_ref, v.name, v.dob)
    otp = election.hub.phones.last(v.mobile_ref)
    assert rejected(lambda: election.elig.pan_finish(v.pan_ref, txn, otp, live_capture(v.face, genuine=False))) == "FACE_MISMATCH"


def test_aadhaar_and_pan_resolve_to_one_roll_entry(election):
    """Someone with both documents cannot register twice: the second registration
    replaces the first (generation 2), it does not add a voter."""
    i = next(i for i, v in enumerate(election.roll) if v.pan_ref)
    a = election.device(i)
    a.register(election.elig, "aadhaar-otp")
    b = election.device(i)
    reg = b.register(election.elig, "pan")
    assert reg["generation"] == 2
    summary = election.elig.registration_summary()["constituencies"][a.voter.constituency]
    assert summary["registered"] == 1 and summary["valid_tags"] == [to_hex(b.T)]


def test_reregistration_limit(election):
    d = election.device(0)
    for _ in range(6):
        d.register(election.elig, "aadhaar-otp")
    assert rejected(lambda: d.register(election.elig, "aadhaar-otp")) == "TOO_MANY_REGISTRATIONS"


def test_registration_proof_bound_to_session(election):
    """A tag proof captured from one registration cannot be replayed in another session."""
    d = election.device(0)
    s1 = d.authenticate(election.elig, "aadhaar-otp")
    t = election.grp.rand_scalar()
    T = election.grp.g_pow(t)
    proof = schnorr_prove(election.grp, t, T, register_context("SYN-TEST", d.voter.constituency, s1)).to_dict()
    s2 = d.authenticate(election.elig, "aadhaar-otp")
    assert rejected(lambda: election.elig.register(s2, to_hex(T), proof)) == "BAD_TAG_PROOF"


def test_tag_cannot_be_reused(election):
    d = election.registered(0)
    session = d.authenticate(election.elig, "aadhaar-otp")
    proof = schnorr_prove(election.grp, d.t, d.T, register_context("SYN-TEST", d.voter.constituency, session)).to_dict()
    assert rejected(lambda: election.elig.register(session, to_hex(d.T), proof)) == "TAG_REUSED"


def test_in_person_voter_cannot_register_again(election):
    d = election.registered(0)
    assert election.elig.mark_voted_in_person(d.voter.voter_id)
    assert rejected(lambda: d.register(election.elig, "aadhaar-otp")) == "VOTED_IN_PERSON"
    assert to_hex(d.T) not in election.elig.valid_tags(d.voter.constituency)


def test_participation_commitment_lets_voter_confirm_registration(election):
    d = election.registered(4)
    from chunaviq.election.eligibility import participation_commitment

    c = participation_commitment("SYN-TEST", d.voter.voter_id, bytes.fromhex(d.registration["participation_salt"]))
    s = election.elig.registration_summary()["constituencies"][d.voter.constituency]
    assert c == d.registration["commitment"] and c in s["commitments"]


# ===================================================================== ballots
def test_valid_ballot_accepted_with_verifiable_receipt(election):
    r = election.vote(0)
    election.board.checkpoint()
    receipt = election.board.receipt(r["seq"])
    assert receipt["tracking_code"] == r["tracking_code"] and r["revote"] == 1
    assert verify_receipt(election.record, receipt)
    forged = dict(receipt, tracking_code="00" * 32)
    assert not verify_receipt(election.record, forged)


def test_identical_retry_returns_original_receipt(election):
    d = election.registered(0)
    sub = election.sub(d, "C1")
    first = election.box.submit(sub)
    again = election.box.submit(sub)
    assert again == {"tracking_code": first["tracking_code"], "seq": first["seq"], "duplicate_submission": True}
    assert election.board.count("ballot") == 1
    election.clock.set(election.box.closes)  # even after polls close, the receipt is returned
    assert election.box.submit(sub)["seq"] == first["seq"]


def test_revote_is_accepted_and_numbered(election):
    d = election.registered(0)
    assert election.cast(d, "C1")["revote"] == 1
    assert election.cast(d, "C2")["revote"] == 2
    assert election.board.count("ballot") == 2


def test_revote_limit(tmp_path):
    e = Election(tmp_path, max_per_tag=2)
    d = e.registered(0)
    e.cast(d, "C1")
    e.cast(d, "C2")
    assert rejected(lambda: e.box.submit(e.sub(d, "C3"))) == "TOO_MANY_REVOTES"


def test_revoked_tag_is_still_accepted_while_voting(election):
    """A coercer holding the old tag must get the same answer as before re-registration."""
    d = election.registered(0)
    old_t, old_T = d.t, d.T
    d.register(election.elig, "aadhaar-otp")
    from chunaviq.election.ballot import encrypt_ballot as enc

    pb = enc(election.pk, election.mhash, "SYN-TEST", d.voter.constituency, d.option_ids, "C1", old_t)
    r = election.box.submit({"ballot": pb.ballot, "tag": to_hex(old_T), "link": make_link(election.pk, election.mhash, pb, old_T)})
    assert r["revote"] == 1


def test_unregistered_tag_rejected(election):
    d = election.device(0)
    d.t = election.grp.rand_scalar()
    d.T = election.grp.g_pow(d.t)
    assert rejected(lambda: election.box.submit(election.sub(d, "C1"))) == "UNREGISTERED_TAG"


def test_wrong_tag_link_rejected(election):
    d = election.registered(0)
    other = election.registered(1)
    sub = election.sub(d, "C1")
    sub["tag"] = to_hex(other.T)
    assert rejected(lambda: election.box.submit(sub)) == "BAD_TAG_LINK"


def test_ballot_copying_into_own_ballot_rejected(election):
    """Copying someone's encrypted selections into your own ballot would let you vote
    "the same as them". Selection proofs are bound to the ballot's tag ciphertext."""
    victim = election.registered(0)
    vs = election.sub(victim, "C2")
    election.box.submit(vs)
    attacker = election.registered(1)
    sub = election.sub(attacker, "C1")
    sub["ballot"]["selections"] = copy.deepcopy(vs["ballot"]["selections"])
    sub["ballot"]["limit_proof"] = vs["ballot"]["limit_proof"]
    assert rejected(lambda: election.box.submit(sub)) in {"BAD_SELECTION_PROOF", "DUPLICATE_CIPHERTEXT"}


def test_ballot_for_other_constituency_rejected(election):
    d = election.registered(0)  # constituency 1
    other = election.cons[1]
    pb = encrypt_ballot(election.pk, election.mhash, "SYN-TEST", other.id, other.option_ids, "C1", d.t)
    sub = {"ballot": pb.ballot, "tag": to_hex(d.T), "link": make_link(election.pk, election.mhash, pb, d.T)}
    assert rejected(lambda: election.box.submit(sub)) == "UNREGISTERED_TAG"


def test_wrong_ballot_style_rejected(election):
    d = election.registered(0)
    s1 = election.sub(d, "C1")
    s1["ballot"]["selections"] = s1["ballot"]["selections"][::-1]
    assert rejected(lambda: election.box.submit(s1)) == "WRONG_BALLOT_STYLE"
    s2 = election.sub(d, "C1")
    s2["ballot"]["selections"] = s2["ballot"]["selections"][:-1]  # drop NOTA
    assert rejected(lambda: election.box.submit(s2)) == "WRONG_BALLOT_STYLE"


def _with_selection_values(election, values):
    """A ballot whose selections encrypt `values`, each with a VALID 0/1 proof,
    and the original (now wrong) limit proof."""
    d = election.registered(0)
    sub = election.sub(d, "C1")
    b = sub["ballot"]
    ta = b["tag"]["ciphertext"]["alpha"]
    for j, m in enumerate(values):
        r = election.grp.rand_scalar()
        ct = election.pk.encrypt(m, r)
        oid = b["selections"][j]["option_id"]
        b["selections"][j]["ciphertext"] = ct.to_dict()
        b["selections"][j]["proof"] = disjunctive_prove(election.pk, ct, m, r, selection_context(election.mhash, b["constituency"], oid, ta)).to_dict()
    return sub


def test_overvote_rejected(election):
    assert rejected(lambda: election.box.submit(_with_selection_values(election, [1, 1, 0, 0]))) == "BAD_LIMIT_PROOF"


def test_blank_ballot_rejected(election):
    """Every ballot must make exactly one selection; abstention is expressed by
    not voting or by NOTA."""
    assert rejected(lambda: election.box.submit(_with_selection_values(election, [0, 0, 0, 0]))) == "BAD_LIMIT_PROOF"


def test_ciphertext_outside_subgroup_rejected(election):
    d = election.registered(0)
    sub = election.sub(d, "C1")
    ct = Ciphertext.from_dict(sub["ballot"]["selections"][0]["ciphertext"])
    sub["ballot"]["selections"][0]["ciphertext"] = Ciphertext(election.grp.p - ct.alpha, ct.beta).to_dict()
    assert rejected(lambda: election.box.submit(sub)) == "INVALID_CIPHERTEXT"


@pytest.mark.parametrize("where", ["ciphertext", "proof", "limit_proof", "tag", "top", "submission"])
def test_marked_ballot_rejected(election, where):
    """Regression (found by the fuzzer): a voter must not be able to embed a
    free-form marker in any part of the ballot to prove their vote to a buyer."""
    sub = election.sub(election.registered(0), "C1")
    b = sub["ballot"]
    target = {
        "ciphertext": b["selections"][0]["ciphertext"],
        "proof": b["selections"][0]["proof"],
        "limit_proof": b["limit_proof"],
        "tag": b["tag"],
        "top": b,
        "submission": sub,
    }[where]
    target["marker"] = "voter-1234"
    assert rejected(lambda: election.box.submit(sub)) == "MALFORMED"


def test_rejections_are_counted_without_identity(election):
    d = election.registered(0)
    sub = election.sub(d, "C1")
    sub["tag"] = to_hex(election.registered(1).T)
    for _ in range(3):
        with pytest.raises(BallotRejected):
            election.box.submit(sub)
    assert election.box.rejections["BAD_TAG_LINK"] == 3


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
        e._fuzz_base = e.sub(e.registered(0), "C2")["ballot"]
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
