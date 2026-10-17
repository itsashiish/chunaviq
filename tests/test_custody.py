"""Trustee HSM applet: one share per trustee, used only under policy."""

import pytest

from chunaviq.crypto.elgamal import PublicKey, add, dlog_bounded
from chunaviq.crypto.group import get_group
from chunaviq.crypto.signing import RoleKey
from chunaviq.crypto.threshold import TrusteeCommitment, combine, joint_public_key
from chunaviq.custody import CustodyError, CustodyPolicy, TrusteeApplet, hsm_kek, request_hash, verify_audit_log
from chunaviq.election.administration import Observer, TrusteeHost, run_hsm_ceremony

G = get_group("TEST-INSECURE-512-160")


@pytest.fixture
def setup():
    officer = RoleKey("officer")
    observers = [Observer() for _ in range(3)]
    hosts = [TrusteeHost(i + 1, G, 2) for i in range(3)]
    for h in hosts:
        h.install(CustodyPolicy(["E1", "E2"], [officer.public_hex], h.operator_keys, 2, [o.key.public_hex for o in observers], 2, 20))
    comms = run_hsm_ceremony(hosts, "national-hash", 2)
    pk = PublicKey(G, joint_public_key(G, comms))
    closed = officer.sign_body({"election_id": "E1", "state": "CLOSED"})
    return officer, observers, hosts, comms, pk, closed


def _request(pk, closed, purpose="aggregate", n=3, nonce="n1", eid="E1"):
    agg = add(G, [pk.encrypt(1, G.rand_scalar()) for _ in range(n)])
    return agg, {
        "election_id": eid,
        "purpose": purpose,
        "closed": closed,
        "record_root": "00",
        "items": [{"ciphertext": agg.to_dict(), "context": ["c"]}],
        "nonce": nonce,
    }


def _att(observers, req, k=2):
    return [o.attest(req, True) for o in observers[:k]]


def test_ceremony_in_hsms_gives_one_share_each_and_decrypts_totals(setup):
    _, observers, hosts, comms, pk, closed = setup
    agg, req = _request(pk, closed, n=5)
    shares = {}
    for h in hosts[:2]:
        res = h.applet.decrypt(req, h.approve(req), _att(observers, req))
        shares[h.index] = int(res["shares"][0]["share"], 16)
    assert dlog_bounded(G, combine(G, agg, shares), 10) == 5
    assert all(len([k for k in vars(h.applet._s) if k == "share"]) == 1 for h in hosts)  # exactly one share per HSM


def test_share_never_leaves_in_plaintext(setup):
    _, _, hosts, comms, _, _ = setup
    blob = hosts[0].applet.seal(hsm_kek())
    share_hex = format(hosts[0].applet._s.share, "x")
    assert share_hex.encode() not in blob


@pytest.mark.parametrize(
    "case,code",
    [
        ("open_election", "ELECTION_NOT_CLOSED"),
        ("forged_close", "ELECTION_NOT_CLOSED"),
        ("one_operator", "OPERATOR_QUORUM_MISSING"),
        ("one_observer", "OBSERVER_QUORUM_MISSING"),
        ("outsider_observers", "OBSERVER_QUORUM_MISSING"),
        ("wrong_purpose", "PURPOSE_NOT_ALLOWED"),
        ("wrong_election", "WRONG_ELECTION"),
        ("replay", "REPLAYED_REQUEST"),
        ("budget", "BUDGET_EXHAUSTED"),
        ("approval_for_other_request", "OPERATOR_QUORUM_MISSING"),
    ],
)
def test_policy_refusals(setup, case, code):
    officer, observers, hosts, _, pk, closed = setup
    h = hosts[0]
    agg, req = _request(pk, closed)
    appr, att = h.approve(req), _att(observers, req)
    if case == "open_election":
        req["closed"] = officer.sign_body({"election_id": "E1", "state": "OPEN"})
        appr, att = h.approve(req), _att(observers, req)
    elif case == "forged_close":
        req["closed"] = RoleKey("officer").sign_body({"election_id": "E1", "state": "CLOSED"})
        appr, att = h.approve(req), _att(observers, req)
    elif case == "one_operator":
        appr = appr[:1]
    elif case == "one_observer":
        att = att[:1]
    elif case == "outsider_observers":
        att = [Observer().attest(req, True) for _ in range(2)]
    elif case == "wrong_purpose":
        req["purpose"] = "single-ballot"
        appr, att = h.approve(req), _att(observers, req)
    elif case == "wrong_election":
        _, req = _request(pk, closed, eid="E9")
        appr, att = h.approve(req), _att(observers, req)
    elif case == "replay":
        h.applet.decrypt(req, appr, att)
    elif case == "budget":
        req["items"] = req["items"] * 21
        appr, att = h.approve(req), _att(observers, req)
    elif case == "approval_for_other_request":
        _, other = _request(pk, closed, nonce="n2")
        appr = h.approve(other)
    with pytest.raises(CustodyError) as ei:
        h.applet.decrypt(req, appr, att)
    assert ei.value.code == code


def test_observer_refuses_when_its_check_fails(setup):
    _, observers, _, _, pk, closed = setup
    _, req = _request(pk, closed)
    with pytest.raises(Exception, match="observer refuses"):
        observers[0].attest(req, False)


def test_audit_log_is_chained_signed_and_published(setup):
    _, observers, hosts, _, pk, closed = setup
    h = hosts[0]
    _, req = _request(pk, closed)
    h.applet.decrypt(req, h.approve(req), _att(observers, req))
    log = h.applet.audit_log()
    assert [r["op"] for r in log] == ["ceremony-begin", "ceremony-finish", "decrypt"]
    assert log[-1]["request"] == request_hash(req)
    assert verify_audit_log(log, h.applet.attestation_key())
    log[1]["op"] = "edited"
    assert not verify_audit_log(log, h.applet.attestation_key())


def test_seal_unseal_and_clone_to_backup_hsm(setup):
    _, observers, hosts, _, pk, closed = setup
    h = hosts[0]
    kek = hsm_kek()
    restored = TrusteeApplet.unseal(h.applet.seal(kek), kek)
    assert restored.attestation_key() == h.applet.attestation_key() and restored._s.share == h.applet._s.share
    with pytest.raises(Exception):
        TrusteeApplet.unseal(h.applet.seal(kek), hsm_kek())  # wrong storage key
    backup = TrusteeApplet(1, G.name, 2, h.applet.policy)
    with pytest.raises(CustodyError):
        h.applet.export_clone(backup.transport_key(), [h.operators[0].sign_body({"approve": "clone:" + backup.transport_key()})])  # one card is not a quorum
    approvals = [o.sign_body({"approve": "clone:" + backup.transport_key()}) for o in h.operators[:2]]
    clone = TrusteeApplet.import_clone(h.applet.export_clone(backup.transport_key(), approvals), backup)
    assert clone._s.share == h.applet._s.share
    _, req = _request(pk, closed, nonce="clone-test")
    assert clone.decrypt(req, h.approve(req), _att(observers, req))["shares"]


def test_feldman_check_inside_hsm_rejects_bad_share():
    observers = [Observer() for _ in range(3)]
    hosts = [TrusteeHost(i + 1, G, 2) for i in range(3)]
    for h in hosts:
        h.install(CustodyPolicy(["E"], [], h.operator_keys, 2, [o.key.public_hex for o in observers], 2, 1))
    comms = [TrusteeCommitment.from_dict(h.applet.begin_ceremony("x")) for h in hosts]
    sealed = hosts[0].applet.share_for(2, hosts[2].applet.transport_key())  # share meant for trustee 2 ...
    with pytest.raises(Exception):  # ... delivered to trustee 3: decryption or Feldman check fails
        hosts[2].applet.receive_share(1, comms[0].to_dict(), sealed)
