"""Protocol v2 proofs: Sigma/OR proofs and the verifiable shuffle.

Each property is checked against BOTH the election package's prover/verifier
and the independent verifier's re-implementation (chunaviq_verify.vsigma).
"""

import random

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from chunaviq.crypto import sigma
from chunaviq.crypto.elgamal import PublicKey
from chunaviq.crypto.group import get_group
from chunaviq.crypto.shuffle import shuffle_and_prove, verify_shuffle
from chunaviq_verify import vsigma
from chunaviq_verify.vmath import G as VG

GRP = get_group("TEST-INSECURE-512-160")
SECURE = get_group("CHUNAVIQ-2048-256-V1")


def _key(grp):
    s = grp.rand_scalar()
    return s, PublicKey(grp, grp.g_pow(s))


def _fast(pk):
    return {pk.group.g: pk.group.g_pow, pk.K: pk.k_pow}


def _vg(grp):
    return VG(grp.p, grp.q, grp.g)


def _enc(pk, m):
    r = pk.group.rand_scalar()
    return (pk.group.g_pow(r), pk.group.g_pow(m) * pk.k_pow(r) % pk.group.p), r


# ------------------------------------------------------------------ tag proof
@pytest.mark.parametrize("grp", [GRP, SECURE], ids=["test", "secure"])
def test_tag_proof_complete_sound_and_bound(grp):
    _, pk = _key(grp)
    t, r = grp.rand_scalar(), grp.rand_scalar()
    a, b = grp.g_pow(r), grp.g_pow(t) * pk.k_pow(r) % grp.p
    st_ = sigma.tag_statement(grp, pk.K, a, b)
    pr = sigma.prove(grp, st_, [r, t], "ballot-tag", ["ctx"], _fast(pk))
    assert sigma.verify(grp, st_, pr, "ballot-tag", ["ctx"], _fast(pk))
    assert vsigma.sigma_ok(_vg(grp), vsigma.tag_eqs(_vg(grp), pk.K, a, b), 2, pr, "ballot-tag", ["ctx"])
    # someone who knows T but not t (the ballot box) cannot produce one
    fake = sigma.prove(grp, st_, [r, grp.rand_scalar()], "ballot-tag", ["ctx"], _fast(pk))
    assert not sigma.verify(grp, st_, fake, "ballot-tag", ["ctx"], _fast(pk))
    assert not vsigma.sigma_ok(_vg(grp), vsigma.tag_eqs(_vg(grp), pk.K, a, b), 2, fake, "ballot-tag", ["ctx"])
    # bound to context and to the ciphertext
    assert not sigma.verify(grp, st_, pr, "ballot-tag", ["other"], _fast(pk))
    assert not sigma.verify(grp, sigma.tag_statement(grp, pk.K, a, b * grp.g % grp.p), pr, "ballot-tag", ["ctx"], _fast(pk))


@pytest.mark.parametrize("field", ["c", "s0", "s1"])
def test_tag_proof_rejects_any_tampered_field(field):
    _, pk = _key(GRP)
    t, r = GRP.rand_scalar(), GRP.rand_scalar()
    a, b = GRP.g_pow(r), GRP.g_pow(t) * pk.k_pow(r) % GRP.p
    st_ = sigma.tag_statement(GRP, pk.K, a, b)
    pr = sigma.prove(GRP, st_, [r, t], "d", [], _fast(pk))
    bad = {"c": pr["c"], "s": list(pr["s"])}
    if field == "c":
        bad["c"] = format((int(pr["c"], 16) + 1) % GRP.q, "x")
    else:
        i = int(field[1])
        bad["s"][i] = format((int(pr["s"][i], 16) + 1) % GRP.q, "x")
    assert not sigma.verify(GRP, st_, bad, "d", [], _fast(pk))
    assert not vsigma.sigma_ok(_vg(GRP), vsigma.tag_eqs(_vg(GRP), pk.K, a, b), 2, bad, "d", [])


def test_tag_proof_rejects_malformed_inputs():
    _, pk = _key(GRP)
    st_ = sigma.tag_statement(GRP, pk.K, GRP.g, GRP.g)
    for bad in ({}, {"c": "1"}, {"c": "1", "s": ["1"]}, {"c": "zz", "s": ["1", "1"]}, {"c": "1", "s": ["1", "1"], "x": 1}):
        assert not sigma.verify(GRP, st_, bad, "d", [])
        assert not vsigma.sigma_ok(_vg(GRP), vsigma.tag_eqs(_vg(GRP), pk.K, GRP.g, GRP.g), 2, bad, "d", [])


# ------------------------------------------------------------------ finalization OR-proof
def _finalization(pk, f, L=4, vote=1):
    grp = pk.group
    votes = [_enc(pk, 1 if j == vote else 0)[0] for j in range(L)]
    u = grp.rand_scalar()
    F = (grp.g_pow(u), grp.g_pow(f) * pk.k_pow(u) % grp.p)
    ws = [grp.rand_scalar() for _ in range(L)]
    masked = [((va if f else 1) * grp.g_pow(w) % grp.p, (vb if f else 1) * pk.k_pow(w) % grp.p) for (va, vb), w in zip(votes, ws, strict=True)]
    return votes, F, masked, u, ws


@pytest.mark.parametrize("f", [0, 1])
def test_finalization_proof_both_branches(f):
    s, pk = _key(GRP)
    votes, F, masked, u, ws = _finalization(pk, f)
    br = sigma.finalize_branches(GRP, pk.K, F, votes, masked)
    pr = sigma.prove_or(GRP, br, f, [u, *ws], "finalize", ["c"], _fast(pk))
    assert sigma.verify_or(GRP, br, pr, "finalize", ["c"], _fast(pk))
    assert vsigma.sigma_or_ok(_vg(GRP), vsigma.finalize_branches(_vg(GRP), pk.K, F, votes, masked), pr, "finalize", ["c"])
    # the masked vote decrypts to the vote when f = 1 and to zero when f = 0
    dec = [mb * pow(pow(ma, s, GRP.p), -1, GRP.p) % GRP.p for ma, mb in masked]
    want = [GRP.g_pow(1 if (f and j == 1) else 0) for j in range(len(masked))]
    assert dec == want


def test_finalization_cannot_count_a_ballot_with_flag_zero():
    """The ballot box cannot publish flag 0 (so the mix shows the ballot as not counted)
    while slipping the real vote into the masked total."""
    _, pk = _key(GRP)
    votes, _, masked1, _, ws = _finalization(pk, 1)
    u = GRP.rand_scalar()
    F0 = (GRP.g_pow(u), pk.k_pow(u))  # flag encrypts 0
    br = sigma.finalize_branches(GRP, pk.K, F0, votes, masked1)
    for real, w in ((0, [u, *ws]), (1, [u, *ws])):
        pr = sigma.prove_or(GRP, br, real, w, "finalize", ["c"], _fast(pk))
        assert not sigma.verify_or(GRP, br, pr, "finalize", ["c"], _fast(pk))
        assert not vsigma.sigma_or_ok(_vg(GRP), vsigma.finalize_branches(_vg(GRP), pk.K, F0, votes, masked1), pr, "finalize", ["c"])


def test_finalization_cannot_change_the_vote():
    _, pk = _key(GRP)
    votes, F, masked, u, ws = _finalization(pk, 1, vote=1)
    other = _finalization(pk, 1, vote=2)[0]  # a different vote
    br = sigma.finalize_branches(GRP, pk.K, F, other, masked)
    pr = sigma.prove_or(GRP, br, 1, [u, *ws], "finalize", ["c"], _fast(pk))
    assert not sigma.verify_or(GRP, br, pr, "finalize", ["c"], _fast(pk))


def test_designated_verifier_proof_convinces_only_the_voter():
    _, pk = _key(GRP)
    t = GRP.rand_scalar()
    T = GRP.g_pow(t)
    u = GRP.rand_scalar()
    F1 = (GRP.g_pow(u), GRP.g * pk.k_pow(u) % GRP.p)  # counted
    F0 = (GRP.g_pow(u), pk.k_pow(u))  # not counted
    real = sigma.prove_or(GRP, sigma.dv_branches(GRP, pk.K, F1, T), 0, [u], "dv-final", ["x"], _fast(pk))
    assert sigma.verify_or(GRP, sigma.dv_branches(GRP, pk.K, F1, T), real, "dv-final", ["x"], _fast(pk))
    # the ballot box cannot claim an uncounted ballot counts ...
    lie = sigma.prove_or(GRP, sigma.dv_branches(GRP, pk.K, F0, T), 0, [u], "dv-final", ["x"], _fast(pk))
    assert not sigma.verify_or(GRP, sigma.dv_branches(GRP, pk.K, F0, T), lie, "dv-final", ["x"], _fast(pk))
    # ... but the voter (who knows t) can, so the proof is worthless as evidence for a coercer
    fake = sigma.prove_or(GRP, sigma.dv_branches(GRP, pk.K, F0, T), 1, [t], "dv-final", ["x"], _fast(pk))
    assert sigma.verify_or(GRP, sigma.dv_branches(GRP, pk.K, F0, T), fake, "dv-final", ["x"], _fast(pk))


# ------------------------------------------------------------------ shuffle
def _rows(pk, n, w=2):
    return [[_enc(pk, random.randrange(3))[0] for _ in range(w)] for _ in range(n)]


def _dec(s, ct):
    return ct[1] * pow(pow(ct[0], s, GRP.p), -1, GRP.p) % GRP.p


@settings(max_examples=15, deadline=None)
@given(st.integers(min_value=1, max_value=24), st.integers(min_value=1, max_value=3))
def test_shuffle_complete_and_preserves_plaintexts(n, w):
    s, pk = _key(GRP)
    rows = _rows(pk, n, w)
    out, proof = shuffle_and_prove(GRP, pk.K, rows, ["ctx"], pk.k_pow)
    assert verify_shuffle(GRP, pk.K, rows, out, proof, ["ctx"], pk.k_pow)
    assert vsigma.shuffle_ok(_vg(GRP), pk.K, rows, out, proof, ["ctx"])
    assert sorted(tuple(_dec(s, c) for c in r) for r in rows) == sorted(tuple(_dec(s, c) for c in r) for r in out)
    if n > 1:
        assert all(o != i for o, i in zip(out, rows, strict=True))  # every ciphertext re-randomised


@pytest.mark.parametrize(
    "attack",
    ["replace_row", "duplicate_row", "drop_and_add", "swap_columns", "wrong_context", "tamper_response", "tamper_commitment", "reuse_proof_other_input"],
)
def test_shuffle_soundness(attack):
    s, pk = _key(GRP)
    rows = _rows(pk, 8)
    out, proof = shuffle_and_prove(GRP, pk.K, rows, ["ctx"], pk.k_pow)
    ctx = ["ctx"]
    out = [list(r) for r in out]
    proof = {k: (list(v) if isinstance(v, list) else v) for k, v in proof.items()}
    if attack == "replace_row":
        out[0] = [_enc(pk, 1)[0], _enc(pk, 1)[0]]
    elif attack == "duplicate_row":
        out[0] = list(out[1])
    elif attack == "drop_and_add":
        out[3][0] = (out[3][0][0], out[3][0][1] * GRP.g % GRP.p)
    elif attack == "swap_columns":
        out[2] = [out[2][1], out[2][0]]
    elif attack == "wrong_context":
        ctx = ["other"]
    elif attack == "tamper_response":
        proof["sprime"][0] = format((int(proof["sprime"][0], 16) + 1) % GRP.q, "x")
    elif attack == "tamper_commitment":
        proof["commitments"][0] = format(int(proof["commitments"][0], 16) * GRP.g % GRP.p, "x")
    elif attack == "reuse_proof_other_input":
        rows = _rows(pk, 8)
    assert not verify_shuffle(GRP, pk.K, rows, out, proof, ctx, pk.k_pow)
    assert not vsigma.shuffle_ok(_vg(GRP), pk.K, rows, out, proof, ctx)


def test_shuffle_secure_group():
    _, pk = _key(SECURE)
    rows = [[_enc(pk, 0)[0], _enc(pk, 1)[0]] for _ in range(6)]
    out, proof = shuffle_and_prove(SECURE, pk.K, rows, ["s"], pk.k_pow)
    assert verify_shuffle(SECURE, pk.K, rows, out, proof, ["s"], pk.k_pow)
    assert vsigma.shuffle_ok(_vg(SECURE), pk.K, rows, out, proof, ["s"])


def test_shuffle_generators_match_and_are_independent_of_g():
    from chunaviq.crypto.shuffle import generators

    a = generators(GRP, 10)
    b = vsigma.generators(_vg(GRP), 10)
    assert a == b and len(set(a)) == 11 and GRP.g not in a and all(GRP.is_element(h) for h in a)
