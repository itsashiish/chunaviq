"""Group, encoding, ElGamal and zero-knowledge proof correctness and soundness."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from chunaviq.crypto.elgamal import Ciphertext, PublicKey, add, dlog_bounded
from chunaviq.crypto.encoding import _encode_item, from_hex, hash_to_scalar, to_hex
from chunaviq.crypto.group import FixedBase, get_group
from chunaviq.crypto.primes import is_probable_prime
from chunaviq.crypto.proofs import (
    ChaumPedersenProof,
    DisjunctiveProof,
    SchnorrProof,
    cp_prove,
    cp_verify,
    disjunctive_prove,
    disjunctive_verify,
    schnorr_prove,
    schnorr_verify,
)

SECURE = get_group("CHUNAVIQ-2048-256-V1")
TEST = get_group("TEST-INSECURE-512-160")


# ------------------------------------------------------------------ group
@pytest.mark.parametrize("grp", [SECURE, TEST], ids=["secure", "test"])
def test_group_parameters_are_sound(grp):
    assert is_probable_prime(grp.p) and is_probable_prime(grp.q)
    assert (grp.p - 1) % grp.q == 0
    assert grp.g != 1 and pow(grp.g, grp.q, grp.p) == 1


def test_secure_group_sizes():
    assert SECURE.p.bit_length() == 2048 and SECURE.q.bit_length() == 256 and SECURE.secure
    assert not TEST.secure


@pytest.mark.parametrize("bad", [0, 1 - 1, -1, "5", True, None])
def test_is_element_rejects_non_integers_and_zero(bad):
    assert not SECURE.is_element(bad)


def test_is_element_rejects_small_order_and_out_of_range():
    p = SECURE.p
    assert not SECURE.is_element(p - 1)  # order 2: would leak a bit if accepted
    assert not SECURE.is_element(p)
    assert not SECURE.is_element(p + 1)
    assert not SECURE.is_element(2)  # generates (almost certainly) the full group, not the q-subgroup
    assert SECURE.is_element(SECURE.g) and SECURE.is_element(1)


@given(st.integers(min_value=0, max_value=TEST.q - 1))
def test_fixed_base_matches_builtin_pow(e):
    fb = FixedBase(TEST.g, TEST.p, TEST.q.bit_length())
    assert fb.pow(e) == pow(TEST.g, e, TEST.p)


def test_fixed_base_secure_group_and_range_check():
    e = SECURE.rand_scalar()
    assert SECURE.g_pow(e) == pow(SECURE.g, e, SECURE.p)
    with pytest.raises(ValueError):
        FixedBase(SECURE.g, SECURE.p, 256).pow(1 << 300)


# ------------------------------------------------------------------ encoding
items = st.recursive(st.integers(min_value=0, max_value=2**300) | st.text(max_size=8), lambda c: st.lists(c, max_size=4), max_leaves=8)


@given(st.lists(items, max_size=4), st.lists(items, max_size=4))
def test_hash_encoding_is_injective(a, b):
    if a != b:
        assert _encode_item(a) != _encode_item(b)


def test_hash_domain_separation():
    assert hash_to_scalar(SECURE.q, "a", 1, 2) != hash_to_scalar(SECURE.q, "b", 1, 2)
    assert hash_to_scalar(SECURE.q, "a", "12") != hash_to_scalar(SECURE.q, "a", 12)


@pytest.mark.parametrize("s", ["", "0a", "A", "-1", "0x1", " 1", "g"])
def test_from_hex_rejects_non_canonical(s):
    with pytest.raises(ValueError):
        from_hex(s)


@given(st.integers(min_value=0, max_value=2**2048))
def test_hex_roundtrip(x):
    assert from_hex(to_hex(x)) == x


# ------------------------------------------------------------------ ElGamal
def _pk(grp):
    return PublicKey(grp, grp.g_pow(grp.rand_scalar()))


def test_public_key_must_be_group_element():
    with pytest.raises(ValueError):
        PublicKey(SECURE, SECURE.p - 1)
    with pytest.raises(ValueError):
        PublicKey(SECURE, 1)


@given(st.lists(st.integers(min_value=0, max_value=1), min_size=1, max_size=25))
def test_homomorphic_addition(ms):
    grp = TEST
    s = grp.rand_scalar()
    pk = PublicKey(grp, grp.g_pow(s))
    agg = add(grp, [pk.encrypt(m, grp.rand_scalar()) for m in ms])
    gm = grp.div(agg.beta, grp.pow(agg.alpha, s))
    assert dlog_bounded(grp, gm, len(ms)) == sum(ms)


def test_dlog_out_of_range_raises():
    with pytest.raises(ValueError):
        dlog_bounded(TEST, TEST.g_pow(10), 5)


def test_encryption_is_randomised():
    pk = _pk(SECURE)
    assert pk.encrypt(1, SECURE.rand_scalar()) != pk.encrypt(1, SECURE.rand_scalar())


# ------------------------------------------------------------------ 0/1 proof
@pytest.mark.parametrize("m", [0, 1])
def test_disjunctive_complete(m):
    pk = _pk(SECURE)
    r = SECURE.rand_scalar()
    ct = pk.encrypt(m, r)
    assert disjunctive_verify(pk, ct, disjunctive_prove(pk, ct, m, r, ["ctx"]), ["ctx"])


def test_disjunctive_refuses_to_prove_non_binary():
    pk = _pk(SECURE)
    with pytest.raises(ValueError):
        disjunctive_prove(pk, pk.encrypt(2, 5), 2, 5, [])


def test_disjunctive_cannot_be_reused_for_another_plaintext():
    """A proof for an encryption of 1 does not transfer to an encryption of 2."""
    pk = _pk(SECURE)
    r = SECURE.rand_scalar()
    pr = disjunctive_prove(pk, pk.encrypt(1, r), 1, r, ["c"])
    assert not disjunctive_verify(pk, pk.encrypt(2, r), pr, ["c"])


@pytest.mark.parametrize("field", ["a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1"])
def test_disjunctive_rejects_any_tampered_field(field):
    pk = _pk(SECURE)
    r = SECURE.rand_scalar()
    ct = pk.encrypt(1, r)
    d = disjunctive_prove(pk, ct, 1, r, ["c"]).to_dict()
    d[field] = to_hex((from_hex(d[field]) + 1) % SECURE.q)
    assert not disjunctive_verify(pk, ct, DisjunctiveProof.from_dict(d), ["c"])


def test_disjunctive_bound_to_context_key_and_ciphertext():
    pk, pk2 = _pk(SECURE), _pk(SECURE)
    r = SECURE.rand_scalar()
    ct = pk.encrypt(0, r)
    pr = disjunctive_prove(pk, ct, 0, r, ["c"])
    assert not disjunctive_verify(pk, ct, pr, ["other"])
    assert not disjunctive_verify(pk2, ct, pr, ["c"])
    assert not disjunctive_verify(pk, Ciphertext(ct.alpha, ct.beta * SECURE.g % SECURE.p), pr, ["c"])


def test_disjunctive_rejects_small_order_ciphertext():
    pk = _pk(SECURE)
    r = SECURE.rand_scalar()
    ct = pk.encrypt(0, r)
    pr = disjunctive_prove(pk, ct, 0, r, ["c"])
    neg = Ciphertext(SECURE.p - ct.alpha, ct.beta)  # alpha * (-1): leaves the subgroup
    assert not disjunctive_verify(pk, neg, pr, ["c"])


# ------------------------------------------------------------------ Schnorr / CP
def test_schnorr():
    x = SECURE.rand_scalar()
    X = SECURE.g_pow(x)
    pr = schnorr_prove(SECURE, x, X, ["k"])
    assert schnorr_verify(SECURE, X, pr, ["k"])
    assert not schnorr_verify(SECURE, X, pr, ["k2"])
    assert not schnorr_verify(SECURE, SECURE.g_pow(x + 1), pr, ["k"])
    assert not schnorr_verify(SECURE, X, SchnorrProof(pr.commitment, (pr.response + 1) % SECURE.q), ["k"])


def test_chaum_pedersen():
    x = SECURE.rand_scalar()
    H = SECURE.g_pow(SECURE.rand_scalar())
    X, Y = SECURE.g_pow(x), SECURE.pow(H, x)
    pr = cp_prove(SECURE, x, H, X, Y, "d", ["c"])
    assert cp_verify(SECURE, H, X, Y, pr, "d", ["c"])
    assert not cp_verify(SECURE, H, X, Y * SECURE.g % SECURE.p, pr, "d", ["c"])
    assert not cp_verify(SECURE, H, X, Y, pr, "other-domain", ["c"])
    # Y negated has a small-order component; must be rejected even if c is even.
    assert not cp_verify(SECURE, H, X, SECURE.p - Y, pr, "d", ["c"])
    assert not cp_verify(SECURE, H, X, Y, ChaumPedersenProof(pr.a, pr.b, SECURE.q), "d", ["c"])
