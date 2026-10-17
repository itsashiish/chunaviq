"""Threshold key custody, blind credentials and the Merkle log."""

import itertools

import pytest
from hypothesis import given
from hypothesis import strategies as st

from chunaviq.crypto.blind import RSABlindSigner, blind, credential_message, unblind
from chunaviq.crypto.elgamal import PublicKey, add, dlog_bounded
from chunaviq.crypto.group import get_group
from chunaviq.crypto.merkle import (
    MerkleTree,
    consistency_proof,
    leaf_hash,
    mth,
    reference_path,
    verify_consistency,
    verify_inclusion,
)
from chunaviq.crypto.threshold import (
    CeremonyError,
    Trustee,
    combine,
    joint_public_key,
    public_share,
    run_ceremony,
    verify_decryption_share,
)

G = get_group("CHUNAVIQ-2048-256-V1")


@pytest.fixture(scope="module")
def ceremony():
    trustees, comms = run_ceremony(G, 5, 3, "mh")
    pk = PublicKey(G, joint_public_key(G, comms))
    votes = [1, 0, 1, 1, 0, 1, 0]
    agg = add(G, [pk.encrypt(m, G.rand_scalar()) for m in votes])
    return trustees, comms, pk, agg, sum(votes)


def test_every_k_subset_decrypts(ceremony):
    trustees, comms, pk, agg, total = ceremony
    for subset in itertools.combinations(trustees, 3):
        shares = {}
        for t in subset:
            M, pr = t.decryption_share(agg, ["x"])
            assert verify_decryption_share(G, agg, public_share(G, comms, t.index), M, pr, ["x"])
            shares[t.index] = M
        assert dlog_bounded(G, combine(G, agg, shares), 10) == total


def test_fewer_than_k_cannot_decrypt(ceremony):
    trustees, comms, pk, agg, total = ceremony
    for subset in itertools.combinations(trustees, 2):
        shares = {t.index: t.decryption_share(agg, ["x"])[0] for t in subset}
        with pytest.raises(ValueError):
            dlog_bounded(G, combine(G, agg, shares), 50)


def test_public_shares_match_secret_shares(ceremony):
    trustees, comms, *_ = ceremony
    for t in trustees:
        assert public_share(G, comms, t.index) == G.g_pow(t.secret_share)


def test_no_trustee_holds_the_joint_secret(ceremony):
    trustees, comms, pk, *_ = ceremony
    assert all(G.g_pow(t.secret_share) != pk.K for t in trustees)
    assert all(t._coeffs == [] for t in trustees)  # coefficients destroyed after the ceremony


def test_bad_share_is_detected():
    a, b = Trustee(1, G, 2, "mh"), Trustee(2, G, 2, "mh")
    with pytest.raises(CeremonyError):
        b.receive_share(a.commitment(), (a.share_for(2) + 1) % G.q)


def test_forged_decryption_share_rejected(ceremony):
    trustees, comms, pk, agg, _ = ceremony
    t = trustees[0]
    M, pr = t.decryption_share(agg, ["x"])
    Ki = public_share(G, comms, t.index)
    assert not verify_decryption_share(G, agg, Ki, M * G.g % G.p, pr, ["x"])
    assert not verify_decryption_share(G, agg, Ki, M, pr, ["y"])
    assert not verify_decryption_share(G, agg, public_share(G, comms, 2), M, pr, ["x"])


# ------------------------------------------------------------------ blind credentials
@pytest.fixture(scope="module")
def signer():
    return RSABlindSigner(2048)


def test_blind_signature_roundtrip(signer):
    msg = credential_message("E", "C1", b"\x07" * 32)
    blinded, state = blind(signer.public, msg)
    sig = unblind(signer.public, state, signer.sign_blinded(blinded))
    assert signer.public.verify(msg, sig)
    assert not signer.public.verify(credential_message("E", "C2", b"\x07" * 32), sig)  # bound to constituency
    assert not signer.public.verify(credential_message("E2", "C1", b"\x07" * 32), sig)  # bound to election
    assert not signer.public.verify(msg, sig + 1)


def test_issuer_sees_only_blinded_value(signer):
    msg = credential_message("E", "C1", b"\x01" * 32)
    blinded, state = blind(signer.public, msg)
    bsig = signer.sign_blinded(blinded)
    sig = unblind(signer.public, state, bsig)
    from chunaviq.crypto.blind import fdh

    assert blinded != fdh(signer.public.n, msg) and bsig != sig  # issuer's view differs from the credential


def test_two_blindings_of_same_message_differ(signer):
    msg = credential_message("E", "C1", b"\x02" * 32)
    assert blind(signer.public, msg)[0] != blind(signer.public, msg)[0]


def test_sign_blinded_range(signer):
    with pytest.raises(ValueError):
        signer.sign_blinded(0)
    with pytest.raises(ValueError):
        signer.sign_blinded(signer.public.n)


def test_token_length_enforced():
    with pytest.raises(ValueError):
        credential_message("E", "C", b"short")


# ------------------------------------------------------------------ Merkle
@given(st.integers(min_value=1, max_value=70))
def test_incremental_tree_matches_rfc6962_reference(n):
    data = [i.to_bytes(2, "big") for i in range(n)]
    t = MerkleTree()
    for d in data:
        t.append(d)
    leaves = [leaf_hash(d) for d in data]
    assert t.root() == mth(leaves)
    for i in range(n):
        p = t.inclusion_proof(i)
        assert p == reference_path(i, leaves)
        assert verify_inclusion(leaves[i], i, n, p, t.root())


@given(st.integers(min_value=1, max_value=60), st.data())
def test_consistency_proofs(n, data):
    m = data.draw(st.integers(min_value=1, max_value=n))
    leaves = [leaf_hash(i.to_bytes(2, "big")) for i in range(n)]
    proof = consistency_proof(leaves, m)
    assert verify_consistency(m, n, mth(leaves[:m]), mth(leaves), proof)
    if m < n:
        forked = list(leaves)
        forked[m - 1] = leaf_hash(b"rewritten history")
        assert not verify_consistency(m, n, mth(leaves[:m]), mth(forked), consistency_proof(forked, m))


def test_inclusion_rejects_wrong_leaf_or_index():
    t = MerkleTree()
    for i in range(9):
        t.append(bytes([i]))
    p = t.inclusion_proof(4)
    assert not verify_inclusion(leaf_hash(b"x"), 4, 9, p, t.root())
    assert not verify_inclusion(leaf_hash(bytes([4])), 5, 9, p, t.root())
    assert not verify_inclusion(leaf_hash(bytes([4])), 9, 9, p, t.root())
