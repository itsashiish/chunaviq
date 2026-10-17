"""Verifiable re-encryption shuffle (mix-net step) with a Terelius-Wikstrom proof.

A mixer takes N rows of w ElGamal ciphertexts, re-encrypts every ciphertext
with fresh randomness and outputs the rows in a secret random order. The
proof shows the output is a re-encrypted permutation of the input without
revealing the permutation. If at least one mixer in a chain keeps its
permutation secret, nobody can link an output row to an input row.

Proof of shuffle: Terelius & Wikstrom, "Proofs of Restricted Shuffles"
(AFRICACRYPT 2010), in the form specified by Haenni, Locher, Koenig and
Dubuis, "Pseudo-Code Algorithms for Verifiable Re-Encryption Mix-Nets"
(FC 2017 workshops), extended to rows of w ciphertexts that share one
permutation. Verificatum, CHVote and the Swiss Post system use the same proof.
Stored in compact form: the verifier recomputes the prover's commitments from
the challenge and the responses.

Independent generators h, h_1..h_N are derived by hashing to the subgroup, so
nobody knows their discrete logarithms (which soundness requires).

Research implementation; not independently audited.
"""

from __future__ import annotations

import hashlib
import secrets
import threading

from .encoding import from_hex, hash_to_scalar, to_hex
from .group import Group

Row = list[tuple[int, int]]

_GEN_LOCK = threading.Lock()
_GEN_CACHE: dict[int, list[int]] = {}


def _derive_generator(p: int, q: int, label: int) -> int:
    nbytes = (p.bit_length() + 7) // 8 + 16
    ctr = 0
    while True:
        seed = b"chunaviq/v1/shuffle-generator\x00" + str(label).encode() + b"\x00" + str(ctr).encode()
        x = int.from_bytes(hashlib.shake_256(seed).digest(nbytes), "big") % p
        h = pow(x, (p - 1) // q, p)
        if h > 1:
            return h
        ctr += 1


def generators(grp: Group, n: int) -> list[int]:
    """[h, h_1, ..., h_n]: index 0 is the commitment-chain base."""
    with _GEN_LOCK:
        cache = _GEN_CACHE.setdefault(grp.p, [])
        while len(cache) < n + 1:
            cache.append(_derive_generator(grp.p, grp.q, len(cache)))
        return cache[: n + 1]


def digest_ints(values) -> bytes:
    """SHA-256 over each value as 4-byte length || big-endian bytes (spec/protocol.md 10)."""
    h = hashlib.sha256()
    for x in values:
        raw = x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")
        h.update(len(raw).to_bytes(4, "big") + raw)
    return h.digest()


def digest_rows(rows: list[Row]) -> bytes:
    return digest_ints(v for row in rows for ct in row for v in ct)


def _u_vector(grp: Group, context: list, din: bytes, dout: bytes, dcom: bytes, n: int) -> list[int]:
    seed = hash_to_scalar(grp.q, "shuffle-u-seed", context, din, dout, dcom)
    return [hash_to_scalar(grp.q, "shuffle-u", seed, j) for j in range(n)]


def _challenge(grp: Group, context: list, din: bytes, dout: bytes, dcom: bytes, dchain: bytes, t: list[int], dhat: bytes) -> int:
    return hash_to_scalar(grp.q, "shuffle-c", context, din, dout, dcom, dchain, t, dhat)


def shuffle_and_prove(grp: Group, K: int, rows: list[Row], context: list, k_pow=None) -> tuple[list[Row], dict]:
    """Re-encrypt and permute rows; return (output rows, proof)."""
    p, q = grp.p, grp.q
    kp = k_pow or (lambda e: grp.pow(K, e))
    N = len(rows)
    if N == 0:
        raise ValueError("nothing to shuffle")
    w = len(rows[0])
    if any(len(r) != w for r in rows):
        raise ValueError("rows must have equal width")
    H = generators(grp, N)
    rng = secrets.SystemRandom()
    perm = list(range(N))
    rng.shuffle(perm)  # output i comes from input perm[i]
    rr = [[grp.rand_scalar() for _ in range(w)] for _ in range(N)]
    out: list[Row] = []
    for i in range(N):
        src = rows[perm[i]]
        out.append([(a * grp.g_pow(rr[i][k]) % p, b * kp(rr[i][k]) % p) for k, (a, b) in enumerate(src)])

    # permutation commitments (indexed by input position)
    r = [grp.rand_scalar() for _ in range(N)]
    com = [0] * N
    for i in range(N):
        j = perm[i]
        com[j] = grp.g_pow(r[j]) * H[i + 1] % p
    din, dout, dcom = digest_rows(rows), digest_rows(out), digest_ints(com)
    u = _u_vector(grp, context, din, dout, dcom, N)
    up = [u[perm[i]] for i in range(N)]

    # commitment chain
    rh = [grp.rand_scalar() for _ in range(N)]
    chain = []
    prev = H[0]
    for i in range(N):
        cur = grp.g_pow(rh[i]) * grp.pow(prev, up[i]) % p
        chain.append(cur)
        prev = cur

    r_bar = sum(r) % q
    r_hat, acc = 0, 1
    for i in range(N - 1, -1, -1):
        r_hat = (r_hat + rh[i] * acc) % q
        acc = acc * up[i] % q
    r_tld = sum(r[j] * u[j] for j in range(N)) % q
    r_p = [sum(rr[i][k] * up[i] for i in range(N)) % q for k in range(w)]

    w1, w2, w3 = grp.rand_scalar(), grp.rand_scalar(), grp.rand_scalar()
    w4 = [grp.rand_scalar() for _ in range(w)]
    what = [grp.rand_scalar() for _ in range(N)]
    wp = [grp.rand_scalar() for _ in range(N)]
    t1, t2 = grp.g_pow(w1), grp.g_pow(w2)
    t3 = grp.g_pow(w3)
    for i in range(N):
        t3 = t3 * grp.pow(H[i + 1], wp[i]) % p
    t4a, t4b = [], []
    for k in range(w):
        a_acc, b_acc = grp.g_pow(q - w4[k]), kp(q - w4[k])
        for i in range(N):
            a_acc = a_acc * grp.pow(out[i][k][0], wp[i]) % p
            b_acc = b_acc * grp.pow(out[i][k][1], wp[i]) % p
        t4a.append(a_acc)
        t4b.append(b_acc)
    that = []
    prev = H[0]
    for i in range(N):
        that.append(grp.g_pow(what[i]) * grp.pow(prev, wp[i]) % p)
        prev = chain[i]
    c = _challenge(grp, context, din, dout, dcom, digest_ints(chain), [t1, t2, t3, *t4a, *t4b], digest_ints(that))
    proof = {
        "commitments": [to_hex(x) for x in com],
        "chain": [to_hex(x) for x in chain],
        "c": to_hex(c),
        "s1": to_hex((w1 + c * r_bar) % q),
        "s2": to_hex((w2 + c * r_hat) % q),
        "s3": to_hex((w3 + c * r_tld) % q),
        "s4": [to_hex((w4[k] + c * r_p[k]) % q) for k in range(w)],
        "shat": [to_hex((what[i] + c * rh[i]) % q) for i in range(N)],
        "sprime": [to_hex((wp[i] + c * up[i]) % q) for i in range(N)],
    }
    return out, proof


PROOF_KEYS = {"commitments", "chain", "c", "s1", "s2", "s3", "s4", "shat", "sprime"}


def verify_shuffle(grp: Group, K: int, rows: list[Row], out: list[Row], proof: dict, context: list, k_pow=None) -> bool:
    """Inputs are assumed to be valid group elements (checked where they came from);
    outputs, commitments and chain values are checked here."""
    p, q = grp.p, grp.q
    kp = k_pow or (lambda e: grp.pow(K, e))
    try:
        if set(proof) != PROOF_KEYS:
            return False
        N = len(rows)
        if N == 0 or len(out) != N:
            return False
        w = len(rows[0])
        if any(len(r) != w for r in rows) or any(len(r) != w for r in out):
            return False
        com = [from_hex(x) for x in proof["commitments"]]
        chain = [from_hex(x) for x in proof["chain"]]
        c = from_hex(proof["c"])
        s1, s2, s3 = from_hex(proof["s1"]), from_hex(proof["s2"]), from_hex(proof["s3"])
        s4 = [from_hex(x) for x in proof["s4"]]
        shat = [from_hex(x) for x in proof["shat"]]
        sp = [from_hex(x) for x in proof["sprime"]]
    except (TypeError, ValueError, KeyError):
        return False
    if len(com) != N or len(chain) != N or len(s4) != w or len(shat) != N or len(sp) != N:
        return False
    if not all(grp.is_scalar(x) for x in (c, s1, s2, s3, *s4, *shat, *sp)):
        return False
    if not all(grp.is_element(x) for x in (*com, *chain)) or not all(grp.is_element(v) for row in out for ct in row for v in ct):
        return False
    H = generators(grp, N)
    din, dout, dcom = digest_rows(rows), digest_rows(out), digest_ints(com)
    u = _u_vector(grp, context, din, dout, dcom, N)
    nc = q - c

    c_bar = 1
    for j in range(N):
        c_bar = c_bar * com[j] % p
    h_prod = 1
    for i in range(N):
        h_prod = h_prod * H[i + 1] % p
    c_bar = c_bar * pow(h_prod, -1, p) % p
    u_prod = 1
    for x in u:
        u_prod = u_prod * x % q
    c_hat = chain[-1] * pow(grp.pow(H[0], u_prod), -1, p) % p
    c_tld = 1
    for j in range(N):
        c_tld = c_tld * grp.pow(com[j], u[j]) % p

    t1 = grp.g_pow(s1) * grp.pow(c_bar, nc) % p
    t2 = grp.g_pow(s2) * grp.pow(c_hat, nc) % p
    t3 = grp.g_pow(s3) * grp.pow(c_tld, nc) % p
    for i in range(N):
        t3 = t3 * grp.pow(H[i + 1], sp[i]) % p
    t4a, t4b = [], []
    for k in range(w):
        a_t = b_t = 1
        for j in range(N):
            a_t = a_t * grp.pow(rows[j][k][0], u[j]) % p
            b_t = b_t * grp.pow(rows[j][k][1], u[j]) % p
        a_acc = grp.g_pow(q - s4[k]) * grp.pow(a_t, nc) % p
        b_acc = kp(q - s4[k]) * grp.pow(b_t, nc) % p
        for i in range(N):
            a_acc = a_acc * grp.pow(out[i][k][0], sp[i]) % p
            b_acc = b_acc * grp.pow(out[i][k][1], sp[i]) % p
        t4a.append(a_acc)
        t4b.append(b_acc)
    that = []
    prev = H[0]
    for i in range(N):
        that.append(grp.g_pow(shat[i]) * grp.pow(prev, sp[i]) * grp.pow(chain[i], nc) % p)
        prev = chain[i]
    return _challenge(grp, context, din, dout, dcom, digest_ints(chain), [t1, t2, t3, *t4a, *t4b], digest_ints(that)) == c


def rows_to_json(rows: list[Row]) -> list[list[dict]]:
    return [[{"alpha": to_hex(a), "beta": to_hex(b)} for a, b in row] for row in rows]


def rows_from_json(data: list[list[dict]]) -> list[Row]:
    return [[(from_hex(ct["alpha"]), from_hex(ct["beta"])) for ct in row] for row in data]


__all__ = ["shuffle_and_prove", "verify_shuffle", "generators", "digest_rows", "rows_to_json", "rows_from_json"]
