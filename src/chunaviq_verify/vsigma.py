"""Protocol v2 proof checks for the independent verifier.

Re-implemented from spec/protocol.md sections 6, 7 and 10 (no imports from the
`chunaviq` package):

  * Sigma proofs of linear relations and their OR-composition (ballot tag proof,
    finalization proof)
  * the Terelius-Wikstrom proof of a re-encryption shuffle of rows of ciphertexts
"""

from __future__ import annotations

import hashlib

from .vmath import G, challenge, hx

# An equation is (value, [(base, witness_index), ...]): value = prod base^w[idx].


def _enc(eqs: list) -> list:
    return [[v, [b for b, _ in t], [str(i) for _, i in t]] for v, t in eqs]


def _recommit(G_: G, eqs: list, s: list[int], c: int) -> list[int]:
    p, q = G_.p, G_.q
    out = []
    for v, terms in eqs:
        acc = G_.e(v, q - c) if c % q else 1
        for base, idx in terms:
            acc = acc * G_.e(base, s[idx]) % p
        out.append(acc)
    return out


def _scalars(G_: G, xs) -> list[int] | None:
    try:
        v = [hx(x) for x in xs]
    except (TypeError, ValueError):
        return None
    return v if G_.sc(*v) else None


def sigma_ok(G_: G, eqs: list, n_w: int, proof: dict, domain: str, ctx: list) -> bool:
    if not isinstance(proof, dict) or set(proof) != {"c", "s"} or not isinstance(proof["s"], list) or len(proof["s"]) != n_w:
        return False
    c = _scalars(G_, [proof["c"]])
    s = _scalars(G_, proof["s"])
    if c is None or s is None or not all(G_.member(v) for v, _ in eqs):
        return False
    A = _recommit(G_, eqs, s, c[0])
    return challenge(G_.q, domain, ctx, [_enc(eqs)], [A]) == c[0]


def sigma_or_ok(G_: G, branches: list[tuple[list, int]], proof: dict, domain: str, ctx: list) -> bool:
    if not isinstance(proof, dict) or set(proof) != {"c", "s"}:
        return False
    if not isinstance(proof["c"], list) or not isinstance(proof["s"], list) or len(proof["c"]) != len(branches) or len(proof["s"]) != len(branches):
        return False
    cs = _scalars(G_, proof["c"])
    if cs is None:
        return False
    A = []
    for (eqs, n_w), sb in zip(branches, proof["s"], strict=True):
        if not isinstance(sb, list) or len(sb) != n_w:
            return False
        s = _scalars(G_, sb)
        if s is None or not all(G_.member(v) for v, _ in eqs):
            return False
        A.append(_recommit(G_, eqs, s, cs[len(A)]))
    return challenge(G_.q, domain, ctx, [_enc(eqs) for eqs, _ in branches], A) == sum(cs) % G_.q


# ------------------------------------------------------------------ protocol statements
def _dh(g: int, K: int, x: int, y: int, i: int) -> list:
    return [(x, [(g, i)]), (y, [(K, i)])]


def tag_eqs(G_: G, K: int, a: int, b: int) -> list:
    return [(a, [(G_.g, 0)]), (b, [(G_.g, 1), (K, 0)])]


def finalize_branches(G_: G, K: int, flag: tuple[int, int], votes: list, masked: list) -> list[tuple[list, int]]:
    p, g = G_.p, G_.g
    gi = pow(g, -1, p)
    fa, fb = flag
    zero, one = _dh(g, K, fa, fb, 0), _dh(g, K, fa, fb * gi % p, 0)
    for j, ((va, vb), (ma, mb)) in enumerate(zip(votes, masked, strict=True)):
        zero += _dh(g, K, ma, mb, j + 1)
        one += _dh(g, K, ma * pow(va, -1, p) % p, mb * pow(vb, -1, p) % p, j + 1)
    n = 1 + len(votes)
    return [(zero, n), (one, n)]


# ------------------------------------------------------------------ shuffle
_GENS: dict[int, list[int]] = {}


def _generator(p: int, q: int, label: int) -> int:
    nb = (p.bit_length() + 7) // 8 + 16
    ctr = 0
    while True:
        x = int.from_bytes(hashlib.shake_256(b"chunaviq/v1/shuffle-generator\x00" + str(label).encode() + b"\x00" + str(ctr).encode()).digest(nb), "big") % p
        h = pow(x, (p - 1) // q, p)
        if h > 1:
            return h
        ctr += 1


def generators(G_: G, n: int) -> list[int]:
    lst = _GENS.setdefault(G_.p, [])
    while len(lst) < n + 1:
        lst.append(_generator(G_.p, G_.q, len(lst)))
    return lst[: n + 1]


def _digest(values) -> bytes:
    h = hashlib.sha256()
    for x in values:
        raw = x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")
        h.update(len(raw).to_bytes(4, "big") + raw)
    return h.digest()


def _rows_digest(rows) -> bytes:
    return _digest(v for row in rows for ct in row for v in ct)


def shuffle_ok(G_: G, K: int, rows: list, out: list, proof: dict, ctx: list) -> bool:
    """rows/out: lists of rows, each a list of (alpha, beta) ints. Inputs assumed checked."""
    p, q, g = G_.p, G_.q, G_.g
    keys = {"commitments", "chain", "c", "s1", "s2", "s3", "s4", "shat", "sprime"}
    if not isinstance(proof, dict) or set(proof) != keys:
        return False
    N = len(rows)
    if N == 0 or len(out) != N:
        return False
    w = len(rows[0])
    if any(len(r) != w for r in rows) or any(len(r) != w for r in out):
        return False
    try:
        com = [hx(x) for x in proof["commitments"]]
        chain = [hx(x) for x in proof["chain"]]
        c, s1, s2, s3 = (hx(proof[k]) for k in ("c", "s1", "s2", "s3"))
        s4 = [hx(x) for x in proof["s4"]]
        shat = [hx(x) for x in proof["shat"]]
        sp = [hx(x) for x in proof["sprime"]]
    except (TypeError, ValueError):
        return False
    if len(com) != N or len(chain) != N or len(s4) != w or len(shat) != N or len(sp) != N:
        return False
    if not G_.sc(c, s1, s2, s3, *s4, *shat, *sp):
        return False
    if not all(G_.member(x) for x in (*com, *chain)) or not all(G_.member(v) for row in out for ct in row for v in ct):
        return False
    H = generators(G_, N)
    din, dout, dcom = _rows_digest(rows), _rows_digest(out), _digest(com)
    seed = challenge(q, "shuffle-u-seed", ctx, din, dout, dcom)
    u = [challenge(q, "shuffle-u", seed, j) for j in range(N)]
    nc = q - c
    cbar = 1
    for x in com:
        cbar = cbar * x % p
    hp = 1
    for x in H[1:]:
        hp = hp * x % p
    cbar = cbar * pow(hp, -1, p) % p
    up = 1
    for x in u:
        up = up * x % q
    chat = chain[-1] * pow(G_.e(H[0], up), -1, p) % p
    ctld = 1
    for x, uj in zip(com, u, strict=True):
        ctld = ctld * G_.e(x, uj) % p
    t1 = G_.e(g, s1) * G_.e(cbar, nc) % p
    t2 = G_.e(g, s2) * G_.e(chat, nc) % p
    t3 = G_.e(g, s3) * G_.e(ctld, nc) % p
    for i in range(N):
        t3 = t3 * G_.e(H[i + 1], sp[i]) % p
    t4a, t4b = [], []
    for k in range(w):
        at = bt = 1
        for j in range(N):
            at = at * G_.e(rows[j][k][0], u[j]) % p
            bt = bt * G_.e(rows[j][k][1], u[j]) % p
        a = G_.e(g, q - s4[k]) * G_.e(at, nc) % p
        b = G_.e(K, q - s4[k]) * G_.e(bt, nc) % p
        for i in range(N):
            a = a * G_.e(out[i][k][0], sp[i]) % p
            b = b * G_.e(out[i][k][1], sp[i]) % p
        t4a.append(a)
        t4b.append(b)
    that = []
    prev = H[0]
    for i in range(N):
        that.append(G_.e(g, shat[i]) * G_.e(prev, sp[i]) * G_.e(chain[i], nc) % p)
        prev = chain[i]
    return challenge(q, "shuffle-c", ctx, din, dout, dcom, _digest(chain), [t1, t2, t3, *t4a, *t4b], _digest(that)) == c
