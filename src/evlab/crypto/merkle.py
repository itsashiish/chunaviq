"""RFC 6962 / RFC 9162 Merkle tree: roots, inclusion proofs and consistency proofs.

The bulletin board is an append-only log. Signed tree heads ("checkpoints") let
anyone confirm that (a) a ballot is included and (b) a later checkpoint extends
an earlier one without rewriting history.
"""

from __future__ import annotations

import hashlib


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


EMPTY_ROOT = hashlib.sha256(b"").digest()


class MerkleTree:
    """Incrementally maintained levels. A lone last node at any level is promoted
    unchanged, which yields exactly the RFC 6962 tree shape (proved by property
    tests against the recursive reference definition below)."""

    def __init__(self) -> None:
        self.levels: list[list[bytes]] = [[]]

    def __len__(self) -> int:
        return len(self.levels[0])

    def append(self, data: bytes) -> int:
        self.levels[0].append(leaf_hash(data))
        self._rebuild_tail()
        return len(self) - 1

    def _rebuild_tail(self) -> None:
        lvl = 0
        while len(self.levels[lvl]) > 1:
            cur = self.levels[lvl]
            if lvl + 1 == len(self.levels):
                self.levels.append([])
            nxt = self.levels[lvl + 1]
            want = (len(cur) + 1) // 2
            i = len(cur) - 1
            pi = i // 2
            val = node_hash(cur[i - 1], cur[i]) if i % 2 == 1 else cur[i]
            if pi < len(nxt):
                nxt[pi] = val
            else:
                nxt.append(val)
            # A previous promoted tail may now have been paired; recompute parent of
            # the earlier node too when the level just became even.
            del nxt[want:]
            lvl += 1
        del self.levels[lvl + 1 :]

    def root(self, size: int | None = None) -> bytes:
        if size is None or size == len(self):
            if not self.levels[0]:
                return EMPTY_ROOT
            return self.levels[-1][0]
        return mth(self.levels[0][:size])

    def inclusion_proof(self, index: int) -> list[bytes]:
        if not 0 <= index < len(self):
            raise IndexError("leaf index out of range")
        path, i = [], index
        for lvl in range(len(self.levels) - 1):
            cur = self.levels[lvl]
            sib = i ^ 1
            if sib < len(cur):
                path.append(cur[sib])
            i //= 2
        return path

    def consistency_proof(self, first: int, second: int | None = None) -> list[bytes]:
        second = len(self) if second is None else second
        return consistency_proof(self.levels[0][:second], first)


# ---------------------------------------------------------------- reference algorithms
def _largest_pow2_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves: list[bytes]) -> bytes:
    """Recursive RFC 6962 Merkle Tree Hash over already-hashed leaves."""
    n = len(leaves)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaves[0]
    k = _largest_pow2_below(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def reference_path(m: int, leaves: list[bytes]) -> list[bytes]:
    n = len(leaves)
    if n <= 1:
        return []
    k = _largest_pow2_below(n)
    if m < k:
        return reference_path(m, leaves[:k]) + [mth(leaves[k:])]
    return reference_path(m - k, leaves[k:]) + [mth(leaves[:k])]


def consistency_proof(leaves: list[bytes], m: int) -> list[bytes]:
    n = len(leaves)
    if not 0 < m <= n:
        raise ValueError("consistency proof needs 0 < first <= second")

    def sub(m: int, d: list[bytes], b: bool) -> list[bytes]:
        n = len(d)
        if m == n:
            return [] if b else [mth(d)]
        k = _largest_pow2_below(n)
        if m <= k:
            return sub(m, d[:k], b) + [mth(d[k:])]
        return sub(m - k, d[k:], False) + [mth(d[:k])]

    return sub(m, leaves, True)


def verify_inclusion(leaf: bytes, index: int, size: int, path: list[bytes], root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2. `leaf` is the leaf *hash*."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, proof: list[bytes]) -> bool:
    """RFC 9162 section 2.1.4.2."""
    if first < 1 or first > second:
        return False
    if first == second:
        return not proof and first_root == second_root
    if not proof:
        return False
    path = list(proof)
    if first & (first - 1) == 0:  # exact power of two
        path = [first_root] + path
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
