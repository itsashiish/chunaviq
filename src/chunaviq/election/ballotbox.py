"""Ballot box (constituency sequencer): accepts encrypted ballots, allows revoting,
and after close decides -- privately but provably -- which ballot of each voter counts.

Acceptance of a submission ``{"ballot", "tag", "link"}``:
  * the election is OPEN and the clock is inside the published window
  * the ballot is valid: ciphertexts, 0/1 and limit proofs, tag proof of knowledge
  * ``link`` proves the ballot's tag ciphertext encrypts ``tag`` (T, never published)
  * T was registered in this constituency at some point (a revoked T is still
    accepted -- refusing it would tell a coercer holding an old tag that the
    voter re-registered or voted in person)
  * at most ``max_per_tag`` ballots per tag (bounds storage abuse)
  * no ciphertext component already on the board (copy defence)

A different ballot under the same tag is a REVOTE and is accepted. An identical
resubmission (same tracking code) is idempotent: the original receipt comes back.

Finalization (after close, once the eligibility authority has handed over the
final set of valid tags): for every ballot in board order the box publishes an
encrypted flag f (1 for the last ballot of each valid tag, else 0), a masked
copy of the vote (a re-encryption of the vote if f = 1, an encryption of zero
if f = 0) and an OR-proof that it did exactly one of those two things. The
tally multiplies the masked votes, so only final ballots count, and nobody can
see which ballots those were. The trustees later shuffle (tag, flag) pairs and
decrypt them to prove that every counted ballot belongs to a distinct valid tag.

The box knows which ballots are revotes of one another (it sees T). It does not
know who T belongs to. The private database is NOT rebuildable from the public
board (the board never shows T), so it is replicated like the board itself.
"""

from __future__ import annotations

import logging
import multiprocessing as mp
import sqlite3
import threading
from collections import Counter
from pathlib import Path

from ..crypto import sigma
from ..crypto.elgamal import Ciphertext, PublicKey
from ..crypto.encoding import from_hex, to_hex
from ..crypto.group import get_group
from .ballot import BallotRejected, check_ballot, check_link, fast_pows, tracking_code
from .board import Board
from .clock import utc

log = logging.getLogger("chunaviq.ballotbox")

FINALIZE_CHUNK = 128
SUBMISSION_KEYS = {"ballot", "tag", "link"}


def finalize_context(mhash: str, constituency: str, tracking: str) -> list:
    return [mhash, "finalize", constituency, tracking]


def dv_context(mhash: str, tracking: str) -> list:
    return [mhash, "dv-final", tracking]


# ------------------------------------------------------------------ finalization worker
_F: dict = {}


def _finit(group_name: str, K_hex: str, mhash: str) -> None:
    grp = get_group(group_name)
    _F.update(pk=PublicKey(grp, int(K_hex, 16)), mhash=mhash)


def _finalize_one(job: tuple) -> tuple[dict, int | None]:
    seq, tc, cons, votes, f = job
    pk: PublicKey = _F["pk"]
    grp = pk.group
    p = grp.p
    u = grp.rand_scalar()
    F = (grp.g_pow(u), grp.g_pow(f) * pk.k_pow(u) % p)
    ws = [grp.rand_scalar() for _ in votes]
    masked = []
    for (va, vb), w in zip(votes, ws, strict=True):
        if f:
            masked.append((va * grp.g_pow(w) % p, vb * pk.k_pow(w) % p))
        else:
            masked.append((grp.g_pow(w), pk.k_pow(w)))
    br = sigma.finalize_branches(grp, pk.K, F, votes, masked)
    proof = sigma.prove_or(grp, br, f, [u, *ws], "finalize", finalize_context(_F["mhash"], cons, tc), fast_pows(pk))
    item = {
        "seq": seq,
        "tracking_code": tc,
        "flag": {"alpha": to_hex(F[0]), "beta": to_hex(F[1])},
        "masked": [{"alpha": to_hex(a), "beta": to_hex(b)} for a, b in masked],
        "proof": proof,
    }
    return item, (u if f else None)


class BallotBox:
    def __init__(self, db_path: Path, board: Board, manifest: dict, mhash: str, pk: PublicKey, clock, tag_known, max_per_tag: int = 30) -> None:
        self.db_path = str(db_path)
        self.board = board
        self.manifest = manifest
        self.mhash = mhash
        self.pk = pk
        self.clock = clock
        self.tag_known = tag_known  # callable(constituency, tag_hex) -> bool (eligibility feed)
        self.max_per_tag = max_per_tag
        self.opens = utc(manifest["window"]["opens_at"])
        self.closes = utc(manifest["window"]["closes_at"])
        self.options = {c["id"]: [o["id"] for o in c["options"]] for c in manifest["constituencies"]}
        self.rejections: Counter[str] = Counter()
        self._lock = threading.Lock()
        self._local = threading.local()
        self._conn().executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS ballots(seq INTEGER PRIMARY KEY, tc TEXT NOT NULL UNIQUE, tag TEXT NOT NULL, cons TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS ballots_tag ON ballots(tag);
            CREATE TABLE IF NOT EXISTS alphas(alpha TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS finals(tc TEXT PRIMARY KEY, u TEXT NOT NULL, flag_alpha TEXT NOT NULL, flag_beta TEXT NOT NULL);
            """
        )

    def _conn(self) -> sqlite3.Connection:
        con = getattr(self._local, "con", None)
        if con is None:
            con = sqlite3.connect(self.db_path, isolation_level=None, timeout=30, check_same_thread=False)
            self._local.con = con
        return con

    # -------------------------------------------------------------------- checks
    def check(self, ballot: dict) -> None:
        check_ballot(ballot, pk=self.pk, mhash=self.mhash, election_id=self.manifest["election_id"], options=self.options)

    def precheck(self, sub: dict) -> str:
        """All checks that need no shared state. Returns the tag (hex) or raises."""
        if not isinstance(sub, dict) or set(sub) != SUBMISSION_KEYS:
            raise BallotRejected("MALFORMED")
        ballot = sub["ballot"]
        self.check(ballot)
        T = check_link(self.pk, self.mhash, ballot, sub["tag"], sub["link"])
        tag = to_hex(T)
        if not self.tag_known(ballot["constituency"], tag):
            raise BallotRejected("UNREGISTERED_TAG")
        return tag

    def _gate(self) -> None:
        if self.board.state != "OPEN":
            raise BallotRejected("ELECTION_NOT_OPEN")
        now = self.clock.now()
        if not self.opens <= now < self.closes:
            raise BallotRejected("OUTSIDE_VOTING_WINDOW")

    # -------------------------------------------------------------------- submit
    def _prior(self, sub: dict) -> dict | None:
        """Idempotent retries: an identical resubmission (same ballot, same tag) returns
        the original receipt instead of an error; nothing is recorded twice."""
        try:
            tc = tracking_code(sub["ballot"])
        except (TypeError, ValueError, KeyError):
            return None
        row = self._conn().execute("SELECT seq, tag FROM ballots WHERE tc=?", (tc,)).fetchone()
        return {"tracking_code": tc, "seq": row[0], "duplicate_submission": True} if row and row[1] == sub.get("tag") else None

    def submit(self, sub: dict, prechecked_tag: str | None = None) -> dict:
        """Returns {"tracking_code", "seq", "revote"} or raises BallotRejected."""
        out = self.submit_batch([sub], prechecked_tags=[prechecked_tag] if prechecked_tag else None)[0]
        if isinstance(out, str):
            raise BallotRejected(out)
        return out

    def submit_batch(self, subs: list[dict], prechecked_tags: list[str | None] | None = None) -> list[dict | str]:
        """Accept many submissions in one transaction and one fsync (group commit).

        Per submission: a receipt, or a rejection code. Each gets its own SAVEPOINT,
        so a problem with one rejects only that one."""
        n = len(subs)
        out: list[dict | str | None] = [None] * n
        tags: list[str | None] = list(prechecked_tags) if prechecked_tags else [None] * n
        for i, s in enumerate(subs):
            prior = self._prior(s) if isinstance(s, dict) else None
            if prior is not None:
                out[i] = prior
                continue
            if tags[i] is None:
                try:
                    tags[i] = self.precheck(s)
                except BallotRejected as e:
                    out[i] = e.code
            elif not self.tag_known(s["ballot"]["constituency"], tags[i]):  # crypto prechecked elsewhere; registration is checked here
                out[i] = "UNREGISTERED_TAG"
        con = self._conn()
        accepted: list[tuple[int, dict, int]] = []
        with self._lock:
            try:
                self._gate()
            except BallotRejected as e:
                for i in range(n):
                    out[i] = out[i] or e.code
                self._count(out)
                return out  # type: ignore[return-value]
            con.execute("BEGIN IMMEDIATE")
            try:
                base = self.board.size
                for i, s in enumerate(subs):
                    if out[i] is not None:
                        continue
                    b = s["ballot"]
                    tc = tracking_code(b)
                    tag = tags[i]
                    con.execute("SAVEPOINT b")
                    prev = con.execute("SELECT COUNT(*) FROM ballots WHERE tag=?", (tag,)).fetchone()[0]
                    if prev >= self.max_per_tag:
                        con.execute("RELEASE b")
                        out[i] = "TOO_MANY_REVOTES"
                        continue
                    try:
                        con.execute("INSERT INTO ballots(seq, tc, tag, cons) VALUES(?,?,?,?)", (base + len(accepted), tc, tag, b["constituency"]))
                    except sqlite3.IntegrityError:  # identical ballot raced in this batch
                        con.execute("ROLLBACK TO b")
                        con.execute("RELEASE b")
                        row = con.execute("SELECT seq, tag FROM ballots WHERE tc=?", (tc,)).fetchone()
                        # idempotent only for the same ballot under the same tag (as in _prior)
                        same = row is not None and row[1] == tag
                        out[i] = {"tracking_code": tc, "seq": row[0], "duplicate_submission": True} if same else "DUPLICATE_CIPHERTEXT"
                        continue
                    try:
                        alphas = [b["tag"]["ciphertext"]["alpha"], *(x["ciphertext"]["alpha"] for x in b["selections"])]
                        con.executemany("INSERT INTO alphas(alpha) VALUES(?)", [(a,) for a in alphas])
                    except sqlite3.IntegrityError:
                        con.execute("ROLLBACK TO b")
                        con.execute("RELEASE b")
                        out[i] = "DUPLICATE_CIPHERTEXT"
                        continue
                    con.execute("RELEASE b")
                    accepted.append((i, {"tracking_code": tc, "ballot": b}, prev + 1))
                entries = self.board.append_ballots([body for _, body, _ in accepted])
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
        for (i, body, rv), entry in zip(accepted, entries, strict=True):
            out[i] = {"tracking_code": body["tracking_code"], "seq": entry["seq"], "revote": rv}
        self._count(out)
        return out  # type: ignore[return-value]

    def _count(self, out) -> None:
        for r in out:
            if isinstance(r, str):
                self.rejections[r] += 1
                log.info("ballot rejected code=%s", r)

    # -------------------------------------------------------------- finalization
    def final_seqs(self, valid_tags: dict[str, set[str]]) -> tuple[set[int], dict]:
        """Last ballot of every tag that is still valid."""
        con = self._conn()
        finals, stats = set(), Counter()
        for tag, cons, last, n in con.execute("SELECT tag, cons, MAX(seq), COUNT(*) FROM ballots GROUP BY tag"):
            if tag in valid_tags.get(cons, set()):
                finals.add(last)
                stats["superseded"] += n - 1
            else:
                stats["revoked_tag_ballots"] += n
        stats["final"] = len(finals)
        return finals, dict(stats)

    def finalize(self, valid_tags: dict[str, set[str]], workers: int = 1, group_name: str | None = None) -> dict:
        if self.board.state != "CLOSED":
            raise BallotRejected("ELECTION_NOT_CLOSED")
        finals, stats = self.final_seqs(valid_tags)
        jobs = []
        for e in self.board.iter_entries("ballot"):
            b = e["body"]["ballot"]
            votes = [(from_hex(s["ciphertext"]["alpha"]), from_hex(s["ciphertext"]["beta"])) for s in b["selections"]]
            jobs.append((e["seq"], e["body"]["tracking_code"], b["constituency"], votes, 1 if e["seq"] in finals else 0))
        init = (group_name or self.pk.group.name, to_hex(self.pk.K), self.mhash)
        if workers > 1 and len(jobs) > 64:
            with mp.get_context("spawn").Pool(workers, initializer=_finit, initargs=init) as pool:
                results = pool.map(_finalize_one, jobs, chunksize=16)
        else:
            _finit(*init)
            results = [_finalize_one(j) for j in jobs]
        con = self._conn()
        con.execute("BEGIN IMMEDIATE")
        for item, u in results:
            if u is not None:
                con.execute(
                    "INSERT INTO finals(tc, u, flag_alpha, flag_beta) VALUES(?,?,?,?)",
                    (item["tracking_code"], to_hex(u), item["flag"]["alpha"], item["flag"]["beta"]),
                )
        con.execute("COMMIT")
        for i in range(0, len(results), FINALIZE_CHUNK):
            items = [it for it, _ in results[i : i + FINALIZE_CHUNK]]
            self.board.append("finalization", self.board.operator.sign_body({"items": items}))
        self.board.checkpoint()
        return stats

    def dv_proof(self, tracking: str) -> dict | None:
        """Designated-verifier proof for the voter that this ballot is the one that counts."""
        row = self._conn().execute("SELECT u, flag_alpha, flag_beta FROM finals WHERE tc=?", (tracking,)).fetchone()
        tag_row = self._conn().execute("SELECT tag FROM ballots WHERE tc=?", (tracking,)).fetchone()
        if row is None or tag_row is None:
            return None
        grp = self.pk.group
        F = (from_hex(row[1]), from_hex(row[2]))
        br = sigma.dv_branches(grp, self.pk.K, F, from_hex(tag_row[0]))
        proof = sigma.prove_or(grp, br, 0, [from_hex(row[0])], "dv-final", dv_context(self.mhash, tracking), fast_pows(self.pk))
        return {"flag": Ciphertext(*F).to_dict(), "proof": proof}

    # ------------------------------------------------------------------ recovery
    def reconcile(self) -> dict:
        """Index vs board: both counts must match exactly."""
        db = self._conn().execute("SELECT COUNT(*) FROM ballots").fetchone()[0]
        board = self.board.count("ballot")
        return {"index_ballots": db, "board_ballots": board, "consistent": db == board}
