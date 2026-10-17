"""Ballot box: accepts anonymous encrypted ballots and posts them to the board.

It never receives a voter identifier. Acceptance requires:
  * the board's lifecycle state is OPEN and the clock is inside the manifest window
  * a valid blind-signed credential for the ballot's constituency, never used before
  * valid ciphertexts and proofs (exactly one selection)
  * no ciphertext component identical to one already on the board (copy defence)

The expensive cryptographic checks run outside the lock (and can run in worker
processes via ``check``); the uniqueness checks and the board append run inside
one critical section with an IMMEDIATE transaction, so concurrent duplicates
cannot both be accepted.

The board is authoritative. ``rebuild_index`` reconstructs the database from the
board after a crash or database loss.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections import Counter
from pathlib import Path

from ..crypto.blind import RSAPublic
from ..crypto.elgamal import PublicKey
from .ballot import BallotRejected, check_ballot, tracking_code
from .board import Board
from .clock import utc

log = logging.getLogger("chunaviq.ballotbox")


class BallotBox:
    def __init__(self, db_path: Path, board: Board, manifest: dict, mhash: str, pk: PublicKey, issuer_keys: dict[str, RSAPublic], clock) -> None:
        self.db_path = str(db_path)
        self.board = board
        self.manifest = manifest
        self.mhash = mhash
        self.pk = pk
        self.issuer_keys = issuer_keys
        self.clock = clock
        self.opens = utc(manifest["window"]["opens_at"])
        self.closes = utc(manifest["window"]["closes_at"])
        self.options = {c["id"]: [o["id"] for o in c["options"]] for c in manifest["constituencies"]}
        self.rejections: Counter[str] = Counter()
        self._lock = threading.Lock()
        self._local = threading.local()
        self._conn().executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS used_tokens(token TEXT PRIMARY KEY, seq INTEGER NOT NULL, tc TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS alphas(alpha TEXT PRIMARY KEY);
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
        check_ballot(ballot, pk=self.pk, mhash=self.mhash, election_id=self.manifest["election_id"], options=self.options, issuer_keys=self.issuer_keys)

    def _gate(self) -> None:
        if self.board.state != "OPEN":
            raise BallotRejected("ELECTION_NOT_OPEN")
        now = self.clock.now()
        if not self.opens <= now < self.closes:
            raise BallotRejected("OUTSIDE_VOTING_WINDOW")

    # -------------------------------------------------------------------- submit
    def _prior(self, ballot: dict) -> dict | None:
        """Idempotent retries: if this exact ballot was already accepted (a voter's
        device retrying after a dropped connection), return the original receipt
        instead of an error. Nothing new is recorded, so nothing is counted twice.
        A *different* ballot with the same credential is still refused."""
        try:
            token, tc = ballot["credential"]["token"], tracking_code(ballot)
        except (KeyError, TypeError):
            return None
        row = self._conn().execute("SELECT seq, tc FROM used_tokens WHERE token=?", (token,)).fetchone()
        if row and row[1] == tc:
            return {"tracking_code": tc, "seq": row[0], "duplicate_submission": True}
        return None

    def submit(self, ballot: dict, prechecked: bool = False) -> dict:
        """Returns {"tracking_code", "seq"} or raises BallotRejected."""
        try:
            prior = self._prior(ballot)
            if prior is not None:
                return prior
            self._gate()
            if not prechecked:
                self.check(ballot)
            return self._commit(ballot)
        except BallotRejected as e:
            with self._lock:
                self.rejections[e.code] += 1
            log.info("ballot rejected code=%s", e.code)
            raise

    def _commit(self, ballot: dict) -> dict:
        token = ballot["credential"]["token"]
        alphas = [s["ciphertext"]["alpha"] for s in ballot["selections"]]
        tc = tracking_code(ballot)
        con = self._conn()
        with self._lock:
            self._gate()  # re-check: the election may have closed while we verified
            con.execute("BEGIN IMMEDIATE")
            try:
                try:
                    con.execute("INSERT INTO used_tokens(token, seq, tc) VALUES(?, ?, ?)", (token, self.board.size, tc))
                except sqlite3.IntegrityError:
                    row = con.execute("SELECT seq, tc FROM used_tokens WHERE token=?", (token,)).fetchone()
                    if row and row[1] == tc:  # identical retry raced with the original
                        con.execute("ROLLBACK")
                        return {"tracking_code": tc, "seq": row[0], "duplicate_submission": True}
                    raise BallotRejected("CREDENTIAL_ALREADY_USED") from None
                try:
                    con.executemany("INSERT INTO alphas(alpha) VALUES(?)", [(a,) for a in alphas])
                except sqlite3.IntegrityError:
                    raise BallotRejected("DUPLICATE_CIPHERTEXT") from None
                entry = self.board.append("ballot", {"tracking_code": tc, "ballot": ballot})
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
        return {"tracking_code": tc, "seq": entry["seq"]}

    def submit_batch(self, ballots: list[dict], prechecked: bool = False) -> list[dict | str]:
        """Accept many ballots in one transaction and one fsync (group commit).

        Returns, per ballot, {"tracking_code", "seq"} or a rejection code. Each
        ballot gets its own SAVEPOINT, so a duplicate inside the batch rejects
        only that ballot. Used by a constituency shard's sequencer under load."""
        out: list[dict | str | None] = [None] * len(ballots)
        if not prechecked:
            for i, b in enumerate(ballots):
                try:
                    self.check(b)
                except BallotRejected as e:
                    out[i] = e.code
        for i, b in enumerate(ballots):
            if out[i] is None:
                prior = self._prior(b)
                if prior is not None:
                    out[i] = prior
        con = self._conn()
        with self._lock:
            try:
                self._gate()
            except BallotRejected as e:
                for i in range(len(ballots)):
                    out[i] = out[i] or e.code
                for code in out:
                    if isinstance(code, str):
                        self.rejections[code] += 1
                return out  # type: ignore[return-value]
            con.execute("BEGIN IMMEDIATE")
            try:
                accepted: list[tuple[int, dict]] = []
                base = self.board.size
                for i, b in enumerate(ballots):
                    if out[i] is not None:
                        continue
                    con.execute("SAVEPOINT b")
                    tc = tracking_code(b)
                    try:
                        con.execute("INSERT INTO used_tokens(token, seq, tc) VALUES(?, ?, ?)", (b["credential"]["token"], base + len(accepted), tc))
                    except sqlite3.IntegrityError:
                        con.execute("ROLLBACK TO b")
                        con.execute("RELEASE b")
                        row = con.execute("SELECT seq, tc FROM used_tokens WHERE token=?", (b["credential"]["token"],)).fetchone()
                        same = row is not None and row[1] == tc
                        out[i] = {"tracking_code": tc, "seq": row[0], "duplicate_submission": True} if same else "CREDENTIAL_ALREADY_USED"
                        continue
                    try:
                        con.executemany("INSERT INTO alphas(alpha) VALUES(?)", [(s["ciphertext"]["alpha"],) for s in b["selections"]])
                    except sqlite3.IntegrityError:
                        con.execute("ROLLBACK TO b")
                        con.execute("RELEASE b")
                        out[i] = "DUPLICATE_CIPHERTEXT"
                        continue
                    con.execute("RELEASE b")
                    accepted.append((i, {"tracking_code": tc, "ballot": b}))
                entries = self.board.append_ballots([body for _, body in accepted])
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
        for (i, body), entry in zip(accepted, entries, strict=True):
            out[i] = {"tracking_code": body["tracking_code"], "seq": entry["seq"]}
        for r in out:
            if isinstance(r, str):
                self.rejections[r] += 1
        return out  # type: ignore[return-value]

    # ------------------------------------------------------------------ recovery
    def rebuild_index(self) -> int:
        """Rebuild used tokens and ciphertext index from the authoritative board."""
        con = self._conn()
        with self._lock:
            con.execute("BEGIN IMMEDIATE")
            con.execute("DELETE FROM used_tokens")
            con.execute("DELETE FROM alphas")
            n = 0
            for e in self.board.iter_entries("ballot"):
                b = e["body"]["ballot"]
                con.execute("INSERT INTO used_tokens(token, seq, tc) VALUES(?, ?, ?)", (b["credential"]["token"], e["seq"], e["body"]["tracking_code"]))
                con.executemany("INSERT INTO alphas(alpha) VALUES(?)", [(s["ciphertext"]["alpha"],) for s in b["selections"]])
                n += 1
            con.execute("COMMIT")
        return n

    def reconcile(self) -> dict:
        """Index vs board: both counts must match exactly."""
        db = self._conn().execute("SELECT COUNT(*) FROM used_tokens").fetchone()[0]
        board = self.board.count("ballot")
        return {"index_tokens": db, "board_ballots": board, "consistent": db == board}
