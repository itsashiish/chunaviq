"""Eligibility authority: verifies identity (Aadhaar OR PAN) and registers one voting tag per roll entry.

Protocol v2 (spec/protocol.md section 5). After identity verification the
voter's device registers a *tag* ``T = g^t`` (``t`` never leaves the device)
with a proof that it knows ``t``. The tag is what lets the voter vote, and
vote again: only the last ballot cast under a currently valid tag counts.

Anti-coercion operations, all keyed by the roll entry:

  re-registration   the voter verifies identity again (e.g. a new phone, or a
                    phone a coercer took or watched) and registers a new tag;
                    the old tag is silently revoked, so anything cast with it
                    stops counting
  in-person override  on polling day an official marks the elector as having
                    voted in person; their online tag is revoked

Revocation is never announced to the ballot box at voting time, so a coercer
holding an old tag gets the same "accepted" answer as before. The ballot box
learns the final set of valid tags only at finalization, after voting closes.

What this authority learns: who registered and which tag they hold. With the
ballot box's cooperation it could learn *who voted when* -- never *how*:
votes are encrypted under the trustees' threshold key. That is the price of
revoting; protocol v1 (blind credentials) did not have it and did not resist
coercion. See docs/coercion.md.

One registration per roll entry is enforced by a PRIMARY KEY on
``registration.voter_id``; tags are globally unique (``tags.tag`` PRIMARY KEY).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from ..crypto.encoding import from_hex, to_hex
from ..crypto.group import Group
from ..crypto.proofs import SchnorrProof, schnorr_verify
from ..crypto.signing import RoleKey
from .clock import hour_bucket
from .identity import IdentityError, IdentityHub, face_match
from .roll import SyntheticVoter

log = logging.getLogger("chunaviq.eligibility")

MAX_FAILED_AUTH = 5
MAX_REGISTRATIONS = 6  # first registration + 5 re-registrations per election
SESSION_TTL_S = 600


class EligibilityError(Exception):
    def __init__(self, code: str, msg: str = "") -> None:
        super().__init__(f"{code}: {msg}" if msg else code)
        self.code = code


def participation_commitment(election_id: str, voter_id: str, salt: bytes) -> str:
    return hashlib.sha256(b"chunaviq/v1/participation\x00" + election_id.encode() + b"\x00" + voter_id.encode() + b"\x00" + salt).hexdigest()


def register_context(election_id: str, constituency: str, session: str) -> list:
    return [election_id, "register", constituency, session]


class EligibilityAuthority:
    def __init__(self, db_path: Path, election_id: str, constituencies: list[str], clock, group: Group, identity: IdentityHub) -> None:
        self.db_path = str(db_path)
        self.election_id = election_id
        self.constituencies = sorted(constituencies)
        self.clock = clock
        self.group = group
        self.identity = identity
        self.key = RoleKey("eligibility")
        self._hkey = secrets.token_bytes(32)  # keyed hashes of identifiers; never published
        self._local = threading.local()
        self._lock = threading.Lock()
        self._accepting = False
        self._sessions: dict[str, tuple[str, float]] = {}
        self._pan_txn: dict[str, tuple[str, str, int]] = {}  # txn -> (voter_id, otp, attempts)
        with self._conn() as con:
            con.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS voters(
                    voter_id TEXT PRIMARY KEY, constituency TEXT NOT NULL,
                    aadhaar_h BLOB UNIQUE, pan_h BLOB UNIQUE,
                    mobile_ref TEXT NOT NULL, photo BLOB NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('eligible','removed')));
                CREATE TABLE IF NOT EXISTS failures(id_h BLOB PRIMARY KEY, n INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS registration(
                    voter_id TEXT PRIMARY KEY REFERENCES voters(voter_id),
                    constituency TEXT NOT NULL, tag TEXT NOT NULL UNIQUE,
                    commitment TEXT NOT NULL UNIQUE, salt BLOB NOT NULL,
                    generation INTEGER NOT NULL, in_person INTEGER NOT NULL DEFAULT 0,
                    bucket TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS tags(tag TEXT PRIMARY KEY, constituency TEXT NOT NULL);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        con = getattr(self._local, "con", None)
        if con is None:
            con = sqlite3.connect(self.db_path, isolation_level=None, timeout=30, check_same_thread=False)
            self._local.con = con
        return con

    def _h(self, kind: str, value: str) -> bytes:
        return hmac.new(self._hkey, kind.encode() + b"\x00" + value.encode(), hashlib.sha256).digest()

    # ------------------------------------------------------------------------ roll
    def load_roll(self, roll: list[SyntheticVoter]) -> None:
        rows = []
        for v in roll:
            if v.constituency not in self.constituencies:
                raise EligibilityError("UNKNOWN_CONSTITUENCY", v.constituency)
            # Aadhaar linkage exists only where the elector supplied it (Form 6B); all synthetic electors have.
            ah = self._h("uid", self.identity.uidai.uid_token_for_linkage(v.aadhaar_ref))
            ph = self._h("pan", v.pan_ref) if v.pan_ref else None
            rows.append((v.voter_id, v.constituency, ah, ph, v.mobile_ref, v.face, "eligible"))
        con = self._conn()
        con.execute("BEGIN IMMEDIATE")
        con.executemany("INSERT INTO voters(voter_id,constituency,aadhaar_h,pan_h,mobile_ref,photo,status) VALUES(?,?,?,?,?,?,?)", rows)
        con.execute("COMMIT")

    def set_accepting(self, accepting: bool) -> None:
        """Registration is open from READY until the online voting window closes."""
        self._accepting = accepting

    # ---------------------------------------------------------------- identity
    def _check_lock(self, id_h: bytes) -> None:
        row = self._conn().execute("SELECT n FROM failures WHERE id_h=?", (id_h,)).fetchone()
        if row and row[0] >= MAX_FAILED_AUTH:
            raise EligibilityError("LOCKED", "too many failed verification attempts")

    def _fail(self, id_h: bytes) -> None:
        self._conn().execute("INSERT INTO failures(id_h,n) VALUES(?,1) ON CONFLICT(id_h) DO UPDATE SET n=n+1", (id_h,))

    def _session_for(self, voter_id: str) -> str:
        s = secrets.token_hex(16)
        with self._lock:
            self._sessions[s] = (voter_id, time.monotonic() + SESSION_TTL_S)
        return s

    def _voter_by(self, column: str, id_h: bytes) -> str:
        row = self._conn().execute(f"SELECT voter_id, status FROM voters WHERE {column}=?", (id_h,)).fetchone()  # noqa: S608 - column is internal
        if row is None:
            raise EligibilityError("NOT_ON_ROLL")
        if row[1] != "eligible":
            raise EligibilityError("REMOVED_FROM_ROLL")
        return row[0]

    def aadhaar_otp_start(self, aadhaar_ref: str) -> str:
        self._check_lock(self._h("ref", aadhaar_ref))
        try:
            return self.identity.uidai.request_otp(aadhaar_ref)
        except IdentityError as e:
            raise EligibilityError(e.code) from None

    def aadhaar_otp_finish(self, aadhaar_ref: str, txn: str, otp: str) -> str:
        id_h = self._h("ref", aadhaar_ref)
        self._check_lock(id_h)
        try:
            token = self.identity.uidai.verify_otp(txn, otp)
        except IdentityError as e:
            self._fail(id_h)
            raise EligibilityError(e.code) from None
        return self._session_for(self._voter_by("aadhaar_h", self._h("uid", token)))

    def aadhaar_face(self, aadhaar_ref: str, capture: bytes) -> str:
        id_h = self._h("ref", aadhaar_ref)
        self._check_lock(id_h)
        try:
            token = self.identity.uidai.face_auth(aadhaar_ref, capture)
        except IdentityError as e:
            self._fail(id_h)
            raise EligibilityError(e.code) from None
        return self._session_for(self._voter_by("aadhaar_h", self._h("uid", token)))

    def pan_start(self, pan_ref: str, name: str, dob: str) -> str:
        """PAN check, then an OTP to the mobile number on the electoral roll."""
        id_h = self._h("pan", pan_ref)
        self._check_lock(id_h)
        res = self.identity.pan.verify(pan_ref, name, dob)
        if res["status"] != "valid" or not (res["name_match"] and res["dob_match"]):
            self._fail(id_h)
            raise EligibilityError("PAN_MISMATCH")
        voter_id = self._voter_by("pan_h", id_h)
        mobile = self._conn().execute("SELECT mobile_ref FROM voters WHERE voter_id=?", (voter_id,)).fetchone()[0]
        txn, code = secrets.token_hex(8), f"{secrets.randbelow(10**6):06d}"
        with self._lock:
            self._pan_txn[txn] = (voter_id, code, 0)
        self.identity.phones.deliver(mobile, code)
        return txn

    def pan_finish(self, pan_ref: str, txn: str, otp: str, capture: bytes) -> str:
        """Second and third factors for PAN: roll-mobile OTP AND face match to the roll photo."""
        id_h = self._h("pan", pan_ref)
        self._check_lock(id_h)
        with self._lock:
            t = self._pan_txn.get(txn)
            if t is None:
                raise EligibilityError("OTP_EXPIRED")
            voter_id, code, attempts = t
            self._pan_txn[txn] = (voter_id, code, attempts + 1)
            if attempts + 1 > 3:
                del self._pan_txn[txn]
                raise EligibilityError("OTP_EXPIRED")
        if not hmac.compare_digest(code, otp):
            self._fail(id_h)
            raise EligibilityError("OTP_MISMATCH")
        photo = self._conn().execute("SELECT photo FROM voters WHERE voter_id=?", (voter_id,)).fetchone()[0]
        if not face_match(photo, capture):
            self._fail(id_h)
            raise EligibilityError("FACE_MISMATCH")
        with self._lock:
            self._pan_txn.pop(txn, None)
        return self._session_for(voter_id)

    # ---------------------------------------------------------------- registration
    def register(self, session: str, tag_hex: str, proof: dict) -> dict:
        """Register (or re-register) the device tag for the authenticated roll entry."""
        if not self._accepting:
            raise EligibilityError("NOT_ACCEPTING")
        with self._lock:
            entry = self._sessions.pop(session, None)
        if entry is None or entry[1] < time.monotonic():
            raise EligibilityError("NO_SESSION")
        voter_id = entry[0]
        grp = self.group
        try:
            T = from_hex(tag_hex)
            pok = SchnorrProof.from_dict(proof)
        except (ValueError, KeyError, TypeError):
            raise EligibilityError("MALFORMED") from None
        con = self._conn()
        cons = con.execute("SELECT constituency FROM voters WHERE voter_id=?", (voter_id,)).fetchone()[0]
        if T == 1 or not schnorr_verify(grp, T, pok, register_context(self.election_id, cons, session)):
            raise EligibilityError("BAD_TAG_PROOF")
        con.execute("BEGIN IMMEDIATE")
        try:
            prev = con.execute("SELECT generation, in_person, commitment, salt FROM registration WHERE voter_id=?", (voter_id,)).fetchone()
            try:
                con.execute("INSERT INTO tags(tag, constituency) VALUES(?,?)", (to_hex(T), cons))
            except sqlite3.IntegrityError:
                raise EligibilityError("TAG_REUSED") from None
            bucket = hour_bucket(self.clock.now())
            if prev is None:
                salt = secrets.token_bytes(16)
                commitment = participation_commitment(self.election_id, voter_id, salt)
                con.execute(
                    "INSERT INTO registration(voter_id,constituency,tag,commitment,salt,generation,bucket) VALUES(?,?,?,?,?,1,?)",
                    (voter_id, cons, to_hex(T), commitment, salt, bucket),
                )
                generation = 1
            else:
                generation, in_person, commitment, salt = prev
                if in_person:
                    raise EligibilityError("VOTED_IN_PERSON")
                if generation >= MAX_REGISTRATIONS:
                    raise EligibilityError("TOO_MANY_REGISTRATIONS")
                generation += 1
                con.execute("UPDATE registration SET tag=?, generation=?, bucket=? WHERE voter_id=?", (to_hex(T), generation, bucket, voter_id))
            con.execute("COMMIT")
        except Exception:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise
        log.info("registration generation=%d", generation)  # no identifiers in logs
        return {"constituency": cons, "generation": generation, "commitment": commitment, "participation_salt": bytes(salt).hex()}

    def mark_voted_in_person(self, voter_id: str) -> bool:
        """Polling-day override. Returns True if an online tag was revoked."""
        con = self._conn()
        con.execute("BEGIN IMMEDIATE")
        cur = con.execute("UPDATE registration SET in_person=1 WHERE voter_id=? AND in_person=0", (voter_id,))
        con.execute("COMMIT")
        return cur.rowcount == 1

    # ----------------------------------------------------- ballot box interfaces
    def known_tag(self, constituency: str, tag_hex: str) -> bool:
        """Was this tag ever registered in this constituency? (Revoked tags still
        answer True: the ballot box must not reveal revocation while voting is open.)"""
        row = self._conn().execute("SELECT constituency FROM tags WHERE tag=?", (tag_hex,)).fetchone()
        return row is not None and row[0] == constituency

    def valid_tags(self, constituency: str) -> list[str]:
        rows = self._conn().execute("SELECT tag FROM registration WHERE constituency=? AND in_person=0", (constituency,))
        return sorted(r[0] for r in rows)

    # --------------------------------------------------------- post-close summary
    def registration_summary(self) -> dict:
        """Full state per constituency (internal use and tests; NOT the published form)."""
        con = self._conn()
        out = {}
        for c in self.constituencies:
            eligible = con.execute("SELECT COUNT(*) FROM voters WHERE constituency=?", (c,)).fetchone()[0]
            regs = con.execute("SELECT commitment, generation, in_person FROM registration WHERE constituency=?", (c,)).fetchall()
            out[c] = {
                "eligible": eligible,
                "registered": len(regs),
                "commitments": sorted(r[0] for r in regs),
                "reregistrations": sum(r[1] - 1 for r in regs),
                "voted_in_person": sum(r[2] for r in regs),
                "valid_tags": self.valid_tags(c),
            }
        return {"election_id": self.election_id, "constituencies": out}

    def registration_entries(self, chunk: int = 4096) -> list[tuple[str, dict]]:
        """Published form: one signed summary with counts and digests, then the sorted
        lists in signed chunks -- so no record line grows with the electorate."""
        full = self.registration_summary()["constituencies"]
        summary = {"election_id": self.election_id, "chunk_size": chunk, "constituencies": {}}
        lists: list[tuple[str, dict]] = []
        for c in self.constituencies:
            f = full[c]
            summary["constituencies"][c] = {
                "eligible": f["eligible"],
                "registered": f["registered"],
                "reregistrations": f["reregistrations"],
                "voted_in_person": f["voted_in_person"],
                "valid_tags": len(f["valid_tags"]),
                "commitments_sha256": list_digest(f["commitments"]),
                "valid_tags_sha256": list_digest(f["valid_tags"]),
            }
            for kind in ("commitments", "valid_tags"):
                items = f[kind]
                for i in range(0, len(items), chunk):
                    lists.append(
                        ("registration_list", self.key.sign_body({"constituency": c, "list": kind, "index": i // chunk, "items": items[i : i + chunk]}))
                    )
        return [("registration_summary", self.key.sign_body(summary)), *lists]


def list_digest(items: list[str]) -> str:
    return hashlib.sha256(b"".join(x.encode() + b"\n" for x in items)).hexdigest()
