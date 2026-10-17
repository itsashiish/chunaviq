"""Eligibility authority: authenticates voters and blind-signs one credential each.

Holds the (synthetic) roll and one RSA blind-signing key per constituency. It
learns *who* obtained a credential but never sees the credential itself, so it
cannot tell which ballot belongs to whom. It never receives ballot content.

One-credential-per-voter is enforced by a PRIMARY KEY on ``issuance.voter_id``
inside an IMMEDIATE transaction, so concurrent requests for the same voter
cannot both succeed (tests/test_concurrency.py).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import sqlite3
import threading
from pathlib import Path

from ..crypto.blind import RSABlindSigner, RSAPublic
from ..crypto.encoding import from_hex, to_hex
from ..crypto.signing import RoleKey
from .clock import hour_bucket
from .roll import SyntheticVoter

log = logging.getLogger("evlab.eligibility")

MAX_FAILED_AUTH = 5


class EligibilityError(Exception):
    def __init__(self, code: str, msg: str = "") -> None:
        super().__init__(f"{code}: {msg}" if msg else code)
        self.code = code


def participation_commitment(election_id: str, voter_id: str, salt: bytes) -> str:
    return hashlib.sha256(b"evlab/v1/participation\x00" + election_id.encode() + b"\x00" + voter_id.encode() + b"\x00" + salt).hexdigest()


class EligibilityAuthority:
    def __init__(self, db_path: Path, election_id: str, constituencies: list[str], clock, rsa_bits: int = 3072) -> None:
        self.db_path = str(db_path)
        self.election_id = election_id
        self.clock = clock
        self.key = RoleKey("eligibility")
        self.signers = {c: RSABlindSigner(rsa_bits) for c in constituencies}
        self._local = threading.local()
        self._accepting = False
        with self._conn() as con:
            con.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS voters(
                    voter_id TEXT PRIMARY KEY, constituency TEXT NOT NULL,
                    auth_salt BLOB NOT NULL, auth_hash BLOB NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('eligible','revoked')),
                    failed_auth INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS issuance(
                    voter_id TEXT PRIMARY KEY REFERENCES voters(voter_id),
                    constituency TEXT NOT NULL, commitment TEXT NOT NULL UNIQUE,
                    salt BLOB NOT NULL, issued_bucket TEXT NOT NULL);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        con = getattr(self._local, "con", None)
        if con is None:
            con = sqlite3.connect(self.db_path, isolation_level=None, timeout=30, check_same_thread=False)
            self._local.con = con
        return con

    # ------------------------------------------------------------------ public keys
    def issuer_keys(self) -> dict[str, RSAPublic]:
        return {c: s.public for c, s in self.signers.items()}

    def issuer_keys_entry(self) -> dict:
        return self.key.sign_body({"election_id": self.election_id, "issuer_keys": {c: k.to_dict() for c, k in sorted(self.issuer_keys().items())}})

    # ------------------------------------------------------------------------ roll
    def load_roll(self, roll: list[SyntheticVoter]) -> None:
        rows = []
        for v in roll:
            if v.constituency not in self.signers:
                raise EligibilityError("UNKNOWN_CONSTITUENCY", v.constituency)
            salt = secrets.token_bytes(16)
            rows.append((v.voter_id, v.constituency, salt, hmac.new(salt, v.auth_secret, hashlib.sha256).digest(), "eligible"))
        con = self._conn()
        con.execute("BEGIN IMMEDIATE")
        con.executemany("INSERT INTO voters(voter_id,constituency,auth_salt,auth_hash,status) VALUES(?,?,?,?,?)", rows)
        con.execute("COMMIT")

    def set_accepting(self, accepting: bool) -> None:
        """Opened by the administration when the election reaches READY/OPEN and
        closed at CLOSE. Issuance outside that window is refused."""
        self._accepting = accepting

    def revoke(self, voter_id: str) -> None:
        con = self._conn()
        con.execute("BEGIN IMMEDIATE")
        try:
            if con.execute("SELECT 1 FROM issuance WHERE voter_id=?", (voter_id,)).fetchone():
                raise EligibilityError("ALREADY_ISSUED", "an anonymous credential cannot be recalled once issued")
            cur = con.execute("UPDATE voters SET status='revoked' WHERE voter_id=?", (voter_id,))
            if cur.rowcount != 1:
                raise EligibilityError("NOT_ON_ROLL")
            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            raise

    # ---------------------------------------------------------------- issuance
    def issue_credential(self, voter_id: str, auth_secret: bytes, blinded_hex: str) -> dict:
        if not self._accepting:
            raise EligibilityError("NOT_ACCEPTING")
        con = self._conn()
        con.execute("BEGIN IMMEDIATE")
        try:
            row = con.execute("SELECT constituency, auth_salt, auth_hash, status, failed_auth FROM voters WHERE voter_id=?", (voter_id,)).fetchone()
            if row is None:
                raise EligibilityError("NOT_ON_ROLL")
            constituency, salt, auth_hash, status, failed = row
            if failed >= MAX_FAILED_AUTH:
                raise EligibilityError("LOCKED", "too many failed authentication attempts")
            if not hmac.compare_digest(hmac.new(salt, auth_secret, hashlib.sha256).digest(), auth_hash):
                con.execute("UPDATE voters SET failed_auth=failed_auth+1 WHERE voter_id=?", (voter_id,))
                con.execute("COMMIT")
                raise EligibilityError("AUTH_FAILED")
            if status != "eligible":
                raise EligibilityError("REVOKED")
            psalt = secrets.token_bytes(16)
            commitment = participation_commitment(self.election_id, voter_id, psalt)
            try:
                con.execute(
                    "INSERT INTO issuance(voter_id,constituency,commitment,salt,issued_bucket) VALUES(?,?,?,?,?)",
                    (voter_id, constituency, commitment, psalt, hour_bucket(self.clock.now())),
                )
            except sqlite3.IntegrityError:
                raise EligibilityError("ALREADY_ISSUED") from None
            blind_sig = self.signers[constituency].sign_blinded(from_hex(blinded_hex))
            con.execute("COMMIT")
        except EligibilityError as e:
            if con.in_transaction:
                con.execute("ROLLBACK")
            log.info("issuance refused code=%s", e.code)  # no voter identifier in logs
            raise
        except Exception:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise
        return {"constituency": constituency, "blind_signature": to_hex(blind_sig), "participation_salt": psalt.hex(), "commitment": commitment}

    # --------------------------------------------------------- post-close summary
    def participation_summary(self) -> dict:
        con = self._conn()
        out = {}
        for c in sorted(self.signers):
            eligible = con.execute("SELECT COUNT(*) FROM voters WHERE constituency=?", (c,)).fetchone()[0]
            commits = sorted(r[0] for r in con.execute("SELECT commitment FROM issuance WHERE constituency=?", (c,)))
            out[c] = {"eligible": eligible, "credentials_issued": len(commits), "commitments": commits}
        return self.key.sign_body({"election_id": self.election_id, "constituencies": out})
