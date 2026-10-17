"""Fine-grained election harness for tests (simulate.run is the end-to-end one)."""

from __future__ import annotations

import datetime as dt
import json
import shutil
from pathlib import Path

from chunaviq.crypto.encoding import canonical_json
from chunaviq.crypto.group import get_group
from chunaviq.crypto.merkle import MerkleTree
from chunaviq.crypto.signing import RoleKey
from chunaviq.custody import CustodyPolicy
from chunaviq.election.administration import Administration, Observer, TrusteeHost
from chunaviq.election.ballotbox import BallotBox
from chunaviq.election.board import Board
from chunaviq.election.client import VoterDevice
from chunaviq.election.clock import FakeClock, iso
from chunaviq.election.eligibility import EligibilityAuthority
from chunaviq.election.identity import IdentityHub
from chunaviq.election.manifest import build_manifest
from chunaviq.election.roll import make_constituencies, make_roll

OPENS = dt.datetime(2026, 11, 2, 1, 30, tzinfo=dt.UTC)
CLOSES = OPENS + dt.timedelta(days=6, hours=11)


class Election:
    """Builds an election up to READY (or OPEN with open_now=True)."""

    def __init__(
        self,
        tmp: Path,
        *,
        voters_per=(6, 6),
        candidates=3,
        trustees=3,
        threshold=2,
        min_mixers=2,
        mix_batch=4,
        max_per_tag=30,
        group="CHUNAVIQ-2048-256-V1",
        open_now=True,
    ) -> None:
        self.tmp = Path(tmp)
        self.grp = get_group(group)
        self.clock = FakeClock(OPENS - dt.timedelta(days=1))
        self.officer, self.operator = RoleKey("officer"), RoleKey("board")
        self.hosts = [TrusteeHost(i + 1, self.grp, threshold) for i in range(trustees)]
        self.observers = [Observer() for _ in range(3)]
        self.cons = make_constituencies(len(voters_per), candidates, list(voters_per), seed=7)
        self.roll = make_roll(self.cons, seed=7)
        self.hub = IdentityHub.synthetic(self.roll)
        (self.tmp / "private").mkdir(parents=True, exist_ok=True)
        self.elig = EligibilityAuthority(self.tmp / "private" / "elig.db", "SYN-TEST", [c.id for c in self.cons], self.clock, self.grp, self.hub)
        self.elig.load_roll(self.roll)
        self.record = self.tmp / "record"
        self.board = Board(self.record, "SYN-TEST", self.operator, self.clock, durable=False)
        self.admin = Administration(self.board, self.officer, self.grp, self.hosts, self.clock, self.observers)
        self.manifest = build_manifest(
            election_id="SYN-TEST",
            title="Test election",
            group_name=group,
            constituencies=self.cons,
            opens_at=iso(OPENS),
            closes_at=iso(CLOSES),
            threshold=threshold,
            trustee_keys=[h.key.public_hex for h in self.hosts],
            officer_key=self.officer.public_hex,
            board_key=self.operator.public_hex,
            eligibility_key=self.elig.key.public_hex,
            software_version="test",
            min_mixers=min_mixers,
            mix_batch=mix_batch,
            max_ballots_per_tag=max_per_tag,
        )
        self.mhash = self.admin.publish_manifest(self.manifest)
        for h in self.hosts:
            h.install(CustodyPolicy(["SYN-TEST"], [self.officer.public_hex], h.operator_keys, 2, [o.key.public_hex for o in self.observers], 2, 10_000))
        self.pk = self.admin.key_ceremony()
        self.admin.ready()
        self.elig.set_accepting(True)
        self.box = BallotBox(self.tmp / "private" / "box.db", self.board, self.manifest, self.mhash, self.pk, self.clock, self.elig.known_tag, max_per_tag)
        self.options = self.box.options
        self.devices: dict[int, VoterDevice] = {}
        self.in_person: list[int] = []
        if open_now:
            self.open()

    def open(self) -> None:
        self.clock.set(OPENS + dt.timedelta(minutes=5))
        self.admin.open()

    def device(self, i: int) -> VoterDevice:
        v = self.roll[i]
        return VoterDevice(v, "SYN-TEST", self.mhash, self.pk, self.options[v.constituency])

    def registered(self, i: int, method: str = "aadhaar-otp") -> VoterDevice:
        d = self.devices.get(i)
        if d is None:
            d = self.device(i)
            d.register(self.elig, method)
            self.devices[i] = d
        return d

    def sub(self, d: VoterDevice, choice: str) -> dict:
        return d.submission(d.prepare(choice))

    def cast(self, d: VoterDevice, choice: str) -> dict:
        r = self.box.submit(self.sub(d, choice))
        d.cast.append(r["tracking_code"])
        return r

    def vote(self, i: int, choice_index: int = 0) -> dict:
        d = self.registered(i)
        return self.cast(d, self.options[d.voter.constituency][choice_index])

    def close_and_tally(self) -> dict:
        self.clock.set(CLOSES)
        self.elig.set_accepting(False)
        self.admin.close(dict(self.box.rejections))
        for i in self.in_person:
            self.elig.mark_voted_in_person(self.roll[i].voter_id)
        self.admin.publish_registration(self.elig.registration_entries(), {c: set(self.elig.valid_tags(c)) for c in self.elig.constituencies})
        self.box.finalize(self.admin.valid_tags)
        res = self.admin.tally()
        self.admin.publish()
        return res


# ---------------------------------------------------------------- record tampering
def load_entries(record: Path) -> list[dict]:
    return [json.loads(x) for x in (record / "entries.jsonl").read_bytes().split(b"\n") if x]


def write_entries(record: Path, entries: list[dict]) -> None:
    (record / "entries.jsonl").write_bytes(b"".join(canonical_json(e) + b"\n" for e in entries))


def resign_checkpoints(record: Path, operator: RoleKey, election_id: str = "SYN-TEST") -> None:
    """Model an insider who controls the board key: rewrite the entries, then
    produce fresh, correctly signed checkpoints over the forged history. The
    verifier must still catch the forgery through the cryptography beneath."""
    entries = load_entries(record)
    t = MerkleTree()
    for e in entries:
        t.append(canonical_json(e))
    body = {
        "election_id": election_id,
        "tree_size": len(t),
        "root": t.root().hex(),
        "time_bucket": entries[-1]["time_bucket"],
        "prev_tree_size": 0,
        "consistency_proof": [],
    }
    (record / "checkpoints.jsonl").write_bytes(canonical_json(operator.sign_body(body)) + b"\n")


def copy_record(src: Path, dst: Path) -> Path:
    shutil.copytree(src, dst)
    return dst
