"""Append-only public bulletin board (the election record).

Every entry is a canonical-JSON line in ``entries.jsonl``; its leaf in an
RFC 6962 Merkle tree is the entry's exact bytes. The board operator signs
checkpoints (tree size + root + consistency proof from the previous
checkpoint) into ``checkpoints.jsonl``. The board is the source of truth: the
ballot box's database is only an index that can be rebuilt from it.

Single-writer by design: one process appends; any number of observers read.
"""

from __future__ import annotations

import json
import os
import threading
from array import array
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from ..crypto.encoding import canonical_json, sha256_hex
from ..crypto.merkle import MerkleTree, verify_consistency
from ..crypto.signing import RoleKey, verify_body
from .clock import hour_bucket

LIFECYCLE_ORDER = ["DRAFT", "KEY_CEREMONY", "READY", "OPEN", "CLOSED", "TALLIED", "PUBLISHED"]


class BoardError(Exception):
    pass


class Board:
    """Memory use is O(entries x 40 bytes) -- Merkle leaf hashes and byte offsets --
    never O(record size). Entry bodies live only on disk and are streamed back
    with ``iter_entries``; a 58-lakh-ballot constituency therefore needs a few
    hundred MB, not the hundreds of GB its record occupies."""

    def __init__(self, directory: Path, election_id: str, operator: RoleKey, clock, durable: bool = True) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.election_id = election_id
        self.operator = operator
        self.clock = clock
        self.durable = durable
        self.tree = MerkleTree()
        self.checkpoints: list[dict] = []
        self.state = "DRAFT"
        self._offsets = array("Q")
        self._end = 0
        self._counts: Counter[str] = Counter()
        self._lock = threading.RLock()
        self._entries_path = self.dir / "entries.jsonl"
        self._cp_path = self.dir / "checkpoints.jsonl"
        if self._entries_path.exists():
            self._load()

    # ------------------------------------------------------------------ persistence
    def _write_line(self, path: Path, data: bytes) -> None:
        with open(path, "ab") as f:
            f.write(data + b"\n")
            if self.durable:
                f.flush()
                os.fsync(f.fileno())

    def _track(self, entry_type: str, line: bytes, state: str | None) -> None:
        self._offsets.append(self._end)
        self._end += len(line) + 1
        self.tree.append(line)
        self._counts[entry_type] += 1
        if state is not None:
            self.state = state

    def _load(self) -> None:
        """Crash recovery: rebuild the tree and refuse to continue if the stored
        entries disagree with any checkpoint the operator already signed."""
        with open(self._entries_path, "rb") as f:
            for i, raw in enumerate(f):
                line = raw.rstrip(b"\n")
                entry = json.loads(line)
                if canonical_json(entry) != line or entry.get("seq") != self.size:
                    raise BoardError(f"entries.jsonl line {i} is not canonical or out of sequence")
                self._track(entry["type"], line, entry["body"]["state"] if entry["type"] == "lifecycle" else None)
        if self._cp_path.exists():
            for line in self._cp_path.read_bytes().split(b"\n"):
                if line:
                    cp = json.loads(line)
                    if not verify_body(cp, self.operator.public_hex, "board"):
                        raise BoardError("checkpoint signature invalid on reload")
                    if cp["tree_size"] > len(self.tree) or self.tree.root(cp["tree_size"]).hex() != cp["root"]:
                        raise BoardError("stored entries do not match a signed checkpoint (tampering or truncation)")
                    self.checkpoints.append(cp)

    # ------------------------------------------------------------------ reading
    @property
    def size(self) -> int:
        return len(self._offsets)

    def count(self, entry_type: str) -> int:
        return self._counts[entry_type]

    def line(self, seq: int) -> bytes:
        with open(self._entries_path, "rb") as f:
            f.seek(self._offsets[seq])
            return f.readline().rstrip(b"\n")

    def entry(self, seq: int) -> dict:
        return json.loads(self.line(seq))

    def iter_entries(self, entry_type: str | None = None) -> Iterator[dict]:
        """Stream entries from disk (constant memory)."""
        if not self._entries_path.exists():
            return
        needle = None if entry_type is None else b'"type":"' + entry_type.encode() + b'"'
        with open(self._entries_path, "rb") as f:
            for raw in f:
                if needle is not None and needle not in raw:
                    continue
                e = json.loads(raw)
                if entry_type is None or e["type"] == entry_type:
                    yield e

    @property
    def entries(self) -> list[dict]:
        """Every entry, loaded from disk. O(record size): for tests and small
        elections only; production paths use iter_entries / count / size."""
        return list(self.iter_entries())

    def entries_of(self, entry_type: str) -> list[dict]:
        return list(self.iter_entries(entry_type))

    # ---------------------------------------------------------------------- append
    def append(self, entry_type: str, body: dict) -> dict:
        with self._lock:
            if entry_type == "lifecycle":
                new = body["state"]
                if LIFECYCLE_ORDER.index(new) != LIFECYCLE_ORDER.index(self.state) + 1:
                    raise BoardError(f"illegal lifecycle transition {self.state} -> {new}")
            entry = {
                "seq": self.size,
                "type": entry_type,
                "time_bucket": hour_bucket(self.clock.now()),
                "body": body,
            }
            data = canonical_json(entry)
            self._write_line(self._entries_path, data)
            self._track(entry_type, data, body["state"] if entry_type == "lifecycle" else None)
            return entry

    def append_ballots(self, bodies: list[dict]) -> list[dict]:
        """Group commit: append many ballot entries with ONE write and ONE fsync.
        Callers acknowledge a voter only after this returns, so durability is the
        same as appending one at a time, at a fraction of the disk cost."""
        with self._lock:
            if not bodies:
                return []
            bucket = hour_bucket(self.clock.now())
            entries, lines = [], []
            for i, body in enumerate(bodies):
                entry = {"seq": self.size + i, "type": "ballot", "time_bucket": bucket, "body": body}
                entries.append(entry)
                lines.append(canonical_json(entry))
            with open(self._entries_path, "ab") as f:
                f.write(b"".join(line + b"\n" for line in lines))
                if self.durable:
                    f.flush()
                    os.fsync(f.fileno())
            for line in lines:
                self._track("ballot", line, None)
            return entries

    def checkpoint(self) -> dict:
        with self._lock:
            size = len(self.tree)
            prev = self.checkpoints[-1] if self.checkpoints else None
            if prev and prev["tree_size"] == size:
                return prev
            proof = []
            if prev and prev["tree_size"] > 0:
                proof = [h.hex() for h in self.tree.consistency_proof(prev["tree_size"], size)]
            body = {
                "election_id": self.election_id,
                "tree_size": size,
                "root": self.tree.root().hex(),
                "time_bucket": hour_bucket(self.clock.now()),
                "prev_tree_size": prev["tree_size"] if prev else 0,
                "consistency_proof": proof,
            }
            cp = self.operator.sign_body(body)
            if prev and prev["tree_size"] > 0:
                ok = verify_consistency(prev["tree_size"], size, bytes.fromhex(prev["root"]), self.tree.root(), [bytes.fromhex(h) for h in proof])
                if not ok:  # pragma: no cover - would indicate a bug in the tree
                    raise BoardError("consistency self-check failed")
            self._write_line(self._cp_path, canonical_json(cp))
            self.checkpoints.append(cp)
            return cp

    # ------------------------------------------------------------------- receipts
    def receipt(self, seq: int) -> dict:
        """Inclusion evidence for one entry against the latest checkpoint."""
        cp = self.checkpoints[-1]
        if seq >= cp["tree_size"]:
            raise BoardError("entry not yet covered by a signed checkpoint")
        entry = self.entry(seq)
        leaves = self.tree.levels[0][: cp["tree_size"]]
        from ..crypto.merkle import reference_path

        path = reference_path(seq, leaves) if cp["tree_size"] != len(self.tree) else self.tree.inclusion_proof(seq)
        return {
            "tracking_code": entry["body"].get("tracking_code"),
            "seq": seq,
            "entry_sha256": sha256_hex(canonical_json(entry)),
            "tree_size": cp["tree_size"],
            "root": cp["root"],
            "inclusion_path": [h.hex() for h in path],
        }
