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
from pathlib import Path

from ..crypto.encoding import canonical_json, sha256_hex
from ..crypto.merkle import MerkleTree, verify_consistency
from ..crypto.signing import RoleKey, verify_body
from .clock import hour_bucket

LIFECYCLE_ORDER = ["DRAFT", "KEY_CEREMONY", "READY", "OPEN", "CLOSED", "TALLIED", "PUBLISHED"]


class BoardError(Exception):
    pass


class Board:
    def __init__(self, directory: Path, election_id: str, operator: RoleKey, clock, durable: bool = True) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.election_id = election_id
        self.operator = operator
        self.clock = clock
        self.durable = durable
        self.tree = MerkleTree()
        self.entries: list[dict] = []
        self.checkpoints: list[dict] = []
        self.state = "DRAFT"
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

    def _load(self) -> None:
        """Crash recovery: rebuild the tree and refuse to continue if the stored
        entries disagree with any checkpoint the operator already signed."""
        raw_lines = self._entries_path.read_bytes().split(b"\n")
        for i, line in enumerate(raw_lines):
            if not line:
                continue
            entry = json.loads(line)
            if canonical_json(entry) != line or entry.get("seq") != len(self.entries):
                raise BoardError(f"entries.jsonl line {i} is not canonical or out of sequence")
            self.entries.append(entry)
            self.tree.append(line)
            if entry["type"] == "lifecycle":
                self.state = entry["body"]["state"]
        if self._cp_path.exists():
            for line in self._cp_path.read_bytes().split(b"\n"):
                if line:
                    cp = json.loads(line)
                    if not verify_body(cp, self.operator.public_hex, "board"):
                        raise BoardError("checkpoint signature invalid on reload")
                    if cp["tree_size"] > len(self.tree) or self.tree.root(cp["tree_size"]).hex() != cp["root"]:
                        raise BoardError("stored entries do not match a signed checkpoint (tampering or truncation)")
                    self.checkpoints.append(cp)

    # ---------------------------------------------------------------------- append
    def append(self, entry_type: str, body: dict) -> dict:
        with self._lock:
            if entry_type == "lifecycle":
                new = body["state"]
                if LIFECYCLE_ORDER.index(new) != LIFECYCLE_ORDER.index(self.state) + 1:
                    raise BoardError(f"illegal lifecycle transition {self.state} -> {new}")
            entry = {
                "seq": len(self.entries),
                "type": entry_type,
                "time_bucket": hour_bucket(self.clock.now()),
                "body": body,
            }
            data = canonical_json(entry)
            self._write_line(self._entries_path, data)
            self.entries.append(entry)
            self.tree.append(data)
            if entry_type == "lifecycle":
                self.state = body["state"]
            return entry

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
        entry = self.entries[seq]
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

    def entries_of(self, entry_type: str) -> list[dict]:
        return [e for e in self.entries if e["type"] == entry_type]
