"""Ballot-intake service for one constituency shard, hardened against denial of service.

    python -m chunaviq.service.sequencer --election DIR --port 8080 --workers 8

Defences, cheapest first -- an attacker must get past each before costing the next:

  1. connection limits and header/body deadlines            (httpd.HTTPServer)
  2. body size cap, checked from Content-Length              (httpd.HTTPServer)
  3. per-client token bucket (the edge sets X-Client from the source address)
  4. load shedding: a bounded verification queue; when full, 503 + Retry-After
     (clients retry with exponential backoff and jitter; retries are idempotent)
  5. strict JSON schema, election and constituency checks
  6. idempotent replay: an already-recorded ballot returns its receipt, no work
  7. the claimed tag must be registered in this constituency (a database lookup):
     nobody without a registration can make the server do expensive work
  8. per-tag rate limit: a registered tag gets at most one expensive check per
     interval, so even a bought or stolen registration cannot flood the provers
  9. only then: proof verification, in a bounded process pool
 10. group commit: one transaction and one fsync per batch, receipts after fsync

Revocation is never visible here (a revoked tag is still "registered"), exactly
as in the library ballot box.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import multiprocessing as mp
import os
import signal
import sqlite3
import threading
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

from ..crypto.elgamal import PublicKey
from ..crypto.group import get_group
from ..crypto.signing import RoleKey
from ..election.ballot import BALLOT_KEYS, tracking_code
from ..election.ballotbox import SUBMISSION_KEYS, BallotBox
from ..election.board import Board
from ..election.clock import SystemClock
from ..election.simulate import _wcheck, _winit
from .httpd import HTTPServer

STATUS = {
    "MALFORMED": 400,
    "WRONG_ELECTION": 400,
    "UNKNOWN_CONSTITUENCY": 400,
    "WRONG_BALLOT_STYLE": 400,
    "INVALID_CIPHERTEXT": 400,
    "BAD_SELECTION_PROOF": 400,
    "BAD_LIMIT_PROOF": 400,
    "BAD_TAG_PROOF": 400,
    "BAD_TAG_LINK": 400,
    "UNREGISTERED_TAG": 403,
    "ELECTION_NOT_OPEN": 403,
    "OUTSIDE_VOTING_WINDOW": 403,
    "DUPLICATE_CIPHERTEXT": 409,
    "TOO_MANY_REVOTES": 409,
}


class TokenBucket:
    def __init__(self, rate: float, burst: float) -> None:
        self.rate, self.burst = rate, burst
        self._b: dict[str, tuple[float, float]] = {}

    def take(self, key: str, now: float) -> bool:
        tokens, ts = self._b.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - ts) * self.rate)
        if tokens < 1:
            self._b[key] = (tokens, now)
            return False
        self._b[key] = (tokens - 1, now)
        if len(self._b) > 2_000_000:  # bound memory under a client-id flood
            self._b.clear()
        return True


class TagRegistry:
    """Read-only view of the eligibility authority's tag table."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = str(db_path)
        self._local = threading.local()

    def known(self, constituency: str, tag: str) -> bool:
        con = getattr(self._local, "con", None)
        if con is None:
            con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, check_same_thread=False)
            self._local.con = con
        row = con.execute("SELECT constituency FROM tags WHERE tag=?", (tag,)).fetchone()
        return row is not None and row[0] == constituency


class Sequencer:
    def __init__(
        self,
        election_dir: Path,
        *,
        workers: int,
        client_rate: float = 2.0,
        client_burst: float = 10.0,
        tag_interval_s: float = 2.0,
        queue_per_worker: int = 32,
        batch_max: int = 256,
        batch_wait_s: float = 0.05,
    ) -> None:
        d = Path(election_dir)
        first = json.loads((d / "record" / "entries.jsonl").open("rb").readline())
        self.manifest = first["body"]["manifest"]
        self.mhash = first["body"]["manifest_hash"]
        grp = get_group(self.manifest["group"])
        K = None
        with open(d / "record" / "entries.jsonl", "rb") as f:
            for raw in f:
                if b'"type":"joint_key"' in raw:
                    K = int(json.loads(raw)["body"]["joint_public_key"], 16)
                    break
        assert K is not None, "record has no joint key"
        self.pk = PublicKey(grp, K)
        self.options = {c["id"]: [o["id"] for o in c["options"]] for c in self.manifest["constituencies"]}
        operator = RoleKey("board", (d / "private" / "board.key").read_bytes())
        self.board = Board(d / "record", self.manifest["election_id"], operator, SystemClock(), durable=True)
        self.tags = TagRegistry(d / "private" / "eligibility.db")
        self.box = BallotBox(
            d / "private" / "ballotbox.db",
            self.board,
            self.manifest,
            self.mhash,
            self.pk,
            SystemClock(),
            self.tags.known,
            self.manifest["revoting"]["max_ballots_per_tag"],
        )
        self.workers = workers
        self.clients = TokenBucket(client_rate, client_burst)
        self.tag_interval_s = tag_interval_s
        self._tag_last: dict[str, float] = {}
        self.queue_max = workers * queue_per_worker
        self.batch_max, self.batch_wait_s = batch_max, batch_wait_s
        self.inflight = 0
        self.stats: Counter[str] = Counter()
        self.pool = ProcessPoolExecutor(
            workers,
            mp_context=mp.get_context("spawn"),
            initializer=_winit,
            initargs=(grp.name, format(K, "x"), self.mhash, self.manifest["election_id"], self.options),
        )
        self.commit_exec = ThreadPoolExecutor(1)  # the single writer
        self._q: asyncio.Queue | None = None
        self.http = HTTPServer(self.handle)

    # ----------------------------------------------------------------- request path
    def _reply(self, code: str, extra: dict | None = None) -> tuple[int, dict, dict]:
        self.stats[code] += 1
        status = STATUS.get(code, 400)
        hdr = {"Retry-After": "1"} if status in (429, 503) else {}
        return status, {"error": code, **(extra or {})}, hdr

    async def handle(self, method: str, path: str, headers: dict, body: bytes, peer: str):
        now = time.monotonic()
        if path == "/v1/health" and method == "GET":
            return 200, {"state": self.board.state, "ballots": self.board.count("ballot"), "inflight": self.inflight}, {}
        if path == "/v1/metrics" and method == "GET":
            return 200, self.snapshot(), {}
        if path != "/v1/ballots":
            return 404, {"error": "NOT_FOUND"}, {}
        if method != "POST":
            return 405, {"error": "METHOD_NOT_ALLOWED"}, {}
        client = headers.get("x-client", peer)
        if not self.clients.take(client, now):
            self.stats["RATE_LIMITED"] += 1
            return 429, {"error": "RATE_LIMITED"}, {"Retry-After": "2"}
        if self.inflight >= self.queue_max:
            self.stats["OVERLOADED"] += 1
            return 503, {"error": "OVERLOADED"}, {"Retry-After": "1"}
        try:
            sub = json.loads(body)
            if not isinstance(sub, dict) or set(sub) != SUBMISSION_KEYS or not isinstance(sub["ballot"], dict) or set(sub["ballot"]) != BALLOT_KEYS:
                raise ValueError
            b = sub["ballot"]
            if b["election_id"] != self.manifest["election_id"]:
                return self._reply("WRONG_ELECTION")
            if b["constituency"] not in self.options:
                return self._reply("UNKNOWN_CONSTITUENCY")
            tag = sub["tag"]
            if not isinstance(tag, str) or not 0 < len(tag) <= 1024:
                raise ValueError
        except (ValueError, TypeError, KeyError, UnicodeDecodeError):
            return self._reply("MALFORMED")
        prior = self.box._prior(sub)
        if prior is not None:
            self.stats["IDEMPOTENT_REPLAY"] += 1
            return 200, prior, {}
        if not self.tags.known(b["constituency"], tag):
            return self._reply("UNREGISTERED_TAG")
        last = self._tag_last.get(tag)
        if last is not None and now - last < self.tag_interval_s:
            self.stats["TAG_RATE_LIMITED"] += 1
            return 429, {"error": "TAG_RATE_LIMITED"}, {"Retry-After": str(int(self.tag_interval_s) + 1)}
        self._tag_last[tag] = now
        self.inflight += 1
        try:
            loop = asyncio.get_running_loop()
            self.stats["VERIFIED_EXPENSIVE"] += 1
            verdict = await loop.run_in_executor(self.pool, _wcheck, sub)
            if verdict.startswith("REJECT:"):
                return self._reply(verdict[7:])
            fut = loop.create_future()
            assert self._q is not None
            await self._q.put((sub, verdict, fut))
            res = await fut
        finally:
            self.inflight -= 1
        if isinstance(res, str):
            return self._reply(res)
        self.stats["ACCEPTED"] += 1
        return 200, res, {}

    # ----------------------------------------------------------------- group commit
    async def _committer(self) -> None:
        assert self._q is not None
        loop = asyncio.get_running_loop()
        while True:
            item = await self._q.get()
            if item is None:
                return
            batch = [item]
            deadline = loop.time() + self.batch_wait_s
            while len(batch) < self.batch_max:
                timeout = deadline - loop.time()
                if timeout <= 0:
                    break
                try:
                    nxt = await asyncio.wait_for(self._q.get(), timeout)
                except TimeoutError:
                    break
                if nxt is None:
                    await self._q.put(None)
                    break
                batch.append(nxt)
            subs, tags = [x[0] for x in batch], [x[1] for x in batch]
            try:
                results = await loop.run_in_executor(self.commit_exec, self.box.submit_batch, subs, tags)
            except Exception as e:  # noqa: BLE001 - never leave a client hanging
                results = [f"INTERNAL:{type(e).__name__}"] * len(batch)
            self.stats["BATCHES"] += 1
            for (_, _, fut), r in zip(batch, results, strict=True):
                if not fut.done():
                    fut.set_result(r)
            if self.stats["BATCHES"] % 40 == 0:
                await loop.run_in_executor(self.commit_exec, self.board.checkpoint)

    def snapshot(self) -> dict:
        return {
            "t": time.time(),
            "inflight": self.inflight,
            "queue_max": self.queue_max,
            "connections": self.http.connections,
            "ballots": self.board.count("ballot"),
            "outcomes": dict(self.stats),
            "http": dict(self.http.stats),
        }

    async def run(self, host: str, port: int, metrics_path: Path | None, ready_path: Path | None) -> None:
        self._q = asyncio.Queue()
        committer = asyncio.create_task(self._committer())
        bound = await self.http.start(host, port)
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        if ready_path:
            ready_path.write_text(str(bound))
        mf = open(metrics_path, "a") if metrics_path else None  # noqa: SIM115 - closed below
        try:
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), 1.0)
                except TimeoutError:
                    pass
                if mf:
                    mf.write(json.dumps(self.snapshot()) + "\n")
                    mf.flush()
        finally:
            await self.http.close()
            await self._q.put(None)
            await committer
            await loop.run_in_executor(self.commit_exec, self.board.checkpoint)
            if mf:
                mf.write(json.dumps(self.snapshot()) + "\n")
                mf.close()
            self.pool.shutdown(cancel_futures=True)
            self.commit_exec.shutdown()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="chunaviq-serve")
    ap.add_argument("--election", type=Path, required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--metrics", type=Path)
    ap.add_argument("--ready-file", type=Path)
    ap.add_argument("--tag-interval", type=float, default=2.0)
    a = ap.parse_args(argv)
    seq = Sequencer(a.election, workers=a.workers, tag_interval_s=a.tag_interval)
    asyncio.run(seq.run(a.host, a.port, a.metrics, a.ready_file))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["Sequencer", "TokenBucket", "TagRegistry", "tracking_code"]
