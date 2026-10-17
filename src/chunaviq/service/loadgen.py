"""Load and attack generator for the ballot-intake service.

Honest voters are an open-loop Poisson arrival process at a target rate:
arrivals do not slow down when the server does, which is what real voters do.
Each honest request retries on 429/503/connection errors with exponential
backoff, full jitter and Retry-After -- safe, because submissions are
idempotent. Every attempt is recorded.

Attack traffic (``FLOODS``) runs alongside, each kind at its own rate, from a
small pool of attacker client ids (a botnet's source addresses):

  junk          random bytes as a request body
  oversize      a Content-Length far above the limit
  unregistered  well-formed ballots under tags nobody registered
  bad_proof     ballots under the attacker's OWN registered tags with broken
                proofs -- the most expensive attack, since it reaches the provers
  replay        an already-accepted ballot, over and over
  slowloris     connections that dribble header bytes and never finish
  idle_conns    connections opened and left idle
"""

from __future__ import annotations

import asyncio
import json
import random
import secrets
import time
from dataclasses import dataclass, field

FLOODS = ("junk", "oversize", "unregistered", "bad_proof", "replay", "slowloris", "idle_conns")


@dataclass
class Record:
    kind: str
    phase: str
    t_sched: float
    t_done: float = 0.0
    status: int = 0
    code: str = ""
    attempts: int = 0
    tracking_code: str = ""


@dataclass
class LoadResult:
    records: list[Record] = field(default_factory=list)
    started: float = 0.0


async def _request(host: str, port: int, body: bytes, client: str, timeout: float = 30.0, headers: dict | None = None) -> tuple[int, dict, dict]:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        h = {"Host": host, "Content-Type": "application/json", "Content-Length": str(len(body)), "X-Client": client, "Connection": "close", **(headers or {})}
        writer.write(("POST /v1/ballots HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n").encode() + body)
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split(" ")[1])
        hdrs = {k.strip().lower(): v.strip() for k, v in (ln.split(":", 1) for ln in lines[1:] if ":" in ln)}
        data = await asyncio.wait_for(reader.readexactly(int(hdrs.get("content-length", "0"))), timeout)
        return status, json.loads(data or b"{}"), hdrs
    finally:
        writer.close()


async def _honest(host, port, body: bytes, client: str, rec: Record, deadline: float, max_attempts: int | None = None) -> None:
    """A voter's phone: retries busy/rate-limited/connection failures with jittered backoff until it
    succeeds or the deadline passes (real phones keep trying across the voting week)."""
    backoff = 0.25
    while True:
        rec.attempts += 1
        try:
            status, out, hdrs = await _request(host, port, body, client)
        except (OSError, TimeoutError, asyncio.IncompleteReadError, ValueError):
            status, out, hdrs = 0, {"error": "CONNECTION"}, {}
        rec.status, rec.code = status, out.get("error", "") if status != 200 else ("IDEMPOTENT" if out.get("duplicate_submission") else "OK")
        if status == 200:
            rec.tracking_code = out.get("tracking_code", "")
        retry = status in (0, 429, 503)
        if not retry or (max_attempts is not None and rec.attempts >= max_attempts) or time.monotonic() > deadline:
            rec.t_done = time.monotonic()
            return
        wait = max(float(hdrs.get("retry-after", 0) or 0), random.uniform(0, backoff))  # noqa: S311 - jitter, not crypto
        backoff = min(backoff * 2, 8.0)
        await asyncio.sleep(wait)


async def _attack(host, port, kind: str, rec: Record, ctx: dict) -> None:
    rec.attempts = 1
    client = f"bot-{random.randrange(ctx['botnet'])}"  # noqa: S311
    try:
        if kind in ("slowloris", "idle_conns"):
            reader, writer = await asyncio.open_connection(host, port)
            try:
                if kind == "slowloris":
                    writer.write(b"POST /v1/ballots HTTP/1.1\r\nHost: x\r\n")
                    for _ in range(30):
                        await asyncio.sleep(0.5)
                        writer.write(b"X-Slow: 1\r\n")
                        await writer.drain()
                else:
                    await asyncio.sleep(15)
                data = await asyncio.wait_for(reader.read(1), 1)
                rec.status, rec.code = (0, "CLOSED_BY_SERVER") if not data else (1, "STILL_OPEN")
            except (OSError, TimeoutError):
                rec.status, rec.code = 0, "CLOSED_BY_SERVER"
            finally:
                writer.close()
        else:
            if kind == "junk":
                body = secrets.token_bytes(2048)
            elif kind == "oversize":
                body = b"{}"
                status, out, _ = await _request(host, port, body, client, headers={"Content-Length": str(50 * 1024 * 1024)})
                rec.status, rec.code = status, out.get("error", "")
                return
            elif kind == "unregistered":
                body = ctx["unregistered"]
            elif kind == "bad_proof":
                body = random.choice(ctx["bad_proof"])  # noqa: S311
            else:  # replay
                body = random.choice(ctx["replay"]) if ctx["replay"] else ctx["unregistered"]  # noqa: S311
            status, out, _ = await _request(host, port, body, client)
            rec.status, rec.code = status, out.get("error", "") if status != 200 else "IDEMPOTENT"
    except (OSError, TimeoutError, asyncio.IncompleteReadError, ValueError):
        rec.status, rec.code = 0, "CONNECTION"
    finally:
        rec.t_done = time.monotonic()


async def run_phases(host: str, port: int, honest_bodies, phases: list[dict], attack_ctx: dict, max_concurrency: int = 4000) -> LoadResult:
    """phases: [{"name", "seconds", "rate", "floods": {kind: rate}}]. honest_bodies: an
    iterator of (body bytes, client id). Returns every request's record."""
    res = LoadResult()
    sem = asyncio.Semaphore(max_concurrency)
    tasks: list[asyncio.Task] = []
    replay_pool: list[bytes] = attack_ctx.setdefault("replay", [])

    async def guarded(coro):
        async with sem:
            await coro

    t0 = time.monotonic()
    res.started = t0
    offset = 0.0
    exhausted = False
    for ph in phases:
        end = offset + ph["seconds"]
        streams = [("honest", ph["rate"])] + [(k, r) for k, r in ph.get("floods", {}).items() if r > 0]
        nexts = {k: offset + random.expovariate(r) for k, r in streams}  # noqa: S311
        while True:
            kind, t_next = min(nexts.items(), key=lambda kv: kv[1])
            if t_next >= end:
                break
            delay = t0 + t_next - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            rec = Record(kind, ph["name"], t_next)
            res.records.append(rec)
            if kind == "honest":
                try:
                    body, client = next(honest_bodies)
                except StopIteration:
                    exhausted = True
                    nexts[kind] = end
                    res.records.pop()
                    continue
                if len(replay_pool) < 50 and random.random() < 0.01:  # noqa: S311
                    replay_pool.append(body)
                tasks.append(asyncio.create_task(guarded(_honest(host, port, body, client, rec, t0 + end + 60))))  # phones retry up to 60 s past the phase end
            else:
                tasks.append(asyncio.create_task(guarded(_attack(host, port, kind, rec, attack_ctx))))
            rate = dict(streams)[kind]
            nexts[kind] = t_next + random.expovariate(rate)  # noqa: S311
        offset = end
        if exhausted:
            break
    await asyncio.gather(*tasks, return_exceptions=True)
    return res


__all__ = ["run_phases", "Record", "LoadResult", "FLOODS"]
