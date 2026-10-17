"""Ballot-intake service: HTTP-level denial-of-service defences, and a full dress rehearsal.

The rehearsal test (marker ``rehearsal``) runs a real election over HTTP under
seven kinds of attack; it takes a few minutes. Run: pytest -m rehearsal
"""

import asyncio
import json

import pytest

from chunaviq.service.httpd import HTTPServer
from chunaviq.service.sequencer import TokenBucket


def test_token_bucket():
    b = TokenBucket(rate=1.0, burst=3)
    assert [b.take("x", 0.0) for _ in range(4)] == [True, True, True, False]
    assert b.take("x", 1.01) and not b.take("x", 1.02)
    assert b.take("y", 0.0)  # independent per client


async def _server(**kw):
    async def echo(method, path, headers, body, peer):
        return 200, {"method": method, "path": path, "len": len(body)}, {}

    srv = HTTPServer(echo, **kw)
    port = await srv.start("127.0.0.1", 0)
    return srv, port


async def _raw(port, data: bytes, read_timeout=3.0) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(data)
    await w.drain()
    try:
        return await asyncio.wait_for(r.read(65536), read_timeout)
    finally:
        w.close()


def test_http_limits():
    async def main():
        srv, port = await _server(max_body=1000, header_timeout=0.5, max_header=512)
        try:
            ok = await _raw(port, b"POST /x HTTP/1.1\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
            assert ok.startswith(b"HTTP/1.1 200") and json.loads(ok.split(b"\r\n\r\n")[1])["len"] == 3
            big = await _raw(port, b"POST /x HTTP/1.1\r\nContent-Length: 5000000\r\n\r\n")
            assert big.startswith(b"HTTP/1.1 413")  # refused before reading the body
            hdr = await _raw(port, b"GET /x HTTP/1.1\r\n" + b"X-Pad: " + b"a" * 2000 + b"\r\n\r\n")
            assert hdr.startswith(b"HTTP/1.1 431")
            bad = await _raw(port, b"NONSENSE\r\n\r\n")
            assert bad.startswith(b"HTTP/1.1 400")
            # slowloris: headers never finish -> connection closed after the header deadline
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"POST /x HTTP/1.1\r\nHost: a\r\n")
            await w.drain()
            assert await asyncio.wait_for(r.read(10), 3) == b""
            w.close()
            assert srv.stats["header_timeout"] >= 1 and srv.stats["body_too_large"] == 1
            # keep-alive: two requests on one connection
            r, w = await asyncio.open_connection("127.0.0.1", port)
            for _ in range(2):
                w.write(b"POST /k HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
                await w.drain()
                head = await r.readuntil(b"\r\n\r\n")
                n = int(next(x for x in head.split(b"\r\n") if x.lower().startswith(b"content-length")).split(b":")[1])
                await r.readexactly(n)
                assert head.startswith(b"HTTP/1.1 200")
            w.close()
        finally:
            await srv.close()

    asyncio.run(main())


def test_connection_cap():
    async def main():
        srv, port = await _server(max_connections=2, header_timeout=5)
        try:
            held = [await asyncio.open_connection("127.0.0.1", port) for _ in range(2)]
            await asyncio.sleep(0.1)
            r, w = await asyncio.open_connection("127.0.0.1", port)
            assert await asyncio.wait_for(r.read(10), 3) == b""  # third connection refused
            w.close()
            for _, hw in held:
                hw.close()
            assert srv.stats["conn_refused"] == 1
        finally:
            await srv.close()

    asyncio.run(main())


@pytest.mark.rehearsal
def test_smoke_dress_rehearsal(tmp_path):
    from chunaviq.service.rehearsal import run

    s = run("smoke", tmp_path / "r", seconds=30)
    assert s["verification"]["status"] == "VERIFIED", s["verification"]
    assert s["every_receipt_is_on_the_board"]
    for name, ph in s["phases"].items():
        assert ph["honest_recorded_pct"] == 100.0, (name, ph["honest_failed_codes"])
    outcomes: dict[str, set] = {}
    for ph in s["phases"].values():
        for k, v in ph["attack_outcomes"].items():
            outcomes.setdefault(k, set()).update(v)
    assert outcomes.get("junk", set()) <= {"400 MALFORMED"}
    assert outcomes.get("oversize", set()) <= {"413 BODY_TOO_LARGE"}
    assert outcomes.get("unregistered", set()) <= {"403 UNREGISTERED_TAG", "429 RATE_LIMITED"}
    assert outcomes.get("bad_proof", set()) <= {"400 BAD_SELECTION_PROOF", "429 TAG_RATE_LIMITED", "429 RATE_LIMITED"}
    assert outcomes.get("replay", set()) <= {"200 IDEMPOTENT", "429 RATE_LIMITED"}
    assert outcomes.get("slowloris", set()) <= {"0 CLOSED_BY_SERVER"}
    for f in ("summary.json", "requests.csv", "server-metrics.csv", "verify.json", "report.md"):
        assert (tmp_path / "r" / f).exists()
