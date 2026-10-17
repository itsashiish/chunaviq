"""A small, defensive HTTP/1.1 server on asyncio (no third-party dependencies).

Only what a ballot-intake endpoint needs, with the limits that matter under
denial-of-service: a cap on concurrent connections, a deadline for receiving
headers (slowloris), a deadline for the body, a maximum header block and a
maximum body size checked from Content-Length before any byte of the body is
read. Keep-alive is supported so honest clients do not pay a handshake per
request. TLS, HTTP/2 and volumetric (network-layer) filtering belong to the
edge in front of this process: a CDN / anycast scrubbing layer and a TLS
terminating load balancer. See docs/dos-and-rehearsal.md.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections import Counter
from collections.abc import Awaitable, Callable

Handler = Callable[[str, str, dict[str, str], bytes, str], Awaitable[tuple[int, dict, dict[str, str]]]]

REASONS = {
    200: "OK",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    413: "Payload Too Large",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    503: "Service Unavailable",
}


class HTTPServer:
    def __init__(
        self,
        handler: Handler,
        *,
        max_body: int = 512 * 1024,
        max_header: int = 8192,
        header_timeout: float = 5.0,
        body_timeout: float = 10.0,
        idle_timeout: float = 30.0,
        max_connections: int = 20_000,
    ) -> None:
        self.handler = handler
        self.max_body = max_body
        self.max_header = max_header
        self.header_timeout = header_timeout
        self.body_timeout = body_timeout
        self.idle_timeout = idle_timeout
        self.max_connections = max_connections
        self.connections = 0
        self.stats: Counter[str] = Counter()
        self._server: asyncio.base_events.Server | None = None

    async def start(self, host: str, port: int) -> int:
        self._server = await asyncio.start_server(self._client, host, port, limit=self.max_header, backlog=4096)
        return self._server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _send(self, writer: asyncio.StreamWriter, status: int, body: dict, headers: dict[str, str], keep: bool) -> None:
        data = json.dumps(body, separators=(",", ":")).encode()
        head = [f"HTTP/1.1 {status} {REASONS.get(status, 'Error')}", "Content-Type: application/json", f"Content-Length: {len(data)}"]
        head += [f"{k}: {v}" for k, v in headers.items()]
        head.append("Connection: keep-alive" if keep else "Connection: close")
        writer.write(("\r\n".join(head) + "\r\n\r\n").encode() + data)
        await writer.drain()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.connections >= self.max_connections:
            self.stats["conn_refused"] += 1
            writer.close()
            return
        self.connections += 1
        peer = writer.get_extra_info("peername")
        peer_s = peer[0] if isinstance(peer, tuple) else "unknown"
        first = True
        try:
            while True:
                try:
                    raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.header_timeout if first else self.idle_timeout)
                except TimeoutError:
                    self.stats["header_timeout" if first else "idle_close"] += 1
                    return
                except asyncio.LimitOverrunError:
                    self.stats["header_too_large"] += 1
                    await self._send(writer, 431, {"error": "HEADER_TOO_LARGE"}, {}, False)
                    return
                except (asyncio.IncompleteReadError, ConnectionError):
                    return
                first = False
                try:
                    lines = raw.decode("latin-1").split("\r\n")
                    method, path, _ = lines[0].split(" ", 2)
                    headers = {}
                    for ln in lines[1:]:
                        if ln:
                            k, v = ln.split(":", 1)
                            headers[k.strip().lower()] = v.strip()
                    length = int(headers.get("content-length", "0"))
                except (ValueError, IndexError):
                    self.stats["bad_request"] += 1
                    await self._send(writer, 400, {"error": "BAD_REQUEST"}, {}, False)
                    return
                if length < 0 or length > self.max_body:
                    self.stats["body_too_large"] += 1
                    await self._send(writer, 413, {"error": "BODY_TOO_LARGE"}, {}, False)
                    return
                try:
                    body = await asyncio.wait_for(reader.readexactly(length), self.body_timeout) if length else b""
                except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                    self.stats["body_timeout"] += 1
                    return
                keep = headers.get("connection", "keep-alive").lower() != "close"
                status, out, extra = await self.handler(method, path, headers, body, peer_s)
                await self._send(writer, status, out, extra, keep)
                if not keep:
                    return
        except ConnectionError:
            return
        finally:
            self.connections -= 1
            with contextlib.suppress(Exception):  # closing an already-broken socket
                writer.close()
