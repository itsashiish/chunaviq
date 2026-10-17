from __future__ import annotations

import datetime as dt
import threading


def utc(s: str) -> dt.datetime:
    d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    if d.tzinfo is None:
        raise ValueError("timestamps must carry a timezone")
    return d.astimezone(dt.UTC)


def iso(d: dt.datetime) -> str:
    return d.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def hour_bucket(d: dt.datetime) -> str:
    """Coarse time stamp published with record entries. Hour granularity limits
    timing correlation between credential issuance and ballot casting."""
    return d.astimezone(dt.UTC).strftime("%Y-%m-%dT%H")


class SystemClock:
    def now(self) -> dt.datetime:
        return dt.datetime.now(dt.UTC)


class FakeClock:
    """Deterministic, thread-safe clock for simulations and tests."""

    def __init__(self, start: dt.datetime) -> None:
        self._t = start
        self._lock = threading.Lock()

    def now(self) -> dt.datetime:
        with self._lock:
            return self._t

    def set(self, t: dt.datetime) -> None:
        with self._lock:
            self._t = t

    def advance(self, **kw) -> None:
        with self._lock:
            self._t += dt.timedelta(**kw)
