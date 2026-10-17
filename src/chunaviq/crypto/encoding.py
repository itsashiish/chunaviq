"""Canonical encodings used for hashing, signing and the published election record.

Two encodings are defined (normative text: spec/record-format.md):

* ``canonical_json`` -- the byte form of every record entry and signed body.
  Sorted keys, no whitespace, ASCII only. Large integers are carried as
  lowercase hex strings, never as JSON numbers.
* ``hash_to_scalar`` -- the Fiat-Shamir challenge function. Items are encoded
  with an unambiguous type-and-length prefix so that no two different item
  sequences produce the same byte string.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

DOMAIN_PREFIX = b"chunaviq/v1/"


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def to_hex(x: int) -> str:
    if x < 0:
        raise ValueError("negative integers are not encodable")
    return format(x, "x")


def from_hex(s: str) -> int:
    if not isinstance(s, str) or not s or any(c not in "0123456789abcdef" for c in s):
        raise ValueError("malformed hex integer")
    if len(s) > 1 and s[0] == "0":
        raise ValueError("non-canonical hex integer (leading zero)")
    return int(s, 16)


def _encode_item(item: Any) -> bytes:
    if isinstance(item, bool):
        raise TypeError("booleans are not hashable items")
    if isinstance(item, int):
        if item < 0:
            raise ValueError("negative integers are not hashable items")
        raw = item.to_bytes(max(1, (item.bit_length() + 7) // 8), "big")
        return b"i" + len(raw).to_bytes(4, "big") + raw
    if isinstance(item, str):
        raw = item.encode("utf-8")
        return b"s" + len(raw).to_bytes(4, "big") + raw
    if isinstance(item, (bytes, bytearray)):
        return b"b" + len(item).to_bytes(4, "big") + bytes(item)
    if isinstance(item, (list, tuple)):
        return b"l" + len(item).to_bytes(4, "big") + b"".join(_encode_item(x) for x in item)
    raise TypeError(f"unsupported hash item type: {type(item).__name__}")


def hash_items(domain: str, *items: Any) -> bytes:
    payload = DOMAIN_PREFIX + domain.encode() + b"\x00" + _encode_item(list(items))
    return hashlib.sha256(payload).digest()


def hash_to_scalar(q: int, domain: str, *items: Any) -> int:
    return int.from_bytes(hash_items(domain, *items), "big") % q
