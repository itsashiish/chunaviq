// Canonical JSON and the Fiat-Shamir hash (spec/record-format.md, spec/protocol.md section 3).
import { sha256 } from "@noble/hashes/sha2.js";
import { bigintToMinBytes, bytesToBigint, bytesToHex, concat, enc } from "./bigint";

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

function escapeString(s: string): string {
  // JSON.stringify, then escape every non-ASCII code unit like Python's ensure_ascii.
  return JSON.stringify(s).replace(/[\u007f-￿]/g, (c) => (c.charCodeAt(0) === 0x7f ? c : "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")));
}

/** json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True) */
export function canonicalJson(v: Json): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new TypeError("only safe integers are allowed in records");
    return String(v);
  }
  if (typeof v === "string") return escapeString(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => escapeString(k) + ":" + canonicalJson(v[k])).join(",") + "}";
}

export const canonicalBytes = (v: Json): Uint8Array => enc.encode(canonicalJson(v));

export const sha256Hex = (b: Uint8Array): string => bytesToHex(sha256(b));

export type HashItem = bigint | string | HashItem[];

function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}

function encodeItem(x: HashItem): Uint8Array {
  if (typeof x === "bigint") {
    if (x < 0n) throw new RangeError("negative");
    const raw = bigintToMinBytes(x);
    return concat(enc.encode("i"), u32(raw.length), raw);
  }
  if (typeof x === "string") {
    const raw = enc.encode(x);
    return concat(enc.encode("s"), u32(raw.length), raw);
  }
  return concat(enc.encode("l"), u32(x.length), ...x.map(encodeItem));
}

export const DOMAIN_PREFIX = "chunaviq/v1/";

export function hashToScalar(q: bigint, domain: string, ...items: HashItem[]): bigint {
  const payload = concat(enc.encode(DOMAIN_PREFIX + domain), new Uint8Array([0]), encodeItem(items));
  return bytesToBigint(sha256(payload)) % q;
}
