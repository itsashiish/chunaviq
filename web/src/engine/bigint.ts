// Big-integer helpers for the browser engine. Mirrors src/chunaviq/crypto/{group,encoding}.py.

export const enc = new TextEncoder();

/** Left-to-right 4-bit fixed-window modular exponentiation. */
export function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  if (exp < 0n) throw new RangeError("negative exponent");
  let b = base % mod;
  if (b < 0n) b += mod;
  if (exp === 0n) return 1n;
  const table: bigint[] = [1n, b];
  for (let i = 2; i < 16; i++) table.push((table[i - 1] * b) % mod);
  const hex = exp.toString(16);
  let r = 1n;
  for (let i = 0; i < hex.length; i++) {
    if (i > 0) {
      r = (r * r) % mod;
      r = (r * r) % mod;
      r = (r * r) % mod;
      r = (r * r) % mod;
    }
    const d = parseInt(hex[i], 16);
    if (d) r = (r * table[d]) % mod;
  }
  return r;
}

export function modinv(a: bigint, m: bigint): bigint {
  let [oldR, r] = [((a % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new RangeError("not invertible");
  return ((oldS % m) + m) % m;
}

/** Precomputed windows for one fixed base: pow costs ~bits/w multiplications. */
export class FixedBase {
  private table: bigint[][] = [];
  constructor(base: bigint, private mod: bigint, private bits = 256, private w = 6) {
    let b = base % mod;
    const size = 1 << w;
    for (let row = 0; row < Math.ceil(bits / w); row++) {
      const t: bigint[] = Array.from({ length: size }, () => 0n);
      t[0] = 1n;
      let acc = 1n;
      for (let j = 1; j < size; j++) {
        acc = (acc * b) % mod;
        t[j] = acc;
      }
      this.table.push(t);
      b = (acc * b) % mod;
    }
  }
  pow(e: bigint): bigint {
    if (e < 0n || e >> BigInt(this.bits) !== 0n) throw new RangeError("exponent out of range");
    const mask = BigInt((1 << this.w) - 1);
    const w = BigInt(this.w);
    let r = 1n;
    let i = 0;
    while (e > 0n) {
      const d = Number(e & mask);
      if (d) r = (r * this.table[i][d]) % this.mod;
      e >>= w;
      i++;
    }
    return r;
  }
}

export const toHex = (x: bigint): string => {
  if (x < 0n) throw new RangeError("negative");
  return x.toString(16);
};

export function fromHex(s: unknown): bigint {
  if (typeof s !== "string" || !/^[0-9a-f]+$/.test(s) || (s.length > 1 && s[0] === "0")) throw new SyntaxError("malformed hex integer");
  return BigInt("0x" + s);
}

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 || !/^[0-9a-f]*$/.test(h)) throw new SyntaxError("bad hex bytes");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function bytesToBigint(b: Uint8Array): bigint {
  return b.length ? BigInt("0x" + bytesToHex(b)) : 0n;
}

/** Minimal big-endian bytes (zero encodes as one 0x00 byte), as in the Python TLV encoding. */
export function bigintToMinBytes(x: bigint): Uint8Array {
  let h = x.toString(16);
  if (h.length % 2) h = "0" + h;
  return hexToBytes(h);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** Uniform in [0, n) by rejection sampling. */
export function randBelow(n: bigint): bigint {
  const bits = n.toString(2).length;
  const bytes = Math.ceil(bits / 8);
  const excess = BigInt(bytes * 8 - bits);
  for (;;) {
    const x = bytesToBigint(randomBytes(bytes)) >> excess;
    if (x < n) return x;
  }
}

export const randScalar = (q: bigint): bigint => 1n + randBelow(q - 1n);

export function bitLength(x: bigint): number {
  return x === 0n ? 0 : x.toString(2).length;
}

export function b64urlToBigint(s: string): bigint {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return bytesToBigint(u8);
}
