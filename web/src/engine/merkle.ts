// RFC 6962 / 9162 Merkle tree. Mirrors src/chunaviq/crypto/merkle.py.
import { sha256 } from "@noble/hashes/sha2.js";
import { concat } from "./bigint";

const ZERO = new Uint8Array([0]);
const ONE = new Uint8Array([1]);
export const leafHash = (data: Uint8Array) => sha256(concat(ZERO, data));
export const nodeHash = (l: Uint8Array, r: Uint8Array) => sha256(concat(ONE, l, r));
export const EMPTY_ROOT = sha256(new Uint8Array());

const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

function largestPow2Below(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export function mth(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return EMPTY_ROOT;
  if (leaves.length === 1) return leaves[0];
  const k = largestPow2Below(leaves.length);
  return nodeHash(mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}

export class MerkleTree {
  levels: Uint8Array[][] = [[]];
  get size() {
    return this.levels[0].length;
  }
  append(data: Uint8Array): number {
    this.levels[0].push(leafHash(data));
    let lvl = 0;
    while (this.levels[lvl].length > 1) {
      const cur = this.levels[lvl];
      if (lvl + 1 === this.levels.length) this.levels.push([]);
      const nxt = this.levels[lvl + 1];
      const i = cur.length - 1;
      const val = i % 2 === 1 ? nodeHash(cur[i - 1], cur[i]) : cur[i];
      const pi = i >> 1;
      if (pi < nxt.length) nxt[pi] = val;
      else nxt.push(val);
      nxt.length = (cur.length + 1) >> 1;
      lvl++;
    }
    this.levels.length = lvl + 1;
    return this.size - 1;
  }
  root(): Uint8Array {
    return this.size ? this.levels[this.levels.length - 1][0] : EMPTY_ROOT;
  }
  inclusionProof(index: number): Uint8Array[] {
    const path: Uint8Array[] = [];
    let i = index;
    for (let lvl = 0; lvl < this.levels.length - 1; lvl++) {
      const sib = i ^ 1;
      if (sib < this.levels[lvl].length) path.push(this.levels[lvl][sib]);
      i >>= 1;
    }
    return path;
  }
  consistencyProof(first: number): Uint8Array[] {
    return consistencyProof(this.levels[0], first);
  }
}

export function consistencyProof(leaves: Uint8Array[], m: number): Uint8Array[] {
  const sub = (m: number, d: Uint8Array[], b: boolean): Uint8Array[] => {
    if (m === d.length) return b ? [] : [mth(d)];
    const k = largestPow2Below(d.length);
    if (m <= k) return [...sub(m, d.slice(0, k), b), mth(d.slice(k))];
    return [...sub(m - k, d.slice(k), false), mth(d.slice(0, k))];
  };
  if (m < 1 || m > leaves.length) throw new RangeError("bad consistency range");
  return sub(m, leaves, true);
}

export function verifyInclusion(leaf: Uint8Array, index: number, size: number, path: Uint8Array[], root: Uint8Array): boolean {
  if (index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      r = nodeHash(p, r);
      if (!(fn & 1)) while (!(fn & 1) && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else r = nodeHash(r, p);
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && eq(r, root);
}

export function verifyConsistency(m: number, n: number, r1: Uint8Array, r2: Uint8Array, proof: Uint8Array[]): boolean {
  if (m < 1 || m > n) return false;
  if (m === n) return proof.length === 0 && eq(r1, r2);
  if (!proof.length) return false;
  const path = (m & (m - 1)) === 0 ? [r1, ...proof] : [...proof];
  let fn = m - 1;
  let sn = n - 1;
  while (fn & 1) {
    fn >>= 1;
    sn >>= 1;
  }
  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if (!(fn & 1)) while (!(fn & 1) && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else sr = nodeHash(sr, c);
    fn >>= 1;
    sn >>= 1;
  }
  return eq(fr, r1) && eq(sr, r2) && sn === 0;
}

/** Roots of the requested prefixes in one pass (RFC 6962 stack). */
export function rootsAt(leaves: Uint8Array[], sizes: Set<number>): Map<number, Uint8Array> {
  const out = new Map<number, Uint8Array>();
  if (sizes.has(0)) out.set(0, EMPTY_ROOT);
  const stack: [number, Uint8Array][] = [];
  leaves.forEach((lf, i) => {
    stack.push([0, lf]);
    while (stack.length >= 2 && stack[stack.length - 1][0] === stack[stack.length - 2][0]) {
      const [h, r] = stack.pop()!;
      const [, l] = stack.pop()!;
      stack.push([h + 1, nodeHash(l, r)]);
    }
    if (sizes.has(i + 1)) {
      let acc = stack[stack.length - 1][1];
      for (let j = stack.length - 2; j >= 0; j--) acc = nodeHash(stack[j][1], acc);
      out.set(i + 1, acc);
    }
  });
  return out;
}
