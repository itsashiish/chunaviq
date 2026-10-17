// Group, ElGamal, zero-knowledge proofs, threshold keys. Mirrors src/chunaviq/crypto/*.py.
import { FixedBase, fromHex, modinv, modpow, randScalar, toHex } from "./bigint";
import { hashToScalar, type HashItem } from "./encoding";
import { G as G_, P as P_, Q as Q_ } from "./params";

export const P = P_;
export const Q = Q_;
export const G = G_;

export const gFB = new FixedBase(G, P, 256);
export const gPow = (e: bigint) => gFB.pow(((e % Q) + Q) % Q);
export const pow = (b: bigint, e: bigint) => modpow(b, ((e % Q) + Q) % Q, P);
export const isElement = (x: unknown): x is bigint => typeof x === "bigint" && x >= 1n && x < P && modpow(x, Q, P) === 1n;
export const inRange = (...xs: bigint[]) => xs.every((x) => typeof x === "bigint" && x >= 1n && x < P);
export const isScalar = (...xs: bigint[]) => xs.every((x) => typeof x === "bigint" && x >= 0n && x < Q);
export const div = (a: bigint, b: bigint) => (a * modinv(b, P)) % P;
export const rand = () => randScalar(Q);

// ------------------------------------------------------------------ ElGamal
export type Ct = { alpha: bigint; beta: bigint };
export const ctToJson = (c: Ct) => ({ alpha: toHex(c.alpha), beta: toHex(c.beta) });
export const ctFromJson = (d: { alpha: string; beta: string }): Ct => ({ alpha: fromHex(d.alpha), beta: fromHex(d.beta) });

export class PublicKey {
  private fb: FixedBase;
  constructor(public K: bigint) {
    if (!isElement(K) || K === 1n) throw new RangeError("invalid public key");
    this.fb = new FixedBase(K, P, 256);
  }
  kPow(e: bigint): bigint {
    return this.fb.pow(((e % Q) + Q) % Q);
  }
  encrypt(m: bigint, r: bigint): Ct {
    return { alpha: gPow(r), beta: (gPow(m) * this.kPow(r)) % P };
  }
}

export function addCts(cts: Ct[]): Ct {
  let a = 1n;
  let b = 1n;
  for (const c of cts) {
    a = (a * c.alpha) % P;
    b = (b * c.beta) % P;
  }
  return { alpha: a, beta: b };
}

export function dlogBounded(gm: bigint, bound: number): number {
  let acc = 1n;
  for (let m = 0; m <= bound; m++) {
    if (acc === gm) return m;
    acc = (acc * G) % P;
  }
  throw new RangeError("plaintext outside expected range");
}

// ------------------------------------------------------------------ proofs
export type Schnorr = { h: bigint; v: bigint };
export type CP = { a: bigint; b: bigint; v: bigint };
export type Disj = { a0: bigint; b0: bigint; a1: bigint; b1: bigint; c0: bigint; c1: bigint; v0: bigint; v1: bigint };

export const DISJ_KEYS = ["a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1"] as const;
export const disjToJson = (d: Disj) => Object.fromEntries(DISJ_KEYS.map((k) => [k, toHex(d[k])])) as Record<string, string>;
export const disjFromJson = (d: Record<string, string>): Disj => Object.fromEntries(DISJ_KEYS.map((k) => [k, fromHex(d[k])])) as Disj;
export const cpToJson = (c: CP) => ({ a: toHex(c.a), b: toHex(c.b), v: toHex(c.v) });
export const cpFromJson = (d: { a: string; b: string; v: string }): CP => ({ a: fromHex(d.a), b: fromHex(d.b), v: fromHex(d.v) });

export function schnorrProve(x: bigint, X: bigint, ctx: HashItem[]): Schnorr {
  const u = rand();
  const h = gPow(u);
  const c = hashToScalar(Q, "schnorr", ctx, X, h);
  return { h, v: (u + c * x) % Q };
}

export function schnorrVerify(X: bigint, pr: Schnorr, ctx: HashItem[]): boolean {
  if (!isElement(X) || !inRange(pr.h) || !isScalar(pr.v)) return false;
  const c = hashToScalar(Q, "schnorr", ctx, X, pr.h);
  return gPow(pr.v) === (pr.h * pow(X, c)) % P;
}

export function cpProve(x: bigint, H: bigint, X: bigint, Y: bigint, domain: string, ctx: HashItem[], hPow?: (e: bigint) => bigint): CP {
  const u = rand();
  const a = gPow(u);
  const b = hPow ? hPow(u) : pow(H, u);
  const c = hashToScalar(Q, domain, ctx, H, X, Y, a, b);
  return { a, b, v: (u + c * x) % Q };
}

export function cpVerify(H: bigint, X: bigint, Y: bigint, pr: CP, domain: string, ctx: HashItem[], hPow?: (e: bigint) => bigint): boolean {
  if (!isElement(H) || !isElement(X) || !isElement(Y) || !inRange(pr.a, pr.b) || !isScalar(pr.v)) return false;
  const c = hashToScalar(Q, domain, ctx, H, X, Y, pr.a, pr.b);
  if (gPow(pr.v) !== (pr.a * pow(X, c)) % P) return false;
  return (hPow ? hPow(pr.v) : pow(H, pr.v)) === (pr.b * pow(Y, c)) % P;
}

const disjChallenge = (pk: PublicKey, ct: Ct, a0: bigint, b0: bigint, a1: bigint, b1: bigint, ctx: HashItem[]) =>
  hashToScalar(Q, "selection-0or1", ctx, pk.K, ct.alpha, ct.beta, a0, b0, a1, b1);

export function disjProve(pk: PublicKey, ct: Ct, m: 0 | 1, r: bigint, ctx: HashItem[]): Disj {
  const bg = div(ct.beta, G);
  const u = rand();
  if (m === 0) {
    const c1 = rand();
    const v1 = rand();
    const a1 = (gPow(v1) * pow(ct.alpha, Q - c1)) % P;
    const b1 = (pk.kPow(v1) * pow(bg, Q - c1)) % P;
    const a0 = gPow(u);
    const b0 = pk.kPow(u);
    const c0 = (((disjChallenge(pk, ct, a0, b0, a1, b1, ctx) - c1) % Q) + Q) % Q;
    return { a0, b0, a1, b1, c0, c1, v0: (u + c0 * r) % Q, v1 };
  }
  const c0 = rand();
  const v0 = rand();
  const a0 = (gPow(v0) * pow(ct.alpha, Q - c0)) % P;
  const b0 = (pk.kPow(v0) * pow(ct.beta, Q - c0)) % P;
  const a1 = gPow(u);
  const b1 = pk.kPow(u);
  const c1 = (((disjChallenge(pk, ct, a0, b0, a1, b1, ctx) - c0) % Q) + Q) % Q;
  return { a0, b0, a1, b1, c0, c1, v0, v1: (u + c1 * r) % Q };
}

export function disjVerify(pk: PublicKey, ct: Ct, pr: Disj, ctx: HashItem[]): boolean {
  if (!isElement(ct.alpha) || !isElement(ct.beta) || !inRange(pr.a0, pr.b0, pr.a1, pr.b1)) return false;
  if (!isScalar(pr.c0, pr.c1, pr.v0, pr.v1)) return false;
  if ((pr.c0 + pr.c1) % Q !== disjChallenge(pk, ct, pr.a0, pr.b0, pr.a1, pr.b1, ctx)) return false;
  const bg = div(ct.beta, G);
  return (
    gPow(pr.v0) === (pr.a0 * pow(ct.alpha, pr.c0)) % P &&
    pk.kPow(pr.v0) === (pr.b0 * pow(ct.beta, pr.c0)) % P &&
    gPow(pr.v1) === (pr.a1 * pow(ct.alpha, pr.c1)) % P &&
    pk.kPow(pr.v1) === (pr.b1 * pow(bg, pr.c1)) % P
  );
}

// ------------------------------------------------------------------ threshold (Feldman k-of-n)
export type TrusteeCommitment = { index: number; commitments: bigint[]; proofs: Schnorr[] };
export const coefficientContext = (mh: string, index: number, j: number): HashItem[] => [mh, "trustee-coefficient", String(index), String(j)];

export function evalCommitments(Cs: bigint[], x: bigint): bigint {
  let acc = 1n;
  let xj = 1n;
  for (const C of Cs) {
    acc = (acc * pow(C, xj)) % P;
    xj = (xj * x) % Q;
  }
  return acc;
}

export class Trustee {
  private coeffs: bigint[];
  private received = new Map<number, bigint>();
  secretShare: bigint | null = null;
  available = true;
  constructor(public index: number, public k: number, private mh: string) {
    this.coeffs = Array.from({ length: k }, rand);
  }
  commitment(): TrusteeCommitment {
    const Cs = this.coeffs.map(gPow);
    return { index: this.index, commitments: Cs, proofs: this.coeffs.map((a, j) => schnorrProve(a, Cs[j], coefficientContext(this.mh, this.index, j))) };
  }
  shareFor(i: number): bigint {
    let acc = 0n;
    let xj = 1n;
    for (const a of this.coeffs) {
      acc = (acc + a * xj) % Q;
      xj = (xj * BigInt(i)) % Q;
    }
    return acc;
  }
  receiveShare(tc: TrusteeCommitment, share: bigint): void {
    if (!isScalar(share) || gPow(share) !== evalCommitments(tc.commitments, BigInt(this.index))) throw new Error(`trustee ${this.index}: invalid share from ${tc.index}`);
    this.received.set(tc.index, share);
  }
  finalize(n: number): void {
    if (this.received.size !== n) throw new Error("missing shares");
    this.secretShare = [...this.received.values()].reduce((a, b) => (a + b) % Q, 0n);
    this.coeffs = []; // destroy polynomial coefficients
  }
  decryptionShare(ct: Ct, ctx: HashItem[]): { M: bigint; proof: CP } {
    if (this.secretShare === null) throw new Error("ceremony not finished");
    const M = pow(ct.alpha, this.secretShare);
    return { M, proof: cpProve(this.secretShare, ct.alpha, gPow(this.secretShare), M, "decryption-share", ctx) };
  }
}

export function publicShare(comms: TrusteeCommitment[], i: number): bigint {
  return comms.reduce((acc, tc) => (acc * evalCommitments(tc.commitments, BigInt(i))) % P, 1n);
}

export function lagrangeAtZero(idx: number[], i: number): bigint {
  let num = 1n;
  let den = 1n;
  for (const m of idx) if (m !== i) {
    num = (num * BigInt(m)) % Q;
    den = (((den * BigInt(m - i)) % Q) + Q) % Q;
  }
  return (num * modinv(den, Q)) % Q;
}

export function combineShares(ct: Ct, shares: Map<number, bigint>): bigint {
  const idx = [...shares.keys()].sort((a, b) => a - b);
  let s = 1n;
  for (const i of idx) s = (s * pow(shares.get(i)!, lagrangeAtZero(idx, i))) % P;
  return div(ct.beta, s);
}
