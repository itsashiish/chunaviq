// Group, ElGamal, zero-knowledge proofs, threshold keys. Mirrors src/chunaviq/crypto/*.py.
import { sha256 } from "@noble/hashes/sha2.js";
import { shake256 } from "@noble/hashes/sha3.js";
import { bigintToMinBytes, bytesToBigint, FixedBase, fromHex, modinv, modpow, randBelow, randScalar, toHex } from "./bigint";
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

/** Baby-step giant-step discrete log in [0, bound]: O(sqrt(bound)). */
export function dlogBounded(gm: bigint, bound: number): number {
  const n = Math.floor(Math.sqrt(bound)) + 1;
  const baby = new Map<bigint, number>();
  let acc = 1n;
  for (let j = 0; j < n; j++) {
    if (!baby.has(acc)) baby.set(acc, j);
    acc = (acc * G) % P;
  }
  const giant = modinv(acc, P);
  let gamma = ((gm % P) + P) % P;
  for (let i = 0; i <= n; i++) {
    const j = baby.get(gamma);
    if (j !== undefined) {
      const m = i * n + j;
      if (m <= bound) return m;
      break;
    }
    gamma = (gamma * giant) % P;
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

// ------------------------------------------------------------------ Sigma proofs (protocol v2; mirrors src/chunaviq/crypto/sigma.py)
/** One equation: value = prod base^w[idx]. */
export type Eq = [bigint, [bigint, number][]];
export type Statement = { eqs: Eq[]; n: number };
export type SigmaProof = { c: string; s: string[] };
export type OrProof = { c: string[]; s: string[][] };
type Fast = Map<bigint, (e: bigint) => bigint>;

const encodeStatement = (st: Statement): HashItem[] => st.eqs.map(([v, terms]) => [v, terms.map(([b]) => b), terms.map(([, i]) => String(i))]);
const powWith = (fast?: Fast) => (b: bigint, e: bigint) => {
  const f = fast?.get(b);
  return f ? f(((e % Q) + Q) % Q) : pow(b, e);
};

function recommit(st: Statement, s: bigint[], c: bigint, pw: (b: bigint, e: bigint) => bigint): bigint[] {
  return st.eqs.map(([v, terms]) => {
    let acc = c % Q ? pw(v, Q - (c % Q)) : 1n;
    for (const [b, i] of terms) acc = (acc * pw(b, s[i])) % P;
    return acc;
  });
}

export function sigmaProve(st: Statement, w: bigint[], domain: string, ctx: HashItem[], fast?: Fast): SigmaProof {
  const pw = powWith(fast);
  const rho = Array.from({ length: st.n }, rand);
  const A = st.eqs.map(([, terms]) => terms.reduce((acc, [b, i]) => (acc * pw(b, rho[i])) % P, 1n));
  const c = hashToScalar(Q, domain, ctx, [encodeStatement(st)], [A]);
  return { c: toHex(c), s: rho.map((r, i) => toHex((r + c * w[i]) % Q)) };
}

export function sigmaVerify(st: Statement, pr: SigmaProof, domain: string, ctx: HashItem[], fast?: Fast): boolean {
  try {
    if (!pr || Object.keys(pr).length !== 2 || !Array.isArray(pr.s) || pr.s.length !== st.n) return false;
    const c = fromHex(pr.c);
    const s = pr.s.map(fromHex);
    if (!isScalar(c, ...s) || !st.eqs.every(([v]) => isElement(v))) return false;
    return hashToScalar(Q, domain, ctx, [encodeStatement(st)], [recommit(st, s, c, powWith(fast))]) === c;
  } catch {
    return false;
  }
}

export function sigmaProveOr(branches: Statement[], real: number, w: bigint[], domain: string, ctx: HashItem[], fast?: Fast): OrProof {
  const pw = powWith(fast);
  const cs: bigint[] = branches.map(() => 0n);
  const ss: bigint[][] = branches.map(() => []);
  const A: bigint[][] = branches.map(() => []);
  branches.forEach((st, b) => {
    if (b === real) return;
    cs[b] = rand();
    ss[b] = Array.from({ length: st.n }, rand);
    A[b] = recommit(st, ss[b], cs[b], pw);
  });
  const st = branches[real];
  const rho = Array.from({ length: st.n }, rand);
  A[real] = st.eqs.map(([, terms]) => terms.reduce((acc, [b, i]) => (acc * pw(b, rho[i])) % P, 1n));
  const c = hashToScalar(Q, domain, ctx, branches.map(encodeStatement), A);
  cs[real] = (((c - cs.reduce((a, b) => a + b, 0n)) % Q) + Q) % Q;
  ss[real] = rho.map((r, i) => (r + cs[real] * w[i]) % Q);
  return { c: cs.map(toHex), s: ss.map((x) => x.map(toHex)) };
}

export function sigmaVerifyOr(branches: Statement[], pr: OrProof, domain: string, ctx: HashItem[], fast?: Fast): boolean {
  try {
    if (!pr || Object.keys(pr).length !== 2 || pr.c.length !== branches.length || pr.s.length !== branches.length) return false;
    const cs = pr.c.map(fromHex);
    const ss = pr.s.map((x) => x.map(fromHex));
    if (ss.some((x, b) => x.length !== branches[b].n) || !isScalar(...cs, ...ss.flat())) return false;
    if (!branches.every((st) => st.eqs.every(([v]) => isElement(v)))) return false;
    const pw = powWith(fast);
    const A = branches.map((st, b) => recommit(st, ss[b], cs[b], pw));
    return hashToScalar(Q, domain, ctx, branches.map(encodeStatement), A) === cs.reduce((a, b) => a + b, 0n) % Q;
  } catch {
    return false;
  }
}

const dh = (K: bigint, x: bigint, y: bigint, i: number): Eq[] => [
  [x, [[G, i]]],
  [y, [[K, i]]],
];
export const tagStatement = (K: bigint, a: bigint, b: bigint): Statement => ({
  eqs: [
    [a, [[G, 0]]],
    [b, [[G, 1], [K, 0]]],
  ],
  n: 2,
});
export const linkStatement = (K: bigint, a: bigint, b: bigint, T: bigint): Statement => ({ eqs: dh(K, a, div(b, T), 0), n: 1 });
export function finalizeBranches(K: bigint, flag: Ct, votes: Ct[], masked: Ct[]): Statement[] {
  const zero = dh(K, flag.alpha, flag.beta, 0);
  const one = dh(K, flag.alpha, div(flag.beta, G), 0);
  votes.forEach((v, j) => {
    zero.push(...dh(K, masked[j].alpha, masked[j].beta, j + 1));
    one.push(...dh(K, div(masked[j].alpha, v.alpha), div(masked[j].beta, v.beta), j + 1));
  });
  return [
    { eqs: zero, n: votes.length + 1 },
    { eqs: one, n: votes.length + 1 },
  ];
}
export const dvBranches = (K: bigint, flag: Ct, T: bigint): Statement[] => [
  { eqs: dh(K, flag.alpha, div(flag.beta, G), 0), n: 1 },
  { eqs: [[T, [[G, 0]]]], n: 1 },
];
export const fastFor = (pk: PublicKey): Fast =>
  new Map([
    [G, gPow],
    [pk.K, (e: bigint) => pk.kPow(e)],
  ]);

// ------------------------------------------------------------------ verifiable shuffle (mirrors src/chunaviq/crypto/shuffle.py)
export type Row = Ct[];
export type ShuffleProof = { commitments: string[]; chain: string[]; c: string; s1: string; s2: string; s3: string; s4: string[]; shat: string[]; sprime: string[] };

const GENS: bigint[] = [];
function deriveGenerator(label: number): bigint {
  const nb = Math.ceil(P.toString(2).length / 8) + 16;
  for (let ctr = 0; ; ctr++) {
    const seed = new TextEncoder().encode(`chunaviq/v1/shuffle-generator\u0000${label}\u0000${ctr}`);
    const x = bytesToBigint(shake256(seed, { dkLen: nb })) % P;
    const h = modpow(x, (P - 1n) / Q, P);
    if (h > 1n) return h;
  }
}
export function generators(n: number): bigint[] {
  while (GENS.length < n + 1) GENS.push(deriveGenerator(GENS.length));
  return GENS.slice(0, n + 1);
}

export function digestInts(values: Iterable<bigint>): Uint8Array {
  const h = sha256.create();
  for (const x of values) {
    const raw = bigintToMinBytes(x);
    h.update(new Uint8Array([(raw.length >>> 24) & 255, (raw.length >>> 16) & 255, (raw.length >>> 8) & 255, raw.length & 255]));
    h.update(raw);
  }
  return h.digest();
}
export const digestRows = (rows: Row[]) => digestInts(rows.flatMap((r) => r.flatMap((c) => [c.alpha, c.beta])));

const uVector = (ctx: HashItem[], din: Uint8Array, dout: Uint8Array, dcom: Uint8Array, n: number) => {
  const seed = hashToScalar(Q, "shuffle-u-seed", ctx, din, dout, dcom);
  return Array.from({ length: n }, (_, j) => hashToScalar(Q, "shuffle-u", seed, BigInt(j)));
};

export function shuffleAndProve(pk: PublicKey, rows: Row[], ctx: HashItem[]): { out: Row[]; proof: ShuffleProof } {
  const N = rows.length;
  const w = rows[0].length;
  const H = generators(N);
  const perm = Array.from({ length: N }, (_, i) => i);
  for (let i = N - 1; i > 0; i--) {
    const j = Number(randBelow(BigInt(i + 1))); // Fisher-Yates, uniform
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }
  const rr = rows.map(() => Array.from({ length: w }, rand));
  const out: Row[] = perm.map((src, i) => rows[src].map((c, k) => ({ alpha: (c.alpha * gPow(rr[i][k])) % P, beta: (c.beta * pk.kPow(rr[i][k])) % P })));
  const r = Array.from({ length: N }, rand);
  const com: bigint[] = Array(N).fill(0n);
  perm.forEach((j, i) => (com[j] = (gPow(r[j]) * H[i + 1]) % P));
  const din = digestRows(rows);
  const dout = digestRows(out);
  const dcom = digestInts(com);
  const u = uVector(ctx, din, dout, dcom, N);
  const up = perm.map((j) => u[j]);
  const rh = Array.from({ length: N }, rand);
  const chain: bigint[] = [];
  let prev = H[0];
  for (let i = 0; i < N; i++) {
    prev = (gPow(rh[i]) * pow(prev, up[i])) % P;
    chain.push(prev);
  }
  const rBar = r.reduce((a, b) => (a + b) % Q, 0n);
  let rHat = 0n;
  let acc = 1n;
  for (let i = N - 1; i >= 0; i--) {
    rHat = (rHat + rh[i] * acc) % Q;
    acc = (acc * up[i]) % Q;
  }
  const rTld = r.reduce((s, rj, j) => (s + rj * u[j]) % Q, 0n);
  const rP = Array.from({ length: w }, (_, k) => rr.reduce((s, ri, i) => (s + ri[k] * up[i]) % Q, 0n));
  const [w1, w2, w3] = [rand(), rand(), rand()];
  const w4 = Array.from({ length: w }, rand);
  const what = Array.from({ length: N }, rand);
  const wp = Array.from({ length: N }, rand);
  let t3 = gPow(w3);
  for (let i = 0; i < N; i++) t3 = (t3 * pow(H[i + 1], wp[i])) % P;
  const t4a: bigint[] = [];
  const t4b: bigint[] = [];
  for (let k = 0; k < w; k++) {
    let a = gPow(Q - w4[k]);
    let b = pk.kPow(Q - w4[k]);
    for (let i = 0; i < N; i++) {
      a = (a * pow(out[i][k].alpha, wp[i])) % P;
      b = (b * pow(out[i][k].beta, wp[i])) % P;
    }
    t4a.push(a);
    t4b.push(b);
  }
  const that: bigint[] = [];
  prev = H[0];
  for (let i = 0; i < N; i++) {
    that.push((gPow(what[i]) * pow(prev, wp[i])) % P);
    prev = chain[i];
  }
  const c = hashToScalar(Q, "shuffle-c", ctx, din, dout, dcom, digestInts(chain), [gPow(w1), gPow(w2), t3, ...t4a, ...t4b], digestInts(that));
  return {
    out,
    proof: {
      commitments: com.map(toHex),
      chain: chain.map(toHex),
      c: toHex(c),
      s1: toHex((w1 + c * rBar) % Q),
      s2: toHex((w2 + c * rHat) % Q),
      s3: toHex((w3 + c * rTld) % Q),
      s4: w4.map((x, k) => toHex((x + c * rP[k]) % Q)),
      shat: what.map((x, i) => toHex((x + c * rh[i]) % Q)),
      sprime: wp.map((x, i) => toHex((x + c * up[i]) % Q)),
    },
  };
}

export const rowsToJson = (rows: Row[]) => rows.map((r) => r.map(ctToJson));
export const rowsFromJson = (d: { alpha: string; beta: string }[][]): Row[] => d.map((r) => r.map(ctFromJson));
