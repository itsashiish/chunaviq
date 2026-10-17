// Independent verifier for ChunavIQ records (protocol v2), in TypeScript.
// Port of src/chunaviq_verify/verifier.py. Independence rule: this module does not import the
// election engine (crypto.ts, ballot.ts, election.ts); it re-implements every check from the spec
// and shares only byte-level helpers (big integers, canonical JSON, SHA-256, Ed25519, Merkle).
import { sha256 } from "@noble/hashes/sha2.js";
import { shake256 } from "@noble/hashes/sha3.js";
import { bigintToMinBytes, bytesToBigint, bytesToHex, fromHex, hexToBytes, modinv, modpow } from "./bigint";
import { canonicalJson, hashToScalar, sha256Hex, type HashItem, type Json } from "./encoding";
import { leafHash, rootsAt, verifyConsistency, verifyInclusion } from "./merkle";
import { G as GG, GROUP_NAME, P as PP, Q as QQ } from "./params";
import { verifyBody, type Body } from "./sign";

export type Status = "PASS" | "FAIL" | "WARN";
export type Check = { id: string; title: string; status: Status; detail: string };
export type Report = { status: "VERIFIED" | "NOT VERIFIED"; failures: number; warnings: number; checks: Check[]; results: Record<string, Json>; facts: Record<string, Json> };

const P = PP;
const Q = QQ;
const G = GG;
const pw = (b: bigint, e: bigint) => modpow(b, ((e % Q) + Q) % Q, P);
const member = (x: bigint) => x >= 1n && x < P && modpow(x, Q, P) === 1n;
const rng = (...xs: bigint[]) => xs.every((x) => x >= 1n && x < P);
const sc = (...xs: bigint[]) => xs.every((x) => x >= 0n && x < Q);
const inv = (x: bigint) => modinv(x, P);
const keysAre = (o: unknown, keys: string[]) => !!o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).length === keys.length && keys.every((k) => k in (o as object));
const enc = new TextEncoder();
type CtJ = { alpha: string; beta: string };
type C2 = [bigint, bigint];
const ct = (d: CtJ): C2 => {
  if (!keysAre(d, ["alpha", "beta"])) throw new Error("ciphertext schema");
  return [fromHex(d.alpha), fromHex(d.beta)];
};

export type VerifyCtx = { K: string; mh: string; eid: string; options: Record<string, string[]> };

function cpOk(H: bigint, X: bigint, Y: bigint, a: bigint, b: bigint, v: bigint, domain: string, ctx: HashItem[]) {
  if (!(member(H) && member(X) && member(Y) && rng(a, b) && sc(v))) return false;
  const c = hashToScalar(Q, domain, ctx, H, X, Y, a, b);
  return pw(G, v) === (a * pw(X, c)) % P && pw(H, v) === (b * pw(Y, c)) % P;
}

// ------------------------------------------------------------------ Sigma / OR proofs (re-implemented)
type Eq = [bigint, [bigint, number][]];
const encSt = (eqs: Eq[]): HashItem[] => eqs.map(([v, t]) => [v, t.map(([b]) => b), t.map(([, i]) => String(i))]);
function recommit(eqs: Eq[], s: bigint[], c: bigint): bigint[] {
  return eqs.map(([v, terms]) => {
    let acc = c % Q ? pw(v, Q - (c % Q)) : 1n;
    for (const [b, i] of terms) acc = (acc * pw(b, s[i])) % P;
    return acc;
  });
}
function scalars(xs: unknown): bigint[] | null {
  if (!Array.isArray(xs)) return null;
  try {
    const v = xs.map((x) => fromHex(x));
    return sc(...v) ? v : null;
  } catch {
    return null;
  }
}
export function sigmaOk(eqs: Eq[], n: number, pr: Record<string, Json>, domain: string, ctx: HashItem[]): boolean {
  if (!keysAre(pr, ["c", "s"])) return false;
  const c = scalars([pr.c]);
  const s = scalars(pr.s);
  if (!c || !s || s.length !== n || !eqs.every(([v]) => member(v))) return false;
  return hashToScalar(Q, domain, ctx, [encSt(eqs)], [recommit(eqs, s, c[0])]) === c[0];
}
export function sigmaOrOk(branches: [Eq[], number][], pr: Record<string, Json>, domain: string, ctx: HashItem[]): boolean {
  if (!keysAre(pr, ["c", "s"])) return false;
  const cs = scalars(pr.c);
  if (!cs || cs.length !== branches.length || !Array.isArray(pr.s) || pr.s.length !== branches.length) return false;
  const A: bigint[][] = [];
  for (let b = 0; b < branches.length; b++) {
    const [eqs, n] = branches[b];
    const s = scalars(pr.s[b]);
    if (!s || s.length !== n || !eqs.every(([v]) => member(v))) return false;
    A.push(recommit(eqs, s, cs[b]));
  }
  return hashToScalar(Q, domain, ctx, branches.map(([eqs]) => encSt(eqs)), A) === cs.reduce((a, b) => a + b, 0n) % Q;
}
const dh = (K: bigint, x: bigint, y: bigint, i: number): Eq[] => [
  [x, [[G, i]]],
  [y, [[K, i]]],
];
const tagEqs = (K: bigint, a: bigint, b: bigint): Eq[] => [
  [a, [[G, 0]]],
  [b, [[G, 1], [K, 0]]],
];
function finalBranches(K: bigint, F: C2, votes: C2[], masked: C2[]): [Eq[], number][] {
  const zero = dh(K, F[0], F[1], 0);
  const one = dh(K, F[0], (F[1] * inv(G)) % P, 0);
  votes.forEach(([va, vb], j) => {
    zero.push(...dh(K, masked[j][0], masked[j][1], j + 1));
    one.push(...dh(K, (masked[j][0] * inv(va)) % P, (masked[j][1] * inv(vb)) % P, j + 1));
  });
  return [
    [zero, votes.length + 1],
    [one, votes.length + 1],
  ];
}

// ------------------------------------------------------------------ shuffle (re-implemented)
const GENS: bigint[] = [];
function generators(n: number): bigint[] {
  const nb = Math.ceil(P.toString(2).length / 8) + 16;
  while (GENS.length < n + 1) {
    for (let ctr = 0; ; ctr++) {
      const x = bytesToBigint(shake256(enc.encode(`chunaviq/v1/shuffle-generator\u0000${GENS.length}\u0000${ctr}`), { dkLen: nb })) % P;
      const h = modpow(x, (P - 1n) / Q, P);
      if (h > 1n) {
        GENS.push(h);
        break;
      }
    }
  }
  return GENS.slice(0, n + 1);
}
function digest(values: bigint[]): Uint8Array {
  const h = sha256.create();
  for (const x of values) {
    const raw = bigintToMinBytes(x);
    h.update(new Uint8Array([(raw.length >>> 24) & 255, (raw.length >>> 16) & 255, (raw.length >>> 8) & 255, raw.length & 255]));
    h.update(raw);
  }
  return h.digest();
}
type RowC = { alpha: bigint; beta: bigint }[];
const rowsDigest = (rows: RowC[]) => digest(rows.flatMap((r) => r.flatMap((c) => [c.alpha, c.beta])));

/** Terelius-Wikstrom shuffle proof check. Inputs are assumed valid; outputs, commitments and chain are checked. */
export function shuffleOk(K: bigint, rows: RowC[], out: RowC[], proof: Record<string, Json>, ctx: HashItem[]): boolean {
  try {
    if (!keysAre(proof, ["commitments", "chain", "c", "s1", "s2", "s3", "s4", "shat", "sprime"])) return false;
    const N = rows.length;
    if (!N || out.length !== N) return false;
    const w = rows[0].length;
    if (rows.some((r) => r.length !== w) || out.some((r) => r.length !== w)) return false;
    const com = (proof.commitments as string[]).map(fromHex);
    const chain = (proof.chain as string[]).map(fromHex);
    const [c, s1, s2, s3] = (["c", "s1", "s2", "s3"] as const).map((k) => fromHex(proof[k]));
    const s4 = (proof.s4 as string[]).map(fromHex);
    const shat = (proof.shat as string[]).map(fromHex);
    const sp = (proof.sprime as string[]).map(fromHex);
    if (com.length !== N || chain.length !== N || s4.length !== w || shat.length !== N || sp.length !== N) return false;
    if (!sc(c, s1, s2, s3, ...s4, ...shat, ...sp)) return false;
    if (![...com, ...chain].every(member) || !out.every((r) => r.every((x) => member(x.alpha) && member(x.beta)))) return false;
    const H = generators(N);
    const din = rowsDigest(rows);
    const dout = rowsDigest(out);
    const dcom = digest(com);
    const seed = hashToScalar(Q, "shuffle-u-seed", ctx, din, dout, dcom);
    const u = Array.from({ length: N }, (_, j) => hashToScalar(Q, "shuffle-u", seed, BigInt(j)));
    const nc = Q - c;
    let cbar = com.reduce((a, x) => (a * x) % P, 1n);
    cbar = (cbar * inv(H.slice(1).reduce((a, x) => (a * x) % P, 1n))) % P;
    const up = u.reduce((a, x) => (a * x) % Q, 1n);
    const chat = (chain[N - 1] * inv(pw(H[0], up))) % P;
    const ctld = com.reduce((a, x, j) => (a * pw(x, u[j])) % P, 1n);
    const t1 = (pw(G, s1) * pw(cbar, nc)) % P;
    const t2 = (pw(G, s2) * pw(chat, nc)) % P;
    let t3 = (pw(G, s3) * pw(ctld, nc)) % P;
    for (let i = 0; i < N; i++) t3 = (t3 * pw(H[i + 1], sp[i])) % P;
    const t4a: bigint[] = [];
    const t4b: bigint[] = [];
    for (let k = 0; k < w; k++) {
      let at = 1n;
      let bt = 1n;
      for (let j = 0; j < N; j++) {
        at = (at * pw(rows[j][k].alpha, u[j])) % P;
        bt = (bt * pw(rows[j][k].beta, u[j])) % P;
      }
      let a = (pw(G, Q - s4[k]) * pw(at, nc)) % P;
      let b = (pw(K, Q - s4[k]) * pw(bt, nc)) % P;
      for (let i = 0; i < N; i++) {
        a = (a * pw(out[i][k].alpha, sp[i])) % P;
        b = (b * pw(out[i][k].beta, sp[i])) % P;
      }
      t4a.push(a);
      t4b.push(b);
    }
    const that: bigint[] = [];
    let prev = H[0];
    for (let i = 0; i < N; i++) {
      that.push((((pw(G, shat[i]) * pw(prev, sp[i])) % P) * pw(chain[i], nc)) % P);
      prev = chain[i];
    }
    return hashToScalar(Q, "shuffle-c", ctx, din, dout, dcom, digest(chain), [t1, t2, t3, ...t4a, ...t4b], digest(that)) === c;
  } catch {
    return false;
  }
}

// ------------------------------------------------------------------ per-item checks (pure; safe in workers)
/** Verify one ballot; returns a rejection code or null. */
export function verifyBallot(b: Record<string, Json>, c: VerifyCtx): string | null {
  try {
    const K = fromHex(c.K);
    if (!keysAre(b, ["election_id", "constituency", "tag", "selections", "limit_proof"])) return "MALFORMED";
    if (b.election_id !== c.eid) return "WRONG_ELECTION";
    const cons = b.constituency as string;
    if (!(cons in c.options)) return "UNKNOWN_CONSTITUENCY";
    const tag = b.tag as Record<string, Json>;
    if (!keysAre(tag, ["ciphertext", "proof"])) return "MALFORMED";
    const [ta, tb] = ct(tag.ciphertext as CtJ);
    if (!member(ta) || !member(tb)) return "INVALID_CIPHERTEXT";
    const tah = (tag.ciphertext as CtJ).alpha;
    const sels = b.selections as Record<string, Json>[];
    if (!Array.isArray(sels) || sels.map((s) => s?.option_id).join("\u0000") !== c.options[cons].join("\u0000")) return "WRONG_BALLOT_STYLE";
    let A = 1n;
    let B = 1n;
    for (const s of sels) {
      const pr = s.proof as Record<string, string>;
      if (!keysAre(s, ["option_id", "ciphertext", "proof"]) || !keysAre(pr, ["a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1"])) return "MALFORMED";
      const [al, be] = ct(s.ciphertext as CtJ);
      const [a0, b0, a1, b1, c0, c1, v0, v1] = ["a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1"].map((k) => fromHex(pr[k]));
      if (!(member(al) && member(be) && rng(a0, b0, a1, b1) && sc(c0, c1, v0, v1))) return "BAD_SELECTION_PROOF";
      const ctx: HashItem[] = [c.mh, "selection", cons, s.option_id as string, tah];
      if ((c0 + c1) % Q !== hashToScalar(Q, "selection-0or1", ctx, K, al, be, a0, b0, a1, b1)) return "BAD_SELECTION_PROOF";
      const bg = (be * inv(G)) % P;
      if (!(pw(G, v0) === (a0 * pw(al, c0)) % P && pw(K, v0) === (b0 * pw(be, c0)) % P && pw(G, v1) === (a1 * pw(al, c1)) % P && pw(K, v1) === (b1 * pw(bg, c1)) % P))
        return "BAD_SELECTION_PROOF";
      A = (A * al) % P;
      B = (B * be) % P;
    }
    const lp = b.limit_proof as Record<string, string>;
    if (!keysAre(lp, ["a", "b", "v"])) return "MALFORMED";
    if (!cpOk(K, A, (B * inv(G)) % P, fromHex(lp.a), fromHex(lp.b), fromHex(lp.v), "contest-limit", [c.mh, "contest-limit", cons, tah])) return "BAD_LIMIT_PROOF";
    const dg = sha256Hex(enc.encode(canonicalJson({ selections: sels, limit_proof: lp } as Json)));
    if (!sigmaOk(tagEqs(K, ta, tb), 2, tag.proof as Record<string, Json>, "ballot-tag", [c.mh, "ballot-tag", cons, dg])) return "BAD_TAG_PROOF";
    return null;
  } catch {
    return "MALFORMED";
  }
}

export type FinalCheck = { seq: number; cons: string; tc: string; votes: CtJ[]; item: Record<string, Json> };
/** Verify one finalization item against its ballot's votes. */
export function verifyFinalItem(x: FinalCheck, c: VerifyCtx): boolean {
  try {
    const it = x.item;
    if (!keysAre(it, ["seq", "tracking_code", "flag", "masked", "proof"]) || it.seq !== x.seq || it.tracking_code !== x.tc) return false;
    const masked = (it.masked as CtJ[]).map(ct);
    if (masked.length !== x.votes.length) return false;
    const F = ct(it.flag as CtJ);
    if (![...F, ...masked.flat()].every(member)) return false;
    return sigmaOrOk(finalBranches(fromHex(c.K), F, x.votes.map(ct), masked), it.proof as Record<string, Json>, "finalize", [c.mh, "finalize", x.cons, x.tc]);
  } catch {
    return false;
  }
}

const lagrange0 = (idx: number[], i: number) => {
  let num = 1n;
  let den = 1n;
  for (const m of idx) if (m !== i) {
    num = (num * BigInt(m)) % Q;
    den = (((den * BigInt(m - i)) % Q) + Q) % Q;
  }
  return (num * modinv(den, Q)) % Q;
};
const combine = (beta: bigint, shares: Map<number, bigint>) => {
  const idx = [...shares.keys()].sort((a, b) => a - b);
  let s = 1n;
  for (const i of idx) s = (s * pw(shares.get(i)!, lagrange0(idx, i))) % P;
  return (beta * inv(s)) % P;
};

export type MixCheck = { cons: string; batch: number; rows: CtJ[][]; shuffles: Body[]; flags: Body[]; tags: Body[]; pubs: Record<string, string>; k: number };
/** Verify one mixing batch: shuffle chain, every flag share, every tag share. */
export function verifyMixBatch(j: MixCheck, c: VerifyCtx): { problems: string[]; tags: string[] } {
  const problems: string[] = [];
  try {
    const K = fromHex(c.K);
    let cur: RowC[] = j.rows.map((r) => r.map((x) => ({ alpha: fromHex(x.alpha), beta: fromHex(x.beta) })));
    for (const sb of j.shuffles) {
      const out = (sb.rows as CtJ[][]).map((r) => r.map((x) => ({ alpha: fromHex(x.alpha), beta: fromHex(x.beta) })));
      if (!shuffleOk(K, cur, out, sb.proof as Record<string, Json>, [c.mh, "mix", j.cons, String(j.batch), String(sb.mixer)])) problems.push(`${j.cons}/${j.batch}: shuffle by trustee ${sb.mixer} does not verify`);
      cur = out;
    }
    const fsh = new Map<number, bigint[]>();
    for (const fb of j.flags) {
      const i = fb.index as number;
      const sh = fb.shares as { share: string; proof: { a: string; b: string; v: string } }[];
      if (sh.length !== cur.length) {
        problems.push(`${j.cons}/${j.batch}: trustee ${i} flag share count`);
        continue;
      }
      fsh.set(i, sh.map((x, r) => {
        const M = fromHex(x.share);
        if (!cpOk(cur[r][1].alpha, fromHex(j.pubs[String(i)]), M, fromHex(x.proof.a), fromHex(x.proof.b), fromHex(x.proof.v), "decryption-share", [c.mh, "mix-flag", j.cons, String(j.batch), String(r)]))
          problems.push(`${j.cons}/${j.batch}: invalid flag share from trustee ${i} row ${r}`);
        return M;
      }));
    }
    if (fsh.size < j.k) return { problems: [...problems, `${j.cons}/${j.batch}: only ${fsh.size} flag decryptions`], tags: [] };
    const want: number[] = [];
    cur.forEach((r, i) => {
      const gf = combine(r[1].beta, new Map([...fsh].map(([t, v]) => [t, v[i]])));
      if (gf !== 1n && gf !== G) problems.push(`${j.cons}/${j.batch}: row ${i} flag is not 0 or 1`);
      if (gf === G) want.push(i);
    });
    const tsh = new Map<number, bigint[]>();
    for (const tb of j.tags) {
      const i = tb.index as number;
      const sh = tb.shares as { share: string; proof: { a: string; b: string; v: string } }[];
      if ((tb.rows as number[]).join() !== want.join() || sh.length !== want.length) {
        problems.push(`${j.cons}/${j.batch}: trustee ${i} decrypted tags of rows other than the counted ones`);
        continue;
      }
      tsh.set(i, sh.map((x, n) => {
        const r = want[n];
        const M = fromHex(x.share);
        if (!cpOk(cur[r][0].alpha, fromHex(j.pubs[String(i)]), M, fromHex(x.proof.a), fromHex(x.proof.b), fromHex(x.proof.v), "decryption-share", [c.mh, "mix-tag", j.cons, String(j.batch), String(r)]))
          problems.push(`${j.cons}/${j.batch}: invalid tag share from trustee ${i} row ${r}`);
        return M;
      }));
    }
    if (want.length && tsh.size < j.k) return { problems: [...problems, `${j.cons}/${j.batch}: only ${tsh.size} tag decryptions`], tags: [] };
    return { problems, tags: want.map((r, n) => combine(cur[r][0].beta, new Map([...tsh].map(([t, v]) => [t, v[n]]))).toString(16)) };
  } catch (e) {
    return { problems: [...problems, `${j.cons}/${j.batch}: malformed (${(e as Error).message})`], tags: [] };
  }
}

/** Heavy checks can run in worker threads: the app passes a runner backed by its worker pool. */
export type VerifyRunner = {
  ballots: (items: Record<string, Json>[], ctx: VerifyCtx, onProgress?: (n: number) => void) => Promise<(string | null)[]>;
  finals: (items: FinalCheck[], ctx: VerifyCtx, onProgress?: (n: number) => void) => Promise<boolean[]>;
  mixes: (items: MixCheck[], ctx: VerifyCtx, onProgress?: (n: number) => void) => Promise<{ problems: string[]; tags: string[] }[]>;
};
export const inlineRunner: VerifyRunner = {
  ballots: async (items, ctx, p) => items.map((b, i) => (p?.(i + 1), verifyBallot(b, ctx))),
  finals: async (items, ctx, p) => items.map((x, i) => (p?.(i + 1), verifyFinalItem(x, ctx))),
  mixes: async (items, ctx, p) => items.map((x, i) => (p?.(i + 1), verifyMixBatch(x, ctx))),
};

class StructureError extends Error {}

function decide(counts: Record<string, number>) {
  const c = Object.entries(counts).filter(([k]) => k !== "NOTA");
  const top = c.length ? Math.max(...c.map(([, v]) => v)) : 0;
  const lead = c.filter(([, v]) => v === top).map(([k]) => k).sort();
  return { winner: lead.length === 1 ? lead[0] : null, tied: lead.length > 1 ? lead : [], nota_exceeds_winner: (counts.NOTA ?? 0) > top };
}

/** Independent baby-step giant-step (does not import the engine's version). */
function bsgs(target: bigint, bound: number): number | null {
  const n = Math.floor(Math.sqrt(bound)) + 1;
  const table = new Map<bigint, number>();
  let acc = 1n;
  for (let j = 0; j < n; j++) {
    if (!table.has(acc)) table.set(acc, j);
    acc = (acc * G) % P;
  }
  const step = inv(acc);
  let cur = target;
  for (let i = 0; i <= n; i++) {
    const j = table.get(cur);
    if (j !== undefined) return i * n + j <= bound ? i * n + j : null;
    cur = (cur * step) % P;
  }
  return null;
}

const hourFloor = (s: string) => new Date(s).toISOString().slice(0, 13);
const listDigest = (items: string[]) => sha256Hex(enc.encode(items.map((x) => x + "\n").join("")));

export async function verifyRecord(
  entriesText: string,
  checkpointsText: string,
  opts: { expectManifestHash?: string; runner?: VerifyRunner; onProgress?: (label: string, done: number, total: number) => void } = {},
): Promise<Report> {
  const checks: Check[] = [];
  const results: Record<string, Json> = {};
  const facts: Record<string, Json> = {};
  const runner = opts.runner ?? inlineRunner;
  const add = (id: string, title: string, ok: boolean | null, detail = "") => {
    checks.push({ id, title, status: ok === null ? "WARN" : ok ? "PASS" : "FAIL", detail });
    return !!ok;
  };
  try {
    await run();
  } catch (e) {
    if (e instanceof StructureError) add("record.structure", "Record follows the required entry sequence", false, e.message);
    else add("record.parse", "Record is well-formed", false, String((e as Error).message ?? e));
  }
  const failures = checks.filter((c) => c.status === "FAIL").length;
  return { status: checks.length && !failures ? "VERIFIED" : "NOT VERIFIED", failures, warnings: checks.filter((c) => c.status === "WARN").length, checks, results, facts };

  async function run() {
    const lines = entriesText.split("\n");
    if (lines[lines.length - 1] === "") lines.pop();
    const entries = lines.map((l) => JSON.parse(l) as { seq: number; type: string; time_bucket: string; body: Body });
    for (let i = 0; i < entries.length; i++) {
      if (canonicalJson(entries[i] as unknown as Json) !== lines[i] || entries[i].seq !== i) {
        add("record.canonical", "Entries are canonical and contiguously numbered", false, `entry ${i}`);
        return;
      }
    }
    add("record.canonical", "Entries are canonical and contiguously numbered", true, `${entries.length} entries`);
    facts.entries = entries.length;

    if (!entries.length || entries[0].type !== "manifest") throw new StructureError("first entry must be the manifest");
    const mb = entries[0].body;
    const man = mb.manifest as Record<string, Json>;
    const mh = sha256Hex(enc.encode(canonicalJson(man)));
    const keys = man.keys as Record<string, string>;
    add("manifest.spec", "Record uses protocol v2 (revoting, mixing)", man.spec_version === "chunaviq-record/2", String(man.spec_version));
    add("manifest.hash", "Manifest hash matches manifest content", mh === mb.manifest_hash, mh);
    add("manifest.signature", "Manifest signed by the election officer key it declares", verifyBody(mb, keys.officer, "officer"));
    if (opts.expectManifestHash) add("manifest.pinned", "Manifest hash equals the independently obtained value", opts.expectManifestHash === mh);
    else add("manifest.pinned", "Manifest hash pinned to an out-of-band value", null, "Not pinned: this record is self-consistent; its authenticity rests on where you got it.");
    const eid = man.election_id as string;
    const mix = man.mixing as { min_mixers: number; batch_size: number };
    Object.assign(facts, { election_id: eid, title: man.title, manifest_hash: mh, notice: man.notice, window: man.window, software: man.software, mixing: mix });
    if (man.group !== GROUP_NAME) {
      add("group.approved", "Election group is an approved parameter set", false, String(man.group));
      return;
    }
    add("group.approved", "Election group is an approved parameter set", true, GROUP_NAME);
    add("group.sanity", "Group generator has order q", G !== 1n && modpow(G, Q, P) === 1n && (P - 1n) % Q === 0n);

    const cps = checkpointsText.split("\n").filter(Boolean).map((l) => JSON.parse(l) as Body);
    const roots = rootsAt(lines.map((l) => leafHash(enc.encode(l))), new Set(cps.map((c) => c.tree_size as number)));
    let ok = cps.length > 0;
    let why = "";
    let prev: Body | null = null;
    for (const cp of cps) {
      const size = cp.tree_size as number;
      if (!verifyBody(cp, keys.board, "board") || cp.election_id !== eid) {
        ok = false;
        why = `bad signature at size ${size}`;
        break;
      }
      if (!roots.has(size) || bytesToHex(roots.get(size)!) !== cp.root) {
        ok = false;
        why = `root mismatch at size ${size} (entries altered, removed or inserted)`;
        break;
      }
      if (prev) {
        const ps = prev.tree_size as number;
        if (size <= ps || cp.prev_tree_size !== ps) {
          ok = false;
          why = `checkpoint sequence broken at size ${size}`;
          break;
        }
        if (!verifyConsistency(ps, size, hexToBytes(prev.root as string), hexToBytes(cp.root as string), (cp.consistency_proof as string[]).map(hexToBytes))) {
          ok = false;
          why = `consistency proof invalid ${ps}->${size}`;
          break;
        }
      }
      prev = cp;
    }
    add("board.checkpoints", "Every signed checkpoint matches the entries and extends its predecessor", ok, why || `${cps.length} checkpoints`);
    const last = cps[cps.length - 1];
    add("board.sealed", "Final signed checkpoint covers every entry", !!last && last.tree_size === entries.length, `final size ${last?.tree_size ?? 0} of ${entries.length}`);
    facts.final_root = (last?.root as string) ?? null;

    let pos = 1;
    const peek = () => entries[pos];
    const next = (type: string, state?: string) => {
      const e = entries[pos];
      if (!e) throw new StructureError(`record ends early; expected ${type}${state ? " " + state : ""}`);
      if (e.type !== type || (state && e.body.state !== state)) throw new StructureError(`entry ${e.seq}: expected ${type}${state ? " " + state : ""}, got ${e.type}`);
      pos++;
      return e;
    };
    const lifecycle = (state: string) => {
      const e = next("lifecycle", state);
      if (!verifyBody(e.body, keys.officer, "officer") || e.body.election_id !== eid) throw new StructureError(`lifecycle ${state} not signed by officer`);
      return e;
    };

    lifecycle("KEY_CEREMONY");
    const tr = man.trustees as { threshold: number; members: { index: number; role: string; public_key: string }[] };
    const k = tr.threshold;
    const cerCtx = (man.federation as { national_manifest_hash?: string } | undefined)?.national_manifest_hash ?? mh;
    const comms = new Map<number, bigint[]>();
    let pok = true;
    for (const m of tr.members) {
      const b = next("trustee_commitment").body;
      const c = b.commitment as { index: number; commitments: string[]; proofs: { h: string; v: string }[] };
      if (!verifyBody(b, m.public_key, m.role) || c.index !== m.index) throw new StructureError(`commitment of ${m.role} missing, out of order or wrongly signed`);
      const Cs = c.commitments.map(fromHex);
      if (Cs.length !== k || c.proofs.length !== k) pok = false;
      Cs.forEach((C, j) => {
        const h = fromHex(c.proofs[j].h);
        const v = fromHex(c.proofs[j].v);
        const ch = hashToScalar(Q, "schnorr", [cerCtx, "trustee-coefficient", String(m.index), String(j)], C, h);
        if (!(member(C) && rng(h) && sc(v) && pw(G, v) === (h * pw(C, ch)) % P)) pok = false;
      });
      comms.set(m.index, Cs);
    }
    add("ceremony.commitments", `All ${tr.members.length} trustees committed to degree-${k - 1} polynomials with valid proofs of knowledge`, pok);
    let acks = true;
    for (const m of tr.members) {
      const b = next("trustee_ack").body;
      acks &&= verifyBody(b, m.public_key, m.role) && b.index === m.index && b.verified_all_shares === true;
    }
    add("ceremony.acks", "Every trustee signed that all shares it received verified", acks);
    const jk = next("joint_key").body;
    let K = 1n;
    for (const Cs of comms.values()) K = (K * Cs[0]) % P;
    add("ceremony.joint_key", "Published joint key = product of trustees' constant commitments", verifyBody(jk, keys.officer, "officer") && fromHex(jk.joint_public_key as string) === K && member(K) && K !== 1n);
    const pubShare = (i: number) => {
      let acc = 1n;
      for (const Cs of comms.values()) {
        let xj = 1n;
        for (const C of Cs) {
          acc = (acc * pw(C, xj)) % P;
          xj = (xj * BigInt(i)) % Q;
        }
      }
      return acc;
    };
    lifecycle("READY");
    const openE = lifecycle("OPEN");

    // ballots
    const ballots: (typeof entries)[number][] = [];
    while (peek() && peek().type === "ballot") ballots.push(next("ballot"));
    const closeE = lifecycle("CLOSED");
    const consList = man.constituencies as { id: string; name: string; eligible_voters: number; options: { id: string; name: string }[] }[];
    const options = Object.fromEntries(consList.map((c) => [c.id, c.options.map((o) => o.id)]));
    const ctx: VerifyCtx = { K: K.toString(16), mh, eid, options };
    const bodies = ballots.map((b) => b.body.ballot as Record<string, Json>);
    const codes = await runner.ballots(bodies, ctx, (d) => opts.onProgress?.("Checking ballot proofs", d, bodies.length));
    const bad = codes.map((c, i) => [ballots[i].seq, c] as const).filter(([, c]) => c);
    add("ballots.valid", "Every ballot has valid ciphertexts, a tag proof and selection/limit proofs (exactly one selection)", bad.length === 0,
      `${bodies.length} checked` + (bad.length ? `; invalid: ${bad.slice(0, 5).map(([s, c]) => `#${s} ${c}`).join(", ")}` : ""));
    const alph = new Map<string, number>();
    for (const b of bodies) {
      const as = [((b.tag as Record<string, CtJ>)?.ciphertext)?.alpha, ...((b.selections as Record<string, CtJ>[]) ?? []).map((s) => s?.ciphertext?.alpha)];
      for (const a of as) alph.set(a, (alph.get(a) ?? 0) + 1);
    }
    add("ballots.no_copies", "No ciphertext appears twice (ballot-copying defence)", [...alph.values()].every((v) => v === 1));
    add("ballots.tracking_codes", "Tracking codes equal the hash of each ballot", ballots.every((e) => e.body.tracking_code === sha256Hex(enc.encode(canonicalJson(e.body.ballot)))));
    const win = man.window as { opens_at: string; closes_at: string };
    const w0 = hourFloor(win.opens_at);
    const w1 = hourFloor(win.closes_at);
    add("ballots.window", "Ballots were recorded inside the published voting window (hour resolution)", ballots.every((e) => e.time_bucket >= w0 && e.time_bucket <= w1));
    add("lifecycle.open_time", "Election opened no earlier than the published opening hour", openE.time_bucket >= w0);
    const cb = closeE.body;
    add("lifecycle.close_count", "CLOSED entry states the number of ballots actually recorded", cb.ballots_accepted === ballots.length, `${cb.ballots_accepted} vs ${ballots.length}`);
    if ("early_close_reason" in cb) add("lifecycle.early_close", "Polls closed at the published time", null, `EARLY CLOSE: ${cb.early_close_reason}`);
    facts.rejections_by_reason = (cb.rejections_by_reason as Json) ?? {};
    facts.ballots_cast = ballots.length;

    // registrations
    const rs = next("registration_summary").body;
    let rOk = verifyBody(rs, keys.eligibility, "eligibility");
    const notes: string[] = [];
    const sums = rs.constituencies as Record<string, Record<string, number | string>>;
    for (const c of consList) {
      const s = sums[c.id];
      if (!s) {
        rOk = false;
        notes.push(`${c.id}: missing`);
        continue;
      }
      if (!(s.eligible === c.eligible_voters && (s.registered as number) <= (s.eligible as number) && s.valid_tags === (s.registered as number) - (s.voted_in_person as number))) {
        rOk = false;
        notes.push(`${c.id}: counts inconsistent`);
      }
      results[c.id] = { eligible: s.eligible, registered: s.registered, voted_in_person: s.voted_in_person, reregistrations: s.reregistrations } as Json;
    }
    const lists = new Map<string, string[]>();
    const nextIdx = new Map<string, number>();
    while (peek() && peek().type === "registration_list") {
      const b = next("registration_list").body;
      const key = `${b.constituency}|${b.list}`;
      if (!verifyBody(b, keys.eligibility, "eligibility") || !["commitments", "valid_tags"].includes(b.list as string) || b.index !== (nextIdx.get(key) ?? 0)) rOk = false;
      nextIdx.set(key, (nextIdx.get(key) ?? 0) + 1);
      lists.set(key, [...(lists.get(key) ?? []), ...(b.items as string[])]);
    }
    const valid = new Map<string, Set<string>>();
    for (const c of consList) {
      const s = sums[c.id] ?? {};
      for (const [kind, count, dg] of [
        ["commitments", s.registered, s.commitments_sha256],
        ["valid_tags", s.valid_tags, s.valid_tags_sha256],
      ] as const) {
        const items = lists.get(`${c.id}|${kind}`) ?? [];
        const sorted = items.every((x, i) => i === 0 || x > items[i - 1]);
        const okItems = kind === "commitments" || items.every((x) => {
          const v = fromHex(x);
          return v !== 1n && member(v);
        });
        if (!sorted || !okItems || items.length !== count || listDigest(items) !== dg) {
          rOk = false;
          notes.push(`${c.id}: ${kind} list does not match the summary`);
        }
        if (kind === "valid_tags") valid.set(c.id, new Set(items));
      }
    }
    add("registration.summary", "Registration summary and lists signed; registered <= eligible; one valid tag per registration not overridden in person; lists sorted, distinct, complete", rOk, notes.join("; "));

    // finalization
    let sigs = true;
    const items: Body[] = [];
    while (peek() && peek().type === "finalization") {
      const e = next("finalization");
      sigs &&= verifyBody(e.body, keys.board, "board");
      items.push(...(e.body.items as Body[]));
    }
    add("finalization.complete", "Every ballot has exactly one finalization item, in record order, signed by the ballot box", sigs && items.length === ballots.length, `${items.length} items for ${ballots.length} ballots`);
    const fjobs: FinalCheck[] = ballots.slice(0, items.length).map((e, i) => {
      const b = e.body.ballot as Record<string, Json>;
      return { seq: e.seq, cons: b.constituency as string, tc: e.body.tracking_code as string, votes: ((b.selections as Record<string, CtJ>[]) ?? []).map((s) => s.ciphertext), item: items[i] as Record<string, Json> };
    });
    const fok = await runner.finals(fjobs, ctx, (d) => opts.onProgress?.("Checking finalization proofs", d, fjobs.length));
    const fbad = fjobs.filter((_, i) => !fok[i]).map((j) => j.seq);
    add("finalization.proofs", "Each finalization proves: [flag 1 and masked vote = the ballot re-encrypted] or [flag 0 and masked vote = zero]", fbad.length === 0, fbad.length ? `invalid at seq ${fbad.slice(0, 5).join(", ")}` : "");

    // mixing, counted tags, tally
    const roles = new Map(tr.members.map((m) => [m.index, m]));
    const pubs = Object.fromEntries(tr.members.map((m) => [String(m.index), pubShare(m.index).toString(16)]));
    let mixOk = true;
    let tagOk = true;
    let tallyOk = true;
    let decOk = true;
    let resOk = true;
    const mnotes: string[] = [];
    const tnotes: string[] = [];
    for (const c of consList) {
      const idx = ballots.map((e, i) => [e, i] as const).filter(([e]) => (e.body.ballot as Record<string, Json>).constituency === c.id);
      const nC = idx.length;
      const jobs: MixCheck[] = [];
      for (let batch = 0; batch * mix.batch_size < nC; batch++) {
        const part = idx.slice(batch * mix.batch_size, (batch + 1) * mix.batch_size);
        const rows = part.map(([e, i]) => [((e.body.ballot as Record<string, Json>).tag as Record<string, CtJ>).ciphertext, (items[i]?.flag as CtJ) ?? { alpha: "1", beta: "1" }]);
        const shuffles: Body[] = [];
        const mixers: number[] = [];
        while (peek() && peek().type === "shuffle") {
          const sb = next("shuffle").body;
          const m = roles.get(sb.mixer as number);
          if (sb.constituency !== c.id || sb.batch !== batch || !m || mixers.includes(m.index) || !verifyBody(sb, m.public_key, m.role)) throw new StructureError(`shuffle entry out of place or wrongly signed (${c.id}/${batch})`);
          shuffles.push(sb);
          mixers.push(m.index);
        }
        if (mixers.length < mix.min_mixers) {
          mixOk = false;
          mnotes.push(`${c.id}/${batch}: ${mixers.length} mixers, ${mix.min_mixers} required`);
        }
        const shares = (kind: string) => {
          const got: Body[] = [];
          while (peek() && peek().type === kind) {
            const b = next(kind).body;
            const m = roles.get(b.index as number);
            if (b.constituency !== c.id || b.batch !== batch || !m || got.some((x) => x.index === m.index) || !verifyBody(b, m.public_key, m.role)) throw new StructureError(`${kind} entry out of place or wrongly signed (${c.id}/${batch})`);
            got.push(b);
          }
          return got;
        };
        const flags = shares("flag_shares");
        const tags = shares("tag_shares");
        jobs.push({ cons: c.id, batch, rows, shuffles, flags, tags, pubs, k });
      }
      const mres = await runner.mixes(jobs, ctx, (d) => opts.onProgress?.("Checking shuffles and decryptions", d, jobs.length));
      const counted: string[] = [];
      for (const r of mres) {
        if (r.problems.length) {
          mixOk = false;
          mnotes.push(...r.problems.slice(0, 3));
        }
        counted.push(...r.tags);
      }
      const vset = valid.get(c.id) ?? new Set();
      if (new Set(counted).size !== counted.length || !counted.every((t) => vset.has(t))) {
        tagOk = false;
        tnotes.push(`${c.id}: counted tags are repeated or not registered and valid`);
      }
      const nFinal = counted.length;
      const ag = next("aggregate").body;
      if (ag.constituency !== c.id || !verifyBody(ag, keys.officer, "officer")) throw new StructureError(`aggregate for ${c.id} missing or unsigned`);
      const opts2 = options[c.id];
      const aggs: Record<string, C2> = {};
      opts2.forEach((oid, j) => {
        let A = 1n;
        let B = 1n;
        for (const [, i] of idx) {
          const m = (items[i]?.masked as CtJ[] | undefined)?.[j];
          if (!m) continue;
          A = (A * fromHex(m.alpha)) % P;
          B = (B * fromHex(m.beta)) % P;
        }
        aggs[oid] = [A, B];
      });
      const posted = ag.aggregates as { option_id: string; ciphertext: CtJ }[];
      if (ag.ballot_count !== nC || ag.final_count !== nFinal || posted.length !== opts2.length || posted.some((x) => !aggs[x.option_id] || fromHex(x.ciphertext.alpha) !== aggs[x.option_id][0] || fromHex(x.ciphertext.beta) !== aggs[x.option_id][1])) {
        tallyOk = false;
        tnotes.push(`${c.id}: aggregate or counts do not match the record`);
      }
      const got: Record<string, Map<number, bigint>> = Object.fromEntries(opts2.map((o) => [o, new Map()]));
      const providers: number[] = [];
      while (peek() && peek().type === "decryption_shares") {
        const b = next("decryption_shares").body;
        const i = b.index as number;
        const m = roles.get(i);
        if (b.constituency !== c.id || !m || providers.includes(i) || !verifyBody(b, m.public_key, m.role)) throw new StructureError(`bad decryption share entry for ${c.id}`);
        providers.push(i);
        const Ki = fromHex(pubs[String(i)]);
        for (const x of b.shares as { option_id: string; share: string; proof: { a: string; b: string; v: string } }[]) {
          const M = fromHex(x.share);
          if (!aggs[x.option_id] || !cpOk(aggs[x.option_id][0], Ki, M, fromHex(x.proof.a), fromHex(x.proof.b), fromHex(x.proof.v), "decryption-share", [mh, "decrypt-aggregate", c.id, x.option_id])) {
            decOk = false;
            tnotes.push(`${c.id}/${x.option_id}: invalid share from trustee ${i}`);
          }
          got[x.option_id]?.set(i, M);
        }
      }
      const res = next("result").body;
      if (providers.length < k) {
        decOk = false;
        tnotes.push(`${c.id}: only ${providers.length} shares, threshold ${k}`);
      }
      if (!verifyBody(res, keys.officer, "officer") || res.constituency !== c.id || [...(res.quorum as number[])].sort().join() !== [...providers].sort().join())
        throw new StructureError(`result for ${c.id} unsigned or quorum mismatch`);
      const counts: Record<string, number | null> = {};
      for (const oid of opts2) counts[oid] = bsgs(combine(aggs[oid][1], got[oid]), nFinal);
      const postedCounts = Object.fromEntries((res.counts as { option_id: string; votes: number }[]).map((x) => [x.option_id, x.votes]));
      const total = Object.values(postedCounts).reduce((a, b) => a + b, 0);
      if (Object.values(counts).some((v) => v === null) || canonicalJson(counts as Json) !== canonicalJson(postedCounts) || total !== nFinal) {
        resOk = false;
        tnotes.push(`${c.id}: decrypted counts differ from published counts`);
      }
      const dec = decide(postedCounts);
      if (canonicalJson({ winner: res.winner, tied: res.tied, nota_exceeds_winner: res.nota_exceeds_winner } as Json) !== canonicalJson(dec as Json) || res.ballot_count !== nC || res.final_count !== nFinal) {
        resOk = false;
        tnotes.push(`${c.id}: winner/tie flags or counts do not follow the published rule`);
      }
      results[c.id] = {
        ...(results[c.id] as object),
        name: c.name,
        counts: postedCounts,
        ballots: nFinal,
        ballots_cast: nC,
        superseded_or_revoked: nC - nFinal,
        quorum: providers,
        options: Object.fromEntries(c.options.map((o) => [o.id, o.name])),
        ...dec,
      } as Json;
    }
    add("mixing.shuffles", `Each batch was shuffled by at least ${mix.min_mixers} trustees with valid proofs, and every flag and tag decryption is proven`, mixOk, mnotes.slice(0, 6).join("; "));
    add("mixing.counted_tags", "Counted ballots carry distinct tags, each a registered tag not overridden in person (at most one counted ballot per voter)", tagOk, tnotes.filter((n) => n.includes("tags")).join("; "));
    add("tally.aggregates", "Encrypted per-option totals equal the product of the finalized (masked) votes", tallyOk, tnotes.filter((n) => n.includes("aggregate")).join("; "));
    add("tally.decryption", `At least ${k} trustees decrypted each total with valid proofs`, decOk);
    add("tally.results", "Published counts equal the verified decryption, sum to the counted ballots, and follow the FPTP/NOTA rule", resOk, tnotes.filter((n) => n.includes("decrypted") || n.includes("rule")).join("; "));
    lifecycle("TALLIED");
    lifecycle("PUBLISHED");
    if (pos < entries.length) throw new StructureError("entries after PUBLISHED");
    add("record.structure", "Record follows the required entry sequence", true);
  }
}

/** A voter's check that their tracking code is inside a signed checkpoint. */
export function verifyReceipt(entriesText: string, checkpointsText: string, r: { tracking_code: string; seq: number; tree_size: number; root: string; inclusion_path: string[] }): boolean {
  const lines = entriesText.split("\n").filter(Boolean);
  if (r.seq >= lines.length) return false;
  const e = JSON.parse(lines[r.seq]);
  if (e.type !== "ballot" || e.body.tracking_code !== r.tracking_code) return false;
  const boardKey = JSON.parse(lines[0]).body.manifest.keys.board as string;
  return checkpointsText
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Body)
    .some((cp) => cp.tree_size === r.tree_size && cp.root === r.root && verifyBody(cp, boardKey, "board") && verifyInclusion(leafHash(enc.encode(lines[r.seq])), r.seq, r.tree_size, r.inclusion_path.map(hexToBytes), hexToBytes(r.root)));
}
