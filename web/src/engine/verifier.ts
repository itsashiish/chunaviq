// Independent verifier for ChunavIQ records, in TypeScript.
// Port of src/chunaviq_verify/verifier.py. Independence rule: this module does not import the
// election engine (crypto.ts, ballot.ts, election.ts); it re-implements every check from the spec
// and shares only byte-level helpers (big integers, canonical JSON, SHA-256, Ed25519, Merkle).
import { bytesToHex, fromHex, hexToBytes, modinv, modpow } from "./bigint";
import { canonicalJson, hashToScalar, sha256Hex, type HashItem, type Json } from "./encoding";
import { leafHash, rootsAt, verifyConsistency, verifyInclusion } from "./merkle";
import { G as GG, GROUP_NAME, P as PP, Q as QQ } from "./params";
import { verifyBody, type Body } from "./sign";
import { sha256 } from "@noble/hashes/sha2.js";

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
const keysAre = (o: unknown, keys: string[]) => !!o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).length === keys.length && keys.every((k) => k in (o as object));
const enc = new TextEncoder();

export type VerifyCtx = { K: string; mh: string; eid: string; options: Record<string, string[]>; issuers: Record<string, { n: string; e: string }> };

function cpOk(H: bigint, X: bigint, Y: bigint, a: bigint, b: bigint, v: bigint, domain: string, ctx: HashItem[]) {
  if (!(member(H) && member(X) && member(Y) && rng(a, b) && sc(v))) return false;
  const c = hashToScalar(Q, domain, ctx, H, X, Y, a, b);
  return pw(G, v) === (a * pw(X, c)) % P && pw(H, v) === (b * pw(Y, c)) % P;
}

function fdhOk(n: bigint, e: bigint, msg: Uint8Array, sig: bigint) {
  if (sig <= 0n || sig >= n) return false;
  const k = Math.ceil(n.toString(2).length / 8);
  const seed = new Uint8Array([...enc.encode("chunaviq/v1/credential-fdh\u0000"), ...msg]);
  const out: number[] = [];
  for (let c = 0; out.length < k - 1; c++) out.push(...sha256(new Uint8Array([...seed, (c >>> 24) & 255, (c >>> 16) & 255, (c >>> 8) & 255, c & 255])));
  return modpow(sig, e, n) === BigInt("0x" + bytesToHex(new Uint8Array(out.slice(0, k - 1))));
}

/** Verify one ballot; returns a rejection code or null. Pure: safe to run in a worker. */
export function verifyBallot(b: Record<string, Json>, c: VerifyCtx): string | null {
  try {
    const K = fromHex(c.K);
    if (!keysAre(b, ["election_id", "constituency", "credential", "selections", "limit_proof"])) return "MALFORMED";
    if (b.election_id !== c.eid) return "WRONG_ELECTION";
    const cons = b.constituency as string;
    if (!(cons in c.options)) return "UNKNOWN_CONSTITUENCY";
    const cred = b.credential as Record<string, string>;
    if (!keysAre(cred, ["token", "signature"]) || typeof cred.token !== "string" || cred.token.length !== 64 || bytesToHex(hexToBytes(cred.token)) !== cred.token) return "MALFORMED";
    const msg = new Uint8Array([...enc.encode(c.eid), 0, ...enc.encode(cons), 0, ...hexToBytes(cred.token)]);
    if (!fdhOk(fromHex(c.issuers[cons].n), fromHex(c.issuers[cons].e), msg, fromHex(cred.signature))) return "BAD_CREDENTIAL";
    const sels = b.selections as Record<string, Json>[];
    if (!Array.isArray(sels) || sels.map((s) => s?.option_id).join("\u0000") !== c.options[cons].join("\u0000")) return "WRONG_BALLOT_STYLE";
    let A = 1n;
    let B = 1n;
    for (const s of sels) {
      const ct = s.ciphertext as Record<string, string>;
      const pr = s.proof as Record<string, string>;
      if (!keysAre(s, ["option_id", "ciphertext", "proof"]) || !keysAre(ct, ["alpha", "beta"]) || !keysAre(pr, ["a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1"])) return "MALFORMED";
      const al = fromHex(ct.alpha);
      const be = fromHex(ct.beta);
      const [a0, b0, a1, b1, c0, c1, v0, v1] = ["a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1"].map((k) => fromHex(pr[k]));
      if (!(member(al) && member(be) && rng(a0, b0, a1, b1) && sc(c0, c1, v0, v1))) return "BAD_SELECTION_PROOF";
      const ctx: HashItem[] = [c.mh, "selection", cons, s.option_id as string, cred.token];
      if ((c0 + c1) % Q !== hashToScalar(Q, "selection-0or1", ctx, K, al, be, a0, b0, a1, b1)) return "BAD_SELECTION_PROOF";
      const bg = (be * modinv(G, P)) % P;
      const ok =
        pw(G, v0) === (a0 * pw(al, c0)) % P && pw(K, v0) === (b0 * pw(be, c0)) % P && pw(G, v1) === (a1 * pw(al, c1)) % P && pw(K, v1) === (b1 * pw(bg, c1)) % P;
      if (!ok) return "BAD_SELECTION_PROOF";
      A = (A * al) % P;
      B = (B * be) % P;
    }
    const lp = b.limit_proof as Record<string, string>;
    if (!keysAre(lp, ["a", "b", "v"])) return "MALFORMED";
    const Y = (B * modinv(G, P)) % P;
    if (!cpOk(K, A, Y, fromHex(lp.a), fromHex(lp.b), fromHex(lp.v), "contest-limit", [c.mh, "contest-limit", cons, cred.token])) return "BAD_LIMIT_PROOF";
    return null;
  } catch {
    return "MALFORMED";
  }
}

export type BallotChecker = (ballots: Record<string, Json>[], ctx: VerifyCtx, onProgress?: (done: number) => void) => Promise<(string | null)[]>;

export const inlineChecker: BallotChecker = async (ballots, ctx, onProgress) => {
  const out: (string | null)[] = [];
  for (const b of ballots) {
    out.push(verifyBallot(b, ctx));
    onProgress?.(out.length);
  }
  return out;
};

class StructureError extends Error {}

const lagrange0 = (idx: number[], i: number) => {
  let num = 1n;
  let den = 1n;
  for (const m of idx) if (m !== i) {
    num = (num * BigInt(m)) % Q;
    den = (((den * BigInt(m - i)) % Q) + Q) % Q;
  }
  return (num * modinv(den, Q)) % Q;
};

function decide(counts: Record<string, number>) {
  const c = Object.entries(counts).filter(([k]) => k !== "NOTA");
  const top = c.length ? Math.max(...c.map(([, v]) => v)) : 0;
  const lead = c.filter(([, v]) => v === top).map(([k]) => k).sort();
  return { winner: lead.length === 1 ? lead[0] : null, tied: lead.length > 1 ? lead : [], nota_exceeds_winner: (counts.NOTA ?? 0) > top };
}

const hourFloor = (s: string) => new Date(s).toISOString().slice(0, 13);

export async function verifyRecord(entriesText: string, checkpointsText: string, opts: { expectManifestHash?: string; checker?: BallotChecker; onProgress?: (label: string, done: number, total: number) => void } = {}): Promise<Report> {
  const checks: Check[] = [];
  const results: Record<string, Json> = {};
  const facts: Record<string, Json> = {};
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
    add("manifest.hash", "Manifest hash matches manifest content", mh === mb.manifest_hash, mh);
    add("manifest.signature", "Manifest signed by the election officer key it declares", verifyBody(mb, keys.officer, "officer"));
    if (opts.expectManifestHash) add("manifest.pinned", "Manifest hash equals the independently obtained value", opts.expectManifestHash === mh);
    else add("manifest.pinned", "Manifest hash pinned to an out-of-band value", null, "Not pinned: this record is self-consistent; its authenticity rests on where you got it.");
    const eid = man.election_id as string;
    Object.assign(facts, { election_id: eid, title: man.title, manifest_hash: mh, notice: man.notice, window: man.window, software: man.software });
    if (man.group !== GROUP_NAME) {
      add("group.approved", "Election group is an approved parameter set", false, String(man.group));
      return;
    }
    add("group.approved", "Election group is an approved parameter set", true, GROUP_NAME);
    add("group.sanity", "Group generator has order q", G !== 1n && modpow(G, Q, P) === 1n && (P - 1n) % Q === 0n);

    const cps = checkpointsText.split("\n").filter(Boolean).map((l) => JSON.parse(l) as Body);
    const leaves = lines.map((l) => leafHash(enc.encode(l)));
    const roots = rootsAt(leaves, new Set(cps.map((c) => c.tree_size as number)));
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
    const next = (type: string, state?: string) => {
      const e = entries[pos++];
      if (!e) throw new StructureError(`record ends early; expected ${type}${state ? " " + state : ""}`);
      if (e.type !== type || (state && e.body.state !== state)) throw new StructureError(`entry ${e.seq}: expected ${type}${state ? " " + state : ""}, got ${e.type}`);
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
        const ch = hashToScalar(Q, "schnorr", [mh, "trustee-coefficient", String(m.index), String(j)], C, h);
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

    const ik = next("issuer_keys").body;
    const consList = man.constituencies as { id: string; name: string; eligible_voters: number; options: { id: string; name: string }[] }[];
    const issuers = ik.issuer_keys as Record<string, { n: string; e: string }>;
    const consIds = consList.map((c) => c.id).sort();
    add("credentials.issuer_keys", "Credential issuer keys signed by the eligibility authority, one per constituency",
      verifyBody(ik, keys.eligibility, "eligibility") && Object.keys(issuers).sort().join() === consIds.join() && Object.values(issuers).every((v) => fromHex(v.e) === 65537n));
    const weak = Object.values(issuers).filter((v) => fromHex(v.n).toString(2).length < 3072).length;
    if (weak) add("credentials.key_size", "Issuer RSA moduli are at least 3072 bits", null, `${weak} below 3072 bits`);
    lifecycle("READY");
    const openE = lifecycle("OPEN");

    const ballots: typeof entries = [];
    let closeE: (typeof entries)[number];
    for (;;) {
      const e = entries[pos++];
      if (!e) throw new StructureError("record ends before CLOSED");
      if (e.type === "ballot") {
        ballots.push(e);
        continue;
      }
      if (e.type !== "lifecycle" || e.body.state !== "CLOSED") throw new StructureError(`entry ${e.seq}: only ballots may appear between OPEN and CLOSED (got ${e.type})`);
      if (!verifyBody(e.body, keys.officer, "officer")) throw new StructureError("CLOSED not signed by officer");
      closeE = e;
      break;
    }
    const options = Object.fromEntries(consList.map((c) => [c.id, c.options.map((o) => o.id)]));
    const ctx: VerifyCtx = { K: K.toString(16), mh, eid, options, issuers };
    const bodies = ballots.map((b) => b.body.ballot as Record<string, Json>);
    const codes = await (opts.checker ?? inlineChecker)(bodies, ctx, (d) => opts.onProgress?.("Checking ballot proofs", d, bodies.length));
    const bad = codes.map((c, i) => [ballots[i].seq, c] as const).filter(([, c]) => c);
    add("ballots.valid", "Every ballot carries a valid credential, ciphertexts and proofs (exactly one selection)", bad.length === 0,
      `${bodies.length} checked` + (bad.length ? `; invalid: ${bad.slice(0, 5).map(([s, c]) => `#${s} ${c}`).join(", ")}` : ""));
    const toks = new Map<string, number>();
    const alph = new Map<string, number>();
    for (const b of bodies) {
      const t = (b.credential as Record<string, string>).token;
      toks.set(t, (toks.get(t) ?? 0) + 1);
      for (const s of b.selections as Record<string, Record<string, string>>[]) alph.set(s.ciphertext.alpha, (alph.get(s.ciphertext.alpha) ?? 0) + 1);
    }
    add("ballots.one_per_credential", "No credential used twice", [...toks.values()].every((v) => v === 1), `${[...toks.values()].filter((v) => v > 1).length} reused`);
    add("ballots.no_copies", "No ciphertext appears twice (ballot-copying defence)", [...alph.values()].every((v) => v === 1));
    add("ballots.tracking_codes", "Tracking codes equal the hash of each ballot", ballots.every((e) => e.body.tracking_code === sha256Hex(enc.encode(canonicalJson(e.body.ballot)))));
    const win = man.window as { opens_at: string; closes_at: string };
    const w0 = hourFloor(win.opens_at);
    const w1 = hourFloor(win.closes_at);
    add("ballots.window", "Ballots were recorded inside the published voting window (hour resolution)", ballots.every((e) => e.time_bucket >= w0 && e.time_bucket <= w1));
    add("lifecycle.open_time", "Election opened no earlier than the published opening hour", openE.time_bucket >= w0);
    const cb = closeE!.body;
    add("lifecycle.close_count", "CLOSED entry states the number of ballots actually recorded", cb.ballots_accepted === ballots.length, `${cb.ballots_accepted} vs ${ballots.length}`);
    if ("early_close_reason" in cb) add("lifecycle.early_close", "Polls closed at the published time", null, `EARLY CLOSE: ${cb.early_close_reason}`);
    facts.rejections_by_reason = (cb.rejections_by_reason as Json) ?? {};

    const ps = next("participation_summary").body;
    const perCons = new Map<string, number>();
    for (const b of bodies) perCons.set(b.constituency as string, (perCons.get(b.constituency as string) ?? 0) + 1);
    let pOk = verifyBody(ps, keys.eligibility, "eligibility");
    const notes: string[] = [];
    for (const c of consList) {
      const s = (ps.constituencies as Record<string, { eligible: number; credentials_issued: number; commitments: string[] }>)[c.id];
      if (!s) {
        pOk = false;
        notes.push(`${c.id}: missing`);
        continue;
      }
      const cm = s.commitments;
      const conds = [s.eligible === c.eligible_voters, s.credentials_issued <= s.eligible, (perCons.get(c.id) ?? 0) <= s.credentials_issued, cm.length === s.credentials_issued, new Set(cm).size === cm.length, cm.join() === [...cm].sort().join()];
      if (!conds.every(Boolean)) {
        pOk = false;
        notes.push(`${c.id}: ${conds}`);
      }
      results[c.id] = { eligible: s.eligible, credentials_issued: s.credentials_issued };
    }
    add("reconciliation.participation", "ballots <= credentials issued <= eligible voters, per constituency", pOk, notes.join("; "));

    let tallyOk = true;
    let decOk = true;
    let resOk = true;
    const tnotes: string[] = [];
    const roles = new Map(tr.members.map((m) => [m.index, m]));
    for (const c of consList) {
      const opts2 = options[c.id];
      const mine = bodies.filter((b) => b.constituency === c.id);
      const ag = next("aggregate").body;
      if (ag.constituency !== c.id || !verifyBody(ag, keys.officer, "officer")) throw new StructureError(`aggregate for ${c.id} missing or unsigned`);
      const aggs: Record<string, [bigint, bigint]> = {};
      opts2.forEach((oid, j) => {
        let A = 1n;
        let B = 1n;
        for (const b of mine) {
          const ct = (b.selections as Record<string, Record<string, string>>[])[j].ciphertext;
          A = (A * fromHex(ct.alpha)) % P;
          B = (B * fromHex(ct.beta)) % P;
        }
        aggs[oid] = [A, B];
      });
      const posted = ag.aggregates as { option_id: string; ciphertext: { alpha: string; beta: string } }[];
      if (ag.ballot_count !== mine.length || posted.length !== opts2.length || posted.some((x) => !aggs[x.option_id] || fromHex(x.ciphertext.alpha) !== aggs[x.option_id][0] || fromHex(x.ciphertext.beta) !== aggs[x.option_id][1])) {
        tallyOk = false;
        tnotes.push(`${c.id}: aggregate mismatch`);
      }
      const got: Record<string, Map<number, bigint>> = Object.fromEntries(opts2.map((o) => [o, new Map()]));
      const providers: number[] = [];
      let res: Body;
      for (;;) {
        const e = entries[pos++];
        if (!e) throw new StructureError(`record ends inside tally of ${c.id}`);
        if (e.type === "decryption_shares") {
          const b = e.body;
          const i = b.index as number;
          const m = roles.get(i);
          if (b.constituency !== c.id || !m || providers.includes(i) || !verifyBody(b, m.public_key, m.role)) throw new StructureError(`bad decryption share entry ${e.seq}`);
          providers.push(i);
          const Ki = pubShare(i);
          for (const x of b.shares as { option_id: string; share: string; proof: { a: string; b: string; v: string } }[]) {
            const M = fromHex(x.share);
            if (!aggs[x.option_id] || !cpOk(aggs[x.option_id][0], Ki, M, fromHex(x.proof.a), fromHex(x.proof.b), fromHex(x.proof.v), "decryption-share", [mh, "decrypt-aggregate", c.id, x.option_id])) {
              decOk = false;
              tnotes.push(`${c.id}/${x.option_id}: invalid share from trustee ${i}`);
            }
            got[x.option_id]?.set(i, M);
          }
          continue;
        }
        if (e.type !== "result") throw new StructureError(`entry ${e.seq}: expected decryption_shares or result`);
        res = e.body;
        break;
      }
      if (providers.length < k) {
        decOk = false;
        tnotes.push(`${c.id}: only ${providers.length} shares, threshold ${k}`);
      }
      if (!verifyBody(res, keys.officer, "officer") || res.constituency !== c.id || [...(res.quorum as number[])].sort().join() !== [...providers].sort().join())
        throw new StructureError(`result for ${c.id} unsigned or quorum mismatch`);
      const counts: Record<string, number | null> = {};
      for (const oid of opts2) {
        const [, B] = aggs[oid];
        let s = 1n;
        for (const i of providers) s = (s * pw(got[oid].get(i) ?? 1n, lagrange0(providers, i))) % P;
        const gm = (B * modinv(s, P)) % P;
        let acc = 1n;
        counts[oid] = null;
        for (let t = 0; t <= mine.length; t++) {
          if (acc === gm) {
            counts[oid] = t;
            break;
          }
          acc = (acc * G) % P;
        }
      }
      const postedCounts = Object.fromEntries((res.counts as { option_id: string; votes: number }[]).map((x) => [x.option_id, x.votes]));
      const total = Object.values(postedCounts).reduce((a, b) => a + b, 0);
      if (Object.values(counts).some((v) => v === null) || canonicalJson(counts as Json) !== canonicalJson(postedCounts) || total !== mine.length) {
        resOk = false;
        tnotes.push(`${c.id}: decrypted counts differ from published counts`);
      }
      const dec = decide(postedCounts);
      if (canonicalJson({ winner: res.winner, tied: res.tied, nota_exceeds_winner: res.nota_exceeds_winner } as Json) !== canonicalJson(dec as Json) || res.ballot_count !== mine.length) {
        resOk = false;
        tnotes.push(`${c.id}: winner/tie flags do not follow the published rule`);
      }
      results[c.id] = { ...(results[c.id] as object), name: c.name, counts: postedCounts, ballots: mine.length, quorum: providers, options: Object.fromEntries(c.options.map((o) => [o.id, o.name])), ...dec } as Json;
    }
    add("tally.aggregates", "Encrypted per-option totals equal the product of all accepted ballots", tallyOk, tnotes.join("; "));
    add("tally.decryption", `At least ${k} trustees decrypted each total with valid proofs`, decOk);
    add("tally.results", "Published counts equal the verified decryption and follow the FPTP/NOTA rule", resOk);
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
