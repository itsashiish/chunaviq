// A complete demo election in the browser (protocol v2): identity checks (synthetic Aadhaar / PAN),
// tag registration, voting and revoting, polling-day override, finalization, mixing by three
// trustees, decryption and tally. Every role keeps its own keys; the record format is identical to
// the Python implementation, so `chunaviq verify` accepts records produced here and vice versa.
import { bytesToHex, fromHex, hexToBytes, randomBytes, toHex } from "./bigint";
import { checkLink, encryptBallot, makeLink, precheck, Rejected, trackingCode, type Ballot, type BoxCtx, type Prepared, type Submission } from "./ballot";
import {
  addCts,
  combineShares,
  cpToJson,
  ctFromJson,
  ctToJson,
  dlogBounded,
  dvBranches,
  fastFor,
  finalizeBranches,
  G,
  gPow,
  P,
  publicShare,
  PublicKey,
  rand,
  rowsFromJson,
  rowsToJson,
  schnorrProve,
  schnorrVerify,
  shuffleAndProve,
  sigmaProveOr,
  sigmaVerifyOr,
  Trustee,
  coefficientContext,
  evalCommitments,
  type Ct,
  type OrProof,
  type Row,
  type ShuffleProof,
  type TrusteeCommitment,
} from "./crypto";
import { canonicalBytes, canonicalJson, sha256Hex, type Json } from "./encoding";
import { MerkleTree } from "./merkle";
import { RoleKey, type Body } from "./sign";
import { shuffleOk } from "./verifier";

export const LIFECYCLE = ["DRAFT", "KEY_CEREMONY", "READY", "OPEN", "CLOSED", "TALLIED", "PUBLISHED"] as const;
export const NOTA = "NOTA";
export const CONSTITUENCY = "SYN-AC-01";
export const MIX_BATCH = 48; // a real election uses 2048 per batch; small batches let the browser mix in parallel
export const MIXERS = 3;
export const MAX_PER_TAG = 30;
export const FINALIZE_CHUNK = 128;

export const OPTIONS = [
  { id: "C1", name: "Aarav Synthetic", party: "Circle Party (synthetic)", symbol: "circle" },
  { id: "C2", name: "Meera Placeholder", party: "Triangle Front (synthetic)", symbol: "triangle" },
  { id: "C3", name: "Kabir Example", party: "Square Alliance (synthetic)", symbol: "square" },
  { id: NOTA, name: "None of the Above", party: "-", symbol: "nota" },
] as const;

export const hourBucket = (d: Date) => d.toISOString().slice(0, 13);
export const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");

export type Entry = { seq: number; type: string; time_bucket: string; body: Body };

// ------------------------------------------------------------------ board
export class Board {
  entries: Entry[] = [];
  lines: string[] = [];
  checkpoints: Body[] = [];
  tree = new MerkleTree();
  state: (typeof LIFECYCLE)[number] = "DRAFT";
  listeners = new Set<() => void>();
  constructor(public electionId: string, public operator: RoleKey, private now: () => Date) {}

  append(type: string, body: Body): Entry {
    if (type === "lifecycle") {
      const next = body.state as (typeof LIFECYCLE)[number];
      if (LIFECYCLE.indexOf(next) !== LIFECYCLE.indexOf(this.state) + 1) throw new Error(`illegal lifecycle transition ${this.state} -> ${next}`);
    }
    const entry: Entry = { seq: this.entries.length, type, time_bucket: hourBucket(this.now()), body };
    const line = canonicalJson(entry as unknown as Json);
    this.entries.push(entry);
    this.lines.push(line);
    this.tree.append(new TextEncoder().encode(line));
    if (type === "lifecycle") this.state = body.state as (typeof LIFECYCLE)[number];
    this.listeners.forEach((f) => f());
    return entry;
  }

  checkpoint(): Body {
    const size = this.tree.size;
    const prev = this.checkpoints[this.checkpoints.length - 1];
    if (prev && prev.tree_size === size) return prev;
    const proof = prev && (prev.tree_size as number) > 0 ? this.tree.consistencyProof(prev.tree_size as number).map(bytesToHex) : [];
    const cp = this.operator.signBody({
      election_id: this.electionId,
      tree_size: size,
      root: bytesToHex(this.tree.root()),
      time_bucket: hourBucket(this.now()),
      prev_tree_size: prev ? (prev.tree_size as number) : 0,
      consistency_proof: proof,
    });
    this.checkpoints.push(cp);
    this.listeners.forEach((f) => f());
    return cp;
  }

  receipt(seq: number) {
    const cp = this.checkpoint();
    return {
      tracking_code: this.entries[seq].body.tracking_code as string,
      seq,
      entry_sha256: sha256Hex(new TextEncoder().encode(this.lines[seq])),
      tree_size: cp.tree_size as number,
      root: cp.root as string,
      inclusion_path: this.tree.inclusionProof(seq).map(bytesToHex),
    };
  }

  of(type: string) {
    return this.entries.filter((e) => e.type === type);
  }

  export() {
    return { entries: this.lines.map((l) => l + "\n").join(""), checkpoints: this.checkpoints.map((c) => canonicalJson(c) + "\n").join("") };
  }
}

// ------------------------------------------------------------------ synthetic identity services
export type Person = { voterId: string; constituency: string; aadhaarRef: string; panRef: string | null; mobileRef: string; face: Uint8Array; name: string; dob: string };

export class SyntheticPhone {
  inbox = new Map<string, string[]>();
  deliver(mobile: string, text: string) {
    this.inbox.set(mobile, [...(this.inbox.get(mobile) ?? []), text]);
  }
  last(mobile: string): string {
    const m = this.inbox.get(mobile);
    if (!m?.length) throw new Error("no message");
    return m[m.length - 1];
  }
}

/** Synthetic camera: a genuine capture differs from the roll photograph in a few bits. */
export function liveCapture(face: Uint8Array, genuine = true): Uint8Array {
  if (!genuine) return randomBytes(face.length);
  const out = new Uint8Array(face);
  for (let i = 0; i < 4; i++) {
    const b = randomBytes(1)[0] % (out.length * 8);
    out[b >> 3] ^= 1 << (b & 7);
  }
  return out;
}
export function faceMatch(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let same = 0;
  for (let i = 0; i < a.length; i++) {
    let x = a[i] ^ b[i];
    let ones = 0;
    while (x) {
      ones += x & 1;
      x >>= 1;
    }
    same += 8 - ones;
  }
  return same >= 240;
}

const otp = () => String(Number(BigInt("0x" + bytesToHex(randomBytes(4))) % 1000000n)).padStart(6, "0");

/** SHA-256 preimage of a participation commitment (src/chunaviq/election/eligibility.py). */
export function participationPreimage(eid: string, voterId: string, salt: Uint8Array): Uint8Array {
  const head = new TextEncoder().encode(`chunaviq/v1/participation\u0000${eid}\u0000${voterId}\u0000`);
  const out = new Uint8Array(head.length + salt.length);
  out.set(head);
  out.set(salt, head.length);
  return out;
}
export const listDigest = (items: string[]) => sha256Hex(new TextEncoder().encode(items.map((x) => x + "\n").join("")));
export const registerContext = (eid: string, cons: string, session: string) => [eid, "register", cons, session];

type Registration = { tag: string; commitment: string; salt: Uint8Array; generation: number; inPerson: boolean };

export class EligibilityAuthority {
  key = new RoleKey("eligibility");
  accepting = false;
  people = new Map<string, Person>();
  private byAadhaar = new Map<string, string>();
  private byPan = new Map<string, string>();
  private failures = new Map<string, number>();
  private sessions = new Map<string, string>();
  private txns = new Map<string, { voterId: string; code: string; tries: number }>();
  registrations = new Map<string, Registration>();
  tags = new Map<string, string>();
  constructor(public electionId: string, public phone: SyntheticPhone) {}

  enrol(p: Person) {
    this.people.set(p.voterId, p);
    this.byAadhaar.set(p.aadhaarRef, p.voterId);
    if (p.panRef) this.byPan.set(p.panRef, p.voterId);
  }
  private locked(id: string) {
    if ((this.failures.get(id) ?? 0) >= 5) throw new Rejected("LOCKED");
  }
  private fail(id: string, code: string): never {
    this.failures.set(id, (this.failures.get(id) ?? 0) + 1);
    throw new Rejected(code);
  }
  private session(voterId: string) {
    const s = bytesToHex(randomBytes(16));
    this.sessions.set(s, voterId);
    return s;
  }
  aadhaarOtpStart(ref: string): string {
    this.locked("a:" + ref);
    const v = this.byAadhaar.get(ref);
    if (!v) throw new Rejected("AADHAAR_NOT_FOUND");
    const txn = bytesToHex(randomBytes(8));
    const code = otp();
    this.txns.set(txn, { voterId: v, code, tries: 0 });
    this.phone.deliver(this.people.get(v)!.mobileRef, code);
    return txn;
  }
  aadhaarOtpFinish(ref: string, txn: string, code: string): string {
    this.locked("a:" + ref);
    const t = this.txns.get(txn);
    if (!t || ++t.tries > 3) throw new Rejected("OTP_EXPIRED");
    if (t.code !== code) this.fail("a:" + ref, "OTP_MISMATCH");
    this.txns.delete(txn);
    return this.session(t.voterId);
  }
  aadhaarFace(ref: string, capture: Uint8Array): string {
    this.locked("a:" + ref);
    const v = this.byAadhaar.get(ref);
    if (!v) throw new Rejected("AADHAAR_NOT_FOUND");
    if (!faceMatch(this.people.get(v)!.face, capture)) this.fail("a:" + ref, "FACE_MISMATCH");
    return this.session(v);
  }
  /** PAN check (number + name + birth date), then an OTP to the mobile number on the electoral roll. */
  panStart(ref: string, name: string, dob: string): string {
    this.locked("p:" + ref);
    const v = this.byPan.get(ref);
    const p = v ? this.people.get(v) : undefined;
    if (!p || p.name !== name || p.dob !== dob) this.fail("p:" + ref, "PAN_MISMATCH");
    const txn = bytesToHex(randomBytes(8));
    const code = otp();
    this.txns.set(txn, { voterId: v!, code, tries: 0 });
    this.phone.deliver(p.mobileRef, code);
    return txn;
  }
  /** PAN's second and third factors: the roll-mobile OTP AND a face match against the roll photograph. */
  panFinish(ref: string, txn: string, code: string, capture: Uint8Array): string {
    this.locked("p:" + ref);
    const t = this.txns.get(txn);
    if (!t || ++t.tries > 3) throw new Rejected("OTP_EXPIRED");
    if (t.code !== code) this.fail("p:" + ref, "OTP_MISMATCH");
    if (!faceMatch(this.people.get(t.voterId)!.face, capture)) this.fail("p:" + ref, "FACE_MISMATCH");
    this.txns.delete(txn);
    return this.session(t.voterId);
  }
  register(session: string, tagHex: string, proof: { h: bigint; v: bigint }) {
    if (!this.accepting) throw new Rejected("NOT_ACCEPTING");
    const voterId = this.sessions.get(session);
    if (!voterId) throw new Rejected("NO_SESSION");
    this.sessions.delete(session);
    const p = this.people.get(voterId)!;
    const T = fromHex(tagHex);
    if (T === 1n || !schnorrVerify(T, proof, registerContext(this.electionId, p.constituency, session))) throw new Rejected("BAD_TAG_PROOF");
    if (this.tags.has(tagHex)) throw new Rejected("TAG_REUSED");
    const prev = this.registrations.get(voterId);
    if (prev?.inPerson) throw new Rejected("VOTED_IN_PERSON");
    if (prev && prev.generation >= 6) throw new Rejected("TOO_MANY_REGISTRATIONS");
    this.tags.set(tagHex, p.constituency);
    let reg: Registration;
    if (prev) reg = { ...prev, tag: tagHex, generation: prev.generation + 1 };
    else {
      const salt = randomBytes(16);
      reg = { tag: tagHex, commitment: sha256Hex(participationPreimage(this.electionId, voterId, salt)), salt, generation: 1, inPerson: false };
    }
    this.registrations.set(voterId, reg);
    return { constituency: p.constituency, generation: reg.generation, commitment: reg.commitment, participation_salt: bytesToHex(reg.salt) };
  }
  markVotedInPerson(voterId: string): boolean {
    const r = this.registrations.get(voterId);
    if (!r || r.inPerson) return false;
    r.inPerson = true;
    return true;
  }
  knownTag(cons: string, tag: string) {
    return this.tags.get(tag) === cons;
  }
  validTags(cons: string): string[] {
    return [...this.registrations.entries()].filter(([v, r]) => this.people.get(v)!.constituency === cons && !r.inPerson).map(([, r]) => r.tag).sort();
  }
  registrationEntries(constituencies: string[], chunk = 4096): [string, Body][] {
    const summary: Record<string, Json> = {};
    const lists: [string, Body][] = [];
    for (const c of constituencies) {
      const regs = [...this.registrations.entries()].filter(([v]) => this.people.get(v)!.constituency === c).map(([, r]) => r);
      const commitments = regs.map((r) => r.commitment).sort();
      const valid = this.validTags(c);
      summary[c] = {
        eligible: [...this.people.values()].filter((p) => p.constituency === c).length,
        registered: regs.length,
        reregistrations: regs.reduce((s, r) => s + r.generation - 1, 0),
        voted_in_person: regs.filter((r) => r.inPerson).length,
        valid_tags: valid.length,
        commitments_sha256: listDigest(commitments),
        valid_tags_sha256: listDigest(valid),
      };
      for (const [kind, items] of [
        ["commitments", commitments],
        ["valid_tags", valid],
      ] as const)
        for (let i = 0; i < items.length; i += chunk) lists.push(["registration_list", this.key.signBody({ constituency: c, list: kind, index: i / chunk, items: items.slice(i, i + chunk) })]);
    }
    return [["registration_summary", this.key.signBody({ election_id: this.electionId, chunk_size: chunk, constituencies: summary })], ...lists];
  }
}

// ------------------------------------------------------------------ voter device
export type AuthMethod = "aadhaar-otp" | "aadhaar-face" | "pan";

export class VoterDevice {
  t?: bigint;
  T?: bigint;
  registration?: { constituency: string; generation: number; commitment: string; participation_salt: string };
  cast: string[] = [];
  lastOtp?: string;
  constructor(public person: Person, private e: DemoElection) {}
  get voterId() {
    return this.person.voterId;
  }
  get constituency() {
    return this.person.constituency;
  }
  authenticate(method: AuthMethod): string {
    const p = this.person;
    const el = this.e.elig;
    if (method === "aadhaar-otp") {
      const txn = el.aadhaarOtpStart(p.aadhaarRef);
      this.lastOtp = this.e.phone.last(p.mobileRef);
      return el.aadhaarOtpFinish(p.aadhaarRef, txn, this.lastOtp);
    }
    if (method === "aadhaar-face") return el.aadhaarFace(p.aadhaarRef, liveCapture(p.face));
    if (!p.panRef) throw new Error("no PAN");
    const txn = el.panStart(p.panRef, p.name, p.dob);
    this.lastOtp = this.e.phone.last(p.mobileRef);
    return el.panFinish(p.panRef, txn, this.lastOtp, liveCapture(p.face));
  }
  /** Verify identity and register a fresh tag. Again = re-registration: the old tag stops counting. */
  register(method: AuthMethod = "aadhaar-otp") {
    const session = this.authenticate(method);
    const t = rand();
    const T = gPow(t);
    this.registration = this.e.elig.register(session, toHex(T), schnorrProve(t, T, registerContext(this.e.electionId, this.constituency, session)));
    this.t = t;
    this.T = T;
    return this.registration;
  }
  prepare(choice: string): Prepared {
    if (this.t === undefined) throw new Error("not registered");
    return encryptBallot(this.e.pk!, this.e.mh, this.e.electionId, this.constituency, this.e.optionIds, choice, this.t);
  }
  submission(prep: Prepared): Submission {
    return { ballot: prep.ballot, tag: toHex(this.T!), link: makeLink(this.e.pk!, this.e.mh, prep, this.T!) };
  }
  /** Is my latest ballot the one that counts? Verifies the ballot box's designated-verifier proof. */
  checkCounted(flag: { alpha: string; beta: string }, proof: OrProof, tracking = this.cast[this.cast.length - 1]): boolean {
    return sigmaVerifyOr(dvBranches(this.e.pk!.K, ctFromJson(flag), this.T!), proof, "dv-final", [this.e.mh, "dv-final", tracking], fastFor(this.e.pk!));
  }
  /** With t, the voter can make an equally valid "proof" for ANY ballot: worthless as evidence to a coercer. */
  fakeCountedProof(flag: { alpha: string; beta: string }, tracking: string): OrProof {
    return sigmaProveOr(dvBranches(this.e.pk!.K, ctFromJson(flag), this.T!), 1, [this.t!], "dv-final", [this.e.mh, "dv-final", tracking], fastFor(this.e.pk!));
  }
}

// ------------------------------------------------------------------ heavy steps (run inline or in workers)
export type FinalJob = { seq: number; tc: string; cons: string; votes: { alpha: string; beta: string }[]; f: 0 | 1 };
export type FinalOut = { item: Body; u: string | null };
export type MixJob = { cons: string; batch: number; rows: { alpha: string; beta: string }[][]; mixers: number[] };
export type MixOut = { outs: { alpha: string; beta: string }[][][]; proofs: ShuffleProof[]; verified: boolean };

export function finalizeOne(pk: PublicKey, mh: string, j: FinalJob): FinalOut {
  const votes = j.votes.map(ctFromJson);
  const u = rand();
  const F: Ct = { alpha: gPow(u), beta: (gPow(BigInt(j.f)) * pk.kPow(u)) % P };
  const ws = votes.map(() => rand());
  const masked = votes.map((v, i) =>
    j.f ? { alpha: (v.alpha * gPow(ws[i])) % P, beta: (v.beta * pk.kPow(ws[i])) % P } : { alpha: gPow(ws[i]), beta: pk.kPow(ws[i]) },
  );
  const proof = sigmaProveOr(finalizeBranches(pk.K, F, votes, masked), j.f, [u, ...ws], "finalize", [mh, "finalize", j.cons, j.tc], fastFor(pk));
  return { item: { seq: j.seq, tracking_code: j.tc, flag: ctToJson(F), masked: masked.map(ctToJson), proof: proof as unknown as Json }, u: j.f ? toHex(u) : null };
}

/** One batch through every mixer in turn, then the observers' re-verification (with the independent verifier's code). */
export function mixBatch(pk: PublicKey, mh: string, j: MixJob): MixOut {
  let cur: Row[] = rowsFromJson(j.rows);
  const outs: Row[][] = [];
  const proofs: ShuffleProof[] = [];
  for (const m of j.mixers) {
    const { out, proof } = shuffleAndProve(pk, cur, [mh, "mix", j.cons, String(j.batch), String(m)]);
    outs.push(out);
    proofs.push(proof);
    cur = out;
  }
  const chain = [rowsFromJson(j.rows), ...outs];
  const verified = j.mixers.every((m, i) => shuffleOk(pk.K, chain[i], chain[i + 1], proofs[i] as unknown as Record<string, Json>, [mh, "mix", j.cons, String(j.batch), String(m)]));
  return { outs: outs.map(rowsToJson), proofs, verified };
}

export type Runner = {
  finalize: (jobs: FinalJob[], onProgress?: (n: number) => void) => Promise<FinalOut[]>;
  mix: (jobs: MixJob[], onProgress?: (n: number) => void) => Promise<MixOut[]>;
};
export const inlineRunner = (e: DemoElection): Runner => ({
  finalize: async (jobs, onProgress) =>
    jobs.map((j, i) => {
      onProgress?.(i + 1);
      return finalizeOne(e.pk!, e.mh, j);
    }),
  mix: async (jobs, onProgress) =>
    jobs.map((j, i) => {
      onProgress?.(i + 1);
      return mixBatch(e.pk!, e.mh, j);
    }),
});

// ------------------------------------------------------------------ the election
export type Progress = (label: string, done: number, total: number) => void;

function makePerson(n: number): Person {
  return {
    voterId: `syn-v-${String(n).padStart(7, "0")}`,
    constituency: CONSTITUENCY,
    aadhaarRef: `syn-uid-${String(n).padStart(7, "0")}`,
    panRef: n % 5 ? `syn-pan-${String(n).padStart(7, "0")}` : null,
    mobileRef: `syn-mob-${String(n).padStart(7, "0")}`,
    face: randomBytes(32),
    name: `Synthetic Person ${n}`,
    dob: `19${50 + (n % 50)}-${String(1 + (n % 12)).padStart(2, "0")}-${String(1 + (n % 28)).padStart(2, "0")}`,
  };
}

export class DemoElection {
  officer = new RoleKey("officer");
  board: Board;
  trustees: { trustee: Trustee; key: RoleKey }[] = [];
  commitments: TrusteeCommitment[] = [];
  pk?: PublicKey;
  manifest!: Body;
  mh = "";
  optionIds: string[] = OPTIONS.map((o) => o.id);
  phone = new SyntheticPhone();
  elig: EligibilityAuthority;
  private byTc = new Map<string, { seq: number; tag: string }>();
  private perTag = new Map<string, number[]>();
  private usedAlphas = new Set<string>();
  private finals = new Map<string, { u: bigint; flag: { alpha: string; beta: string } }>();
  rejections: Record<string, number> = {};
  validTags = new Set<string>();
  opensAt!: Date;
  closesAt!: Date;
  results?: Record<string, Json>;
  stats = { cast: 0, final: 0, superseded: 0, revoked: 0 };
  private constructor(public electionId: string, public now: () => Date) {
    this.board = new Board(electionId, new RoleKey("board"), now);
    this.elig = new EligibilityAuthority(electionId, this.phone);
  }

  static async create(opts: { eligible: number; trustees?: number; threshold?: number; now?: () => Date }) {
    const id = `SYN-DEMO-${bytesToHex(randomBytes(3)).toUpperCase()}`;
    const e = new DemoElection(id, opts.now ?? (() => new Date()));
    e.setup(opts.eligible, opts.trustees ?? 5, opts.threshold ?? 3);
    return e;
  }

  get boxCtx(): BoxCtx {
    return { pk: this.pk!, mh: this.mh, eid: this.electionId, options: { [CONSTITUENCY]: this.optionIds } };
  }

  private lifecycle(state: string, extra: Body = {}) {
    this.board.append("lifecycle", this.officer.signBody({ election_id: this.electionId, state, ...extra }));
    this.board.checkpoint();
  }

  private setup(eligible: number, n: number, k: number) {
    for (let i = 1; i <= n; i++) this.trustees.push({ trustee: null as unknown as Trustee, key: new RoleKey(`trustee-${i}`) });
    const now = this.now();
    this.opensAt = new Date(Math.floor(now.getTime() / 1000) * 1000 - 1000);
    this.closesAt = new Date(this.opensAt.getTime() + 2 * 3600 * 1000);
    for (let v = 1; v <= eligible; v++) this.elig.enrol(makePerson(v));
    this.manifest = {
      spec_version: "chunaviq-record/2",
      election_id: this.electionId,
      title: "ChunavIQ browser demo election",
      notice:
        "SYNTHETIC RESEARCH ELECTION. All voters, candidates, parties and results are artificial. This record has no legal effect and was not produced under the authority of the Election Commission of India or any State Election Commission.",
      voting_rule: "FPTP-single-member; one selection per ballot; NOTA counted but cannot win; a voter may vote again and only their last ballot under a currently valid registration counts",
      group: "CHUNAVIQ-2048-256-V1",
      window: { opens_at: iso(this.opensAt), closes_at: iso(this.closesAt) },
      constituencies: [{ id: CONSTITUENCY, name: "Synthetic Constituency 1", eligible_voters: eligible, options: OPTIONS.map(({ id, name, party }) => ({ id, name, party })) }],
      trustees: { threshold: k, members: this.trustees.map((t, i) => ({ index: i + 1, role: t.key.role, public_key: t.key.publicHex })) },
      keys: { officer: this.officer.publicHex, board: this.board.operator.publicHex, eligibility: this.elig.key.publicHex },
      mixing: { min_mixers: MIXERS, batch_size: MIX_BATCH },
      revoting: { max_ballots_per_tag: MAX_PER_TAG },
      software: { name: "chunaviq-web", version: "0.3.0", source_digest: (globalThis as { __BUILD_ID__?: string }).__BUILD_ID__ ?? "local" },
    };
    this.mh = sha256Hex(canonicalBytes(this.manifest));
    this.board.append("manifest", this.officer.signBody({ manifest: this.manifest, manifest_hash: this.mh }));
    this.board.checkpoint();

    this.lifecycle("KEY_CEREMONY");
    this.trustees.forEach((t, i) => (t.trustee = new Trustee(i + 1, k, this.mh)));
    this.commitments = this.trustees.map(({ trustee, key }) => {
      const tc = trustee.commitment();
      this.board.append("trustee_commitment", key.signBody({ commitment: commitmentToJson(tc) }));
      return tc;
    });
    for (const { trustee } of this.trustees) {
      for (const tc of this.commitments) {
        if (!tc.commitments.every((C, j) => schnorrVerify(C, tc.proofs[j], coefficientContext(this.mh, tc.index, j)))) throw new Error("bad commitment");
      }
      this.trustees.forEach(({ trustee: dealer }, j) => trustee.receiveShare(this.commitments[j], dealer.shareFor(trustee.index)));
    }
    for (const { trustee, key } of this.trustees) {
      trustee.finalize(n);
      this.board.append("trustee_ack", key.signBody({ index: trustee.index, verified_all_shares: true }));
    }
    const K = this.commitments.reduce((acc, tc) => (acc * tc.commitments[0]) % P, 1n);
    this.pk = new PublicKey(K);
    this.board.append("joint_key", this.officer.signBody({ joint_public_key: toHex(K) }));
    this.lifecycle("READY");
    this.elig.accepting = true;
    this.lifecycle("OPEN");
  }

  device(voterId: string): VoterDevice {
    const p = this.elig.people.get(voterId);
    if (!p) throw new Rejected("NOT_ON_ROLL");
    return new VoterDevice(p, this);
  }

  // ---------------------------------------------------------------- ballot box
  private gate() {
    if (this.board.state !== "OPEN") throw new Rejected("ELECTION_NOT_OPEN");
    const t = this.now().getTime();
    if (t < this.opensAt.getTime() || t >= this.closesAt.getTime()) throw new Rejected("OUTSIDE_VOTING_WINDOW");
  }

  submit(sub: Submission, precheckedTag?: string): { tracking_code: string; seq: number; revote?: number; duplicate_submission?: boolean } {
    try {
      // Idempotent retry: the same ballot under the same tag gets its original receipt, not a second entry.
      let tc = "";
      try {
        tc = trackingCode(sub.ballot);
      } catch {
        throw new Rejected("MALFORMED");
      }
      const prior = this.byTc.get(tc);
      if (prior && prior.tag === sub.tag) return { tracking_code: tc, seq: prior.seq, duplicate_submission: true };
      this.gate();
      let tag = precheckedTag;
      if (!tag) {
        const v = precheck(sub, this.boxCtx);
        if (v.startsWith("REJECT:")) throw new Rejected(v.slice(7));
        tag = v;
      }
      if (!this.elig.knownTag(sub.ballot.constituency, tag)) throw new Rejected("UNREGISTERED_TAG");
      const mine = this.perTag.get(tag) ?? [];
      if (mine.length >= MAX_PER_TAG) throw new Rejected("TOO_MANY_REVOTES");
      if (prior) throw new Rejected("DUPLICATE_CIPHERTEXT");
      const alphas = [sub.ballot.tag.ciphertext.alpha, ...sub.ballot.selections.map((s) => s.ciphertext.alpha)];
      if (alphas.some((a) => this.usedAlphas.has(a)) || new Set(alphas).size !== alphas.length) throw new Rejected("DUPLICATE_CIPHERTEXT");
      const entry = this.board.append("ballot", { tracking_code: tc, ballot: sub.ballot as unknown as Json });
      this.byTc.set(tc, { seq: entry.seq, tag });
      this.perTag.set(tag, [...mine, entry.seq]);
      alphas.forEach((a) => this.usedAlphas.add(a));
      return { tracking_code: tc, seq: entry.seq, revote: mine.length + 1 };
    } catch (e) {
      if (e instanceof Rejected) this.rejections[e.code] = (this.rejections[e.code] ?? 0) + 1;
      throw e;
    }
  }

  // ---------------------------------------------------------------- close, finalize, mix, count
  close(earlyReason = "Demo: the visitor closed the polls before the published closing time.", inPerson: string[] = []) {
    this.elig.accepting = false;
    const early = this.now().getTime() < this.closesAt.getTime();
    this.lifecycle("CLOSED", {
      ballots_accepted: this.board.of("ballot").length,
      rejections_by_reason: Object.fromEntries(Object.entries(this.rejections).sort()),
      ...(early ? { early_close_reason: earlyReason } : {}),
    });
    for (const v of inPerson) this.elig.markVotedInPerson(v); // polling day at the booth
    for (const [t, b] of this.elig.registrationEntries([CONSTITUENCY])) this.board.append(t, b);
    this.validTags = new Set(this.elig.validTags(CONSTITUENCY));
  }

  async finalize(runner: Runner = inlineRunner(this), progress?: Progress) {
    const finals = new Set<number>();
    for (const [tag, seqs] of this.perTag) {
      if (this.validTags.has(tag)) {
        finals.add(seqs[seqs.length - 1]);
        this.stats.superseded += seqs.length - 1;
      } else this.stats.revoked += seqs.length;
    }
    const ballots = this.board.of("ballot");
    this.stats.cast = ballots.length;
    this.stats.final = finals.size;
    const jobs: FinalJob[] = ballots.map((e) => {
      const b = e.body.ballot as unknown as Ballot;
      return { seq: e.seq, tc: e.body.tracking_code as string, cons: b.constituency, votes: b.selections.map((s) => s.ciphertext), f: finals.has(e.seq) ? 1 : 0 };
    });
    const outs = await runner.finalize(jobs, (n) => progress?.("Ballot box finalizing: which ballot of each voter counts", n, jobs.length));
    outs.forEach((o) => {
      if (o.u) this.finals.set(o.item.tracking_code as string, { u: fromHex(o.u), flag: o.item.flag as { alpha: string; beta: string } });
    });
    for (let i = 0; i < outs.length; i += FINALIZE_CHUNK) this.board.append("finalization", this.board.operator.signBody({ items: outs.slice(i, i + FINALIZE_CHUNK).map((o) => o.item) }));
    this.board.checkpoint();
  }

  /** The ballot box's designated-verifier proof that this ballot counts (only for the final ballot of a valid tag). */
  dvProof(tracking: string): { flag: { alpha: string; beta: string }; proof: OrProof } | null {
    const f = this.finals.get(tracking);
    const b = this.byTc.get(tracking);
    if (!f || !b) return null;
    return { flag: f.flag, proof: sigmaProveOr(dvBranches(this.pk!.K, ctFromJson(f.flag), fromHex(b.tag)), 0, [f.u], "dv-final", [this.mh, "dv-final", tracking], fastFor(this.pk!)) };
  }

  async mixAndTally(offline: number[] = [1], runner: Runner = inlineRunner(this), progress?: Progress) {
    if (this.board.state !== "CLOSED") throw new Error("tally requires CLOSED");
    const k = (this.manifest.trustees as { threshold: number }).threshold;
    const avail = this.trustees.filter((t) => !offline.includes(t.trustee.index));
    if (avail.length < Math.max(k, MIXERS)) throw new Error("not enough trustees");
    const quorumHosts = avail.slice(0, k);
    const mixers = avail.slice(0, MIXERS);
    const quorum = quorumHosts.map((t) => t.trustee.index);
    const ballots = this.board.of("ballot");
    const fin = new Map<number, Body>();
    for (const e of this.board.of("finalization")) for (const it of e.body.items as Body[]) fin.set(it.seq as number, it);
    const jobs: MixJob[] = [];
    for (let b0 = 0; b0 < ballots.length; b0 += MIX_BATCH)
      jobs.push({
        cons: CONSTITUENCY,
        batch: b0 / MIX_BATCH,
        rows: ballots.slice(b0, b0 + MIX_BATCH).map((e) => [(e.body.ballot as unknown as Ballot).tag.ciphertext, fin.get(e.seq)!.flag as { alpha: string; beta: string }]),
        mixers: mixers.map((m) => m.trustee.index),
      });
    const mixed = await runner.mix(jobs, (n) => progress?.(`${MIXERS} trustees shuffling and re-encrypting, batch by batch`, n, jobs.length));
    const counted: string[] = [];
    jobs.forEach((job, bi) => {
      const { outs, proofs, verified } = mixed[bi];
      if (!verified) throw new Error("observers refuse: a shuffle did not verify");
      mixers.forEach((m, i) => this.board.append("shuffle", m.key.signBody({ constituency: CONSTITUENCY, batch: job.batch, mixer: m.trustee.index, rows: outs[i] as unknown as Json, proof: proofs[i] as unknown as Json })));
      const final = outs[outs.length - 1].map((r) => r.map(ctFromJson));
      const shares = new Map<number, bigint[]>();
      for (const { trustee, key } of quorumHosts) {
        const items = final.map((r, i) => trustee.decryptionShare(r[1], [this.mh, "mix-flag", CONSTITUENCY, String(job.batch), String(i)]));
        shares.set(trustee.index, items.map((x) => x.M));
        this.board.append("flag_shares", key.signBody({ constituency: CONSTITUENCY, batch: job.batch, index: trustee.index, shares: items.map((x) => ({ share: toHex(x.M), proof: cpToJson(x.proof) })) }));
      }
      const rowsF: number[] = [];
      final.forEach((r, i) => {
        const gf = combineShares(r[1], new Map(quorumHosts.map((h) => [h.trustee.index, shares.get(h.trustee.index)![i]])));
        if (gf !== 1n && gf !== G) throw new Error("a flag decrypted to something other than 0 or 1");
        if (gf === G) rowsF.push(i);
      });
      const tshares = new Map<number, bigint[]>();
      for (const { trustee, key } of quorumHosts) {
        const items = rowsF.map((i) => trustee.decryptionShare(final[i][0], [this.mh, "mix-tag", CONSTITUENCY, String(job.batch), String(i)]));
        tshares.set(trustee.index, items.map((x) => x.M));
        this.board.append("tag_shares", key.signBody({ constituency: CONSTITUENCY, batch: job.batch, index: trustee.index, rows: rowsF, shares: items.map((x) => ({ share: toHex(x.M), proof: cpToJson(x.proof) })) }));
      }
      rowsF.forEach((i, j) => counted.push(toHex(combineShares(final[i][0], new Map(quorumHosts.map((h) => [h.trustee.index, tshares.get(h.trustee.index)![j]]))))));
    });
    if (new Set(counted).size !== counted.length || !counted.every((t) => this.validTags.has(t))) throw new Error("counted tags are not distinct valid registrations");
    progress?.("Trustees decrypting the totals", 0, 1);
    const masked = ballots.map((e) => (fin.get(e.seq)!.masked as { alpha: string; beta: string }[]).map(ctFromJson));
    const aggs: Record<string, Ct> = {};
    this.optionIds.forEach((oid, j) => (aggs[oid] = addCts(masked.map((m) => m[j]))));
    const nFinal = counted.length;
    this.board.append(
      "aggregate",
      this.officer.signBody({ constituency: CONSTITUENCY, ballot_count: ballots.length, final_count: nFinal, aggregates: this.optionIds.map((oid) => ({ option_id: oid, ciphertext: ctToJson(aggs[oid]) })) }),
    );
    const shares: Record<string, Map<number, bigint>> = Object.fromEntries(this.optionIds.map((o) => [o, new Map()]));
    for (const { trustee, key } of quorumHosts) {
      const items = this.optionIds.map((oid) => {
        const { M, proof } = trustee.decryptionShare(aggs[oid], [this.mh, "decrypt-aggregate", CONSTITUENCY, oid]);
        shares[oid].set(trustee.index, M);
        return { option_id: oid, share: toHex(M), proof: cpToJson(proof) };
      });
      this.board.append("decryption_shares", key.signBody({ constituency: CONSTITUENCY, index: trustee.index, shares: items }));
    }
    const counts: Record<string, number> = {};
    for (const oid of this.optionIds) counts[oid] = dlogBounded(combineShares(aggs[oid], shares[oid]), nFinal);
    const dec = decide(counts);
    this.board.append(
      "result",
      this.officer.signBody({ constituency: CONSTITUENCY, quorum, ballot_count: ballots.length, final_count: nFinal, counts: this.optionIds.map((oid) => ({ option_id: oid, votes: counts[oid] })), ...dec }),
    );
    this.lifecycle("TALLIED");
    this.lifecycle("PUBLISHED");
    this.results = { counts, quorum, ballots: nFinal, cast: ballots.length, ...dec };
    return this.results;
  }

  publicShareOf(i: number) {
    return publicShare(this.commitments, i);
  }

  /** Test helper: the tag a ballot was cast under (the ballot box's private knowledge). */
  tagOf(tracking: string) {
    return this.byTc.get(tracking)?.tag;
  }

  checkLinkFor(sub: Submission) {
    return checkLink(this.boxCtx, sub.ballot, sub.tag, sub.link);
  }
}

export function decide(counts: Record<string, number>): { winner: string | null; tied: string[]; nota_exceeds_winner: boolean } {
  const cands = Object.entries(counts).filter(([k]) => k !== NOTA);
  const top = cands.length ? Math.max(...cands.map(([, v]) => v)) : 0;
  const leaders = cands.filter(([, v]) => v === top).map(([k]) => k).sort();
  return { winner: leaders.length === 1 ? leaders[0] : null, tied: leaders.length > 1 ? leaders : [], nota_exceeds_winner: (counts[NOTA] ?? 0) > top };
}

export function commitmentToJson(tc: TrusteeCommitment): Json {
  return { index: tc.index, commitments: tc.commitments.map(toHex), proofs: tc.proofs.map((p) => ({ h: toHex(p.h), v: toHex(p.v) })) };
}

export { evalCommitments, hexToBytes };
