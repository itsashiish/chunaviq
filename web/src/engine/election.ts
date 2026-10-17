// A complete demo election in the browser: board, officer, trustees, eligibility authority,
// ballot box and tally. Every role keeps its own keys; the record format is identical to the
// Python implementation, so `chunaviq verify` accepts records produced here.
import { bytesToHex, fromHex, hexToBytes, randomBytes, toHex } from "./bigint";
import { blind, BlindSigner, credentialMessage, rsaToJson, unblind, type RSAPublic } from "./blind";
import { checkBallot, encryptBallot, Rejected, trackingCode, type Ballot, type BoxCtx, type Prepared } from "./ballot";
import {
  addCts,
  combineShares,
  cpToJson,
  ctFromJson,
  ctToJson,
  dlogBounded,
  publicShare,
  PublicKey,
  schnorrVerify,
  Trustee,
  coefficientContext,
  evalCommitments,
  P,
  type Ct,
  type TrusteeCommitment,
} from "./crypto";
import { canonicalBytes, canonicalJson, sha256Hex, type Json } from "./encoding";
import { MerkleTree } from "./merkle";
import { RoleKey, type Body } from "./sign";

export const LIFECYCLE = ["DRAFT", "KEY_CEREMONY", "READY", "OPEN", "CLOSED", "TALLIED", "PUBLISHED"] as const;
export const NOTA = "NOTA";
export const CONSTITUENCY = "SYN-AC-01";

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

// ------------------------------------------------------------------ eligibility authority
type RollRow = { constituency: string; secret: string; issued?: { commitment: string; salt: Uint8Array } };

export class EligibilityAuthority {
  key = new RoleKey("eligibility");
  roll = new Map<string, RollRow>();
  accepting = false;
  private constructor(public electionId: string, public signers: Record<string, BlindSigner>) {}
  static async create(electionId: string, constituencies: string[], bits = 3072) {
    const signers: Record<string, BlindSigner> = {};
    for (const c of constituencies) signers[c] = await BlindSigner.generate(bits);
    return new EligibilityAuthority(electionId, signers);
  }
  issuers(): Record<string, RSAPublic> {
    return Object.fromEntries(Object.entries(this.signers).map(([c, s]) => [c, s.pub]));
  }
  issuerKeysEntry(): Body {
    return this.key.signBody({ election_id: this.electionId, issuer_keys: Object.fromEntries(Object.entries(this.issuers()).sort().map(([c, k]) => [c, rsaToJson(k)])) });
  }
  register(voterId: string, constituency: string): string {
    const secret = bytesToHex(randomBytes(16));
    this.roll.set(voterId, { constituency, secret });
    return secret;
  }
  issue(voterId: string, secret: string, blindedHex: string) {
    if (!this.accepting) throw new Rejected("NOT_ACCEPTING");
    const row = this.roll.get(voterId);
    if (!row) throw new Rejected("NOT_ON_ROLL");
    if (row.secret !== secret) throw new Rejected("AUTH_FAILED");
    if (row.issued) throw new Rejected("ALREADY_ISSUED");
    const salt = randomBytes(16);
    const commitment = sha256Hex(participationPreimage(this.electionId, voterId, salt));
    row.issued = { commitment, salt };
    const sig = this.signers[row.constituency].signBlinded(fromHex(blindedHex));
    return { constituency: row.constituency, blind_signature: toHex(sig), participation_salt: bytesToHex(salt), commitment };
  }
  participationSummary(): Body {
    const out: Record<string, Json> = {};
    for (const c of Object.keys(this.signers).sort()) {
      const rows = [...this.roll.values()].filter((r) => r.constituency === c);
      const commits = rows.filter((r) => r.issued).map((r) => r.issued!.commitment).sort();
      out[c] = { eligible: rows.length, credentials_issued: commits.length, commitments: commits };
    }
    return this.key.signBody({ election_id: this.electionId, constituencies: out });
  }
}

/** SHA-256 preimage of a participation commitment (src/chunaviq/election/eligibility.py). */
export function participationPreimage(eid: string, voterId: string, salt: Uint8Array): Uint8Array {
  const head = new TextEncoder().encode(`chunaviq/v1/participation\u0000${eid}\u0000${voterId}\u0000`);
  const out = new Uint8Array(head.length + salt.length);
  out.set(head);
  out.set(salt, head.length);
  return out;
}

// ------------------------------------------------------------------ voter device
export class VoterDevice {
  token?: Uint8Array;
  signature?: bigint;
  receiptSalt?: string;
  commitment?: string;
  lastBlinded?: string;
  constructor(public voterId: string, private secret: string, public constituency: string, private e: DemoElection) {}
  obtainCredential(): void {
    const pub = this.e.elig.signers[this.constituency].pub;
    const token = randomBytes(32);
    const msg = credentialMessage(this.e.electionId, this.constituency, token);
    const { blinded, r } = blind(pub, msg);
    this.lastBlinded = toHex(blinded);
    const resp = this.e.elig.issue(this.voterId, this.secret, this.lastBlinded);
    this.signature = unblind(pub, msg, r, fromHex(resp.blind_signature));
    this.token = token;
    this.receiptSalt = resp.participation_salt;
    this.commitment = resp.commitment;
  }
  prepare(choice: string): Prepared {
    if (!this.token || this.signature === undefined) throw new Error("no credential");
    return encryptBallot(this.e.pk!, this.e.mh, this.e.electionId, this.constituency, this.e.optionIds, choice, bytesToHex(this.token), toHex(this.signature));
  }
}

// ------------------------------------------------------------------ the election
export type Progress = (label: string, done: number, total: number) => void;

export class DemoElection {
  officer = new RoleKey("officer");
  board: Board;
  trustees: { trustee: Trustee; key: RoleKey }[] = [];
  commitments: TrusteeCommitment[] = [];
  pk?: PublicKey;
  manifest!: Body;
  mh = "";
  optionIds: string[] = OPTIONS.map((o) => o.id);
  usedTokens = new Set<string>();
  usedAlphas = new Set<string>();
  rejections: Record<string, number> = {};
  opensAt!: Date;
  closesAt!: Date;
  results?: Record<string, Json>;
  private constructor(public electionId: string, public elig: EligibilityAuthority, public now: () => Date) {
    this.board = new Board(electionId, new RoleKey("board"), now);
  }

  static async create(opts: { eligible: number; trustees?: number; threshold?: number; rsaBits?: number; now?: () => Date }) {
    const id = `SYN-DEMO-${bytesToHex(randomBytes(3)).toUpperCase()}`;
    const elig = await EligibilityAuthority.create(id, [CONSTITUENCY], opts.rsaBits ?? 3072);
    const e = new DemoElection(id, elig, opts.now ?? (() => new Date()));
    e.setup(opts.eligible, opts.trustees ?? 5, opts.threshold ?? 3);
    return e;
  }

  get boxCtx(): BoxCtx {
    return { pk: this.pk!, mh: this.mh, eid: this.electionId, options: { [CONSTITUENCY]: this.optionIds }, issuers: this.elig.issuers() };
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
    for (let v = 1; v <= eligible; v++) this.elig.register(`syn-v-${String(v).padStart(7, "0")}`, CONSTITUENCY);
    this.manifest = {
      spec_version: "chunaviq-record/1",
      election_id: this.electionId,
      title: "ChunavIQ browser demo election",
      notice:
        "SYNTHETIC RESEARCH ELECTION. All voters, candidates, parties and results are artificial. This record has no legal effect and was not produced under the authority of the Election Commission of India or any State Election Commission.",
      voting_rule: "FPTP-single-member; one selection per ballot; NOTA counted but cannot win",
      group: "CHUNAVIQ-2048-256-V1",
      window: { opens_at: iso(this.opensAt), closes_at: iso(this.closesAt) },
      constituencies: [{ id: CONSTITUENCY, name: "Synthetic Constituency 1", eligible_voters: eligible, options: OPTIONS.map(({ id, name, party }) => ({ id, name, party })) }],
      trustees: { threshold: k, members: this.trustees.map((t, i) => ({ index: i + 1, role: t.key.role, public_key: t.key.publicHex })) },
      keys: { officer: this.officer.publicHex, board: this.board.operator.publicHex, eligibility: this.elig.key.publicHex },
      software: { name: "chunaviq-web", version: "0.2.0", source_digest: (globalThis as { __BUILD_ID__?: string }).__BUILD_ID__ ?? "local" },
    };
    this.mh = sha256Hex(canonicalBytes(this.manifest));
    this.board.append("manifest", this.officer.signBody({ manifest: this.manifest, manifest_hash: this.mh }));
    this.board.checkpoint();

    // key ceremony
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
    this.board.append("issuer_keys", this.elig.issuerKeysEntry());
    this.lifecycle("READY");
    this.elig.accepting = true;
    this.lifecycle("OPEN");
  }

  // ---------------------------------------------------------------- ballot box
  private gate() {
    if (this.board.state !== "OPEN") throw new Rejected("ELECTION_NOT_OPEN");
    const t = this.now().getTime();
    if (t < this.opensAt.getTime() || t >= this.closesAt.getTime()) throw new Rejected("OUTSIDE_VOTING_WINDOW");
  }

  submit(ballot: Ballot, prechecked = false): { tracking_code: string; seq: number } {
    try {
      this.gate();
      if (!prechecked) checkBallot(ballot, this.boxCtx);
      const tok = ballot.credential.token;
      if (this.usedTokens.has(tok)) throw new Rejected("CREDENTIAL_ALREADY_USED");
      const alphas = ballot.selections.map((s) => s.ciphertext.alpha);
      if (alphas.some((a) => this.usedAlphas.has(a)) || new Set(alphas).size !== alphas.length) throw new Rejected("DUPLICATE_CIPHERTEXT");
      const tc = trackingCode(ballot);
      const entry = this.board.append("ballot", { tracking_code: tc, ballot: ballot as unknown as Json });
      this.usedTokens.add(tok);
      alphas.forEach((a) => this.usedAlphas.add(a));
      return { tracking_code: tc, seq: entry.seq };
    } catch (e) {
      if (e instanceof Rejected) this.rejections[e.code] = (this.rejections[e.code] ?? 0) + 1;
      throw e;
    }
  }

  device(voterId: string): VoterDevice {
    const row = this.elig.roll.get(voterId);
    if (!row) throw new Rejected("NOT_ON_ROLL");
    return new VoterDevice(voterId, row.secret, row.constituency, this);
  }

  // ---------------------------------------------------------------- close + tally
  close(earlyReason = "Demo: the visitor closed the polls before the published closing time.") {
    this.elig.accepting = false;
    const early = this.now().getTime() < this.closesAt.getTime();
    this.lifecycle("CLOSED", {
      ballots_accepted: this.board.of("ballot").length,
      rejections_by_reason: Object.fromEntries(Object.entries(this.rejections).sort()),
      ...(early ? { early_close_reason: earlyReason } : {}),
    });
    this.board.append("participation_summary", this.elig.participationSummary());
  }

  tally(offline: number[] = [1]) {
    if (this.board.state !== "CLOSED") throw new Error("tally requires CLOSED");
    const k = (this.manifest.trustees as { threshold: number }).threshold;
    const quorumHosts = this.trustees.filter((t) => !offline.includes(t.trustee.index)).slice(0, k);
    if (quorumHosts.length < k) throw new Error("not enough trustees for the threshold");
    const quorum = quorumHosts.map((t) => t.trustee.index);
    const ballots = this.board.of("ballot").map((e) => e.body.ballot as unknown as Ballot);
    const aggs: Record<string, Ct> = {};
    this.optionIds.forEach((oid, j) => (aggs[oid] = addCts(ballots.map((b) => ctFromJson(b.selections[j].ciphertext)))));
    this.board.append("aggregate", this.officer.signBody({ constituency: CONSTITUENCY, ballot_count: ballots.length, aggregates: this.optionIds.map((oid) => ({ option_id: oid, ciphertext: ctToJson(aggs[oid]) })) }));
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
    for (const oid of this.optionIds) counts[oid] = dlogBounded(combineShares(aggs[oid], shares[oid]), ballots.length);
    const dec = decide(counts);
    this.board.append("result", this.officer.signBody({ constituency: CONSTITUENCY, quorum, ballot_count: ballots.length, counts: this.optionIds.map((oid) => ({ option_id: oid, votes: counts[oid] })), ...dec }));
    this.lifecycle("TALLIED");
    this.lifecycle("PUBLISHED");
    this.results = { counts, quorum, ballots: ballots.length, ...dec };
    return this.results;
  }

  publicShareOf(i: number) {
    return publicShare(this.commitments, i);
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
