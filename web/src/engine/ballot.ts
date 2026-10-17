// Encrypted ballots (protocol v2) and ballot-box acceptance rules. Mirrors src/chunaviq/election/ballot.py.
import {
  addCts,
  cpFromJson,
  cpProve,
  cpToJson,
  cpVerify,
  ctFromJson,
  ctToJson,
  DISJ_KEYS,
  disjFromJson,
  disjProve,
  disjToJson,
  disjVerify,
  div,
  fastFor,
  gPow,
  isElement,
  linkStatement,
  P,
  PublicKey,
  Q,
  rand,
  sigmaProve,
  sigmaVerify,
  tagStatement,
  type Ct,
  type SigmaProof,
} from "./crypto";
import { canonicalBytes, sha256Hex, type Json } from "./encoding";
import { fromHex, toHex } from "./bigint";

export const selectionContext = (mh: string, cons: string, oid: string, tagAlpha: string) => [mh, "selection", cons, oid, tagAlpha];
export const limitContext = (mh: string, cons: string, tagAlpha: string) => [mh, "contest-limit", cons, tagAlpha];
export const tagContext = (mh: string, cons: string, digest: string) => [mh, "ballot-tag", cons, digest];
export const linkContext = (mh: string, tracking: string) => [mh, "tag-link", tracking];

export type Selection = { option_id: string; ciphertext: { alpha: string; beta: string }; proof: Record<string, string> };
export type Ballot = {
  election_id: string;
  constituency: string;
  tag: { ciphertext: { alpha: string; beta: string }; proof: SigmaProof };
  selections: Selection[];
  limit_proof: { a: string; b: string; v: string };
};
export type Submission = { ballot: Ballot; tag: string; link: SigmaProof };
export type Prepared = { ballot: Ballot; choice: string; nonces: bigint[]; tagR: bigint };

export const trackingCode = (b: Ballot | Json) => sha256Hex(canonicalBytes(b as Json));
export const bodyDigest = (sels: Selection[], lp: Ballot["limit_proof"]) => sha256Hex(canonicalBytes({ selections: sels, limit_proof: lp } as unknown as Json));

export function encryptBallot(pk: PublicKey, mh: string, eid: string, cons: string, optionIds: string[], choice: string, t: bigint): Prepared {
  if (!optionIds.includes(choice)) throw new RangeError("choice is not on this ballot");
  const rT = rand();
  const tagCt: Ct = { alpha: gPow(rT), beta: (gPow(t) * pk.kPow(rT)) % P };
  const ta = toHex(tagCt.alpha);
  const selections: Selection[] = [];
  const nonces: bigint[] = [];
  const cts: Ct[] = [];
  for (const oid of optionIds) {
    const m = oid === choice ? 1 : 0;
    const r = rand();
    const ct = pk.encrypt(BigInt(m), r);
    selections.push({ option_id: oid, ciphertext: ctToJson(ct), proof: disjToJson(disjProve(pk, ct, m, r, selectionContext(mh, cons, oid, ta))) });
    nonces.push(r);
    cts.push(ct);
  }
  const agg = addCts(cts);
  const R = nonces.reduce((a, b) => (a + b) % Q, 0n);
  const lp = cpToJson(cpProve(R, pk.K, agg.alpha, div(agg.beta, gPow(1n)), "contest-limit", limitContext(mh, cons, ta), (e) => pk.kPow(e)));
  const proof = sigmaProve(tagStatement(pk.K, tagCt.alpha, tagCt.beta), [rT, t], "ballot-tag", tagContext(mh, cons, bodyDigest(selections, lp)), fastFor(pk));
  return { ballot: { election_id: eid, constituency: cons, tag: { ciphertext: ctToJson(tagCt), proof }, selections, limit_proof: lp }, choice, nonces, tagR: rT };
}

/** Private proof for the ballot box that the tag ciphertext encrypts T (never published). */
export function makeLink(pk: PublicKey, mh: string, prep: Prepared, T: bigint): SigmaProof {
  const tc = ctFromJson(prep.ballot.tag.ciphertext);
  return sigmaProve(linkStatement(pk.K, tc.alpha, tc.beta, T), [prep.tagR], "tag-link", linkContext(mh, trackingCode(prep.ballot)), fastFor(pk));
}

/** Benaloh cast-or-challenge: re-encrypt with the revealed nonces and compare. */
export function benalohAudit(pk: PublicKey, prep: Prepared, optionIds: string[]): boolean {
  if (prep.ballot.selections.length !== optionIds.length || prep.nonces.length !== optionIds.length) return false;
  return optionIds.every((oid, j) => {
    const e = pk.encrypt(oid === prep.choice ? 1n : 0n, prep.nonces[j]);
    const c = ctFromJson(prep.ballot.selections[j].ciphertext);
    return e.alpha === c.alpha && e.beta === c.beta;
  });
}

export class Rejected extends Error {
  constructor(public code: string) {
    super(code);
  }
}

export type BoxCtx = { pk: PublicKey; mh: string; eid: string; options: Record<string, string[]> };

const keysAre = (o: unknown, keys: readonly string[]) =>
  !!o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).length === keys.length && keys.every((k) => k in (o as object));

/** Stateless validity checks; throws Rejected(code). Exact schemas at every level (finding F-001). */
export function checkBallot(b: unknown, c: BoxCtx): void {
  try {
    if (!keysAre(b, ["election_id", "constituency", "tag", "selections", "limit_proof"])) throw new Rejected("MALFORMED");
    const x = b as Ballot;
    if (x.election_id !== c.eid) throw new Rejected("WRONG_ELECTION");
    const cons = x.constituency;
    if (typeof cons !== "string" || !(cons in c.options)) throw new Rejected("UNKNOWN_CONSTITUENCY");
    if (!keysAre(x.tag, ["ciphertext", "proof"]) || !keysAre(x.tag.ciphertext, ["alpha", "beta"])) throw new Rejected("MALFORMED");
    const tct = ctFromJson(x.tag.ciphertext);
    if (!isElement(tct.alpha) || !isElement(tct.beta)) throw new Rejected("INVALID_CIPHERTEXT");
    const ta = x.tag.ciphertext.alpha;
    if (!Array.isArray(x.selections) || x.selections.map((s) => s?.option_id).join("\u0000") !== c.options[cons].join("\u0000")) throw new Rejected("WRONG_BALLOT_STYLE");
    const cts: Ct[] = [];
    for (const s of x.selections) {
      if (!keysAre(s, ["option_id", "ciphertext", "proof"]) || !keysAre(s.ciphertext, ["alpha", "beta"]) || !keysAre(s.proof, DISJ_KEYS)) throw new Rejected("MALFORMED");
      const ct = ctFromJson(s.ciphertext);
      if (!isElement(ct.alpha) || !isElement(ct.beta)) throw new Rejected("INVALID_CIPHERTEXT");
      if (!disjVerify(c.pk, ct, disjFromJson(s.proof), selectionContext(c.mh, cons, s.option_id, ta))) throw new Rejected("BAD_SELECTION_PROOF");
      cts.push(ct);
    }
    if (!keysAre(x.limit_proof, ["a", "b", "v"])) throw new Rejected("MALFORMED");
    const agg = addCts(cts);
    if (!cpVerify(c.pk.K, agg.alpha, div(agg.beta, gPow(1n)), cpFromJson(x.limit_proof), "contest-limit", limitContext(c.mh, cons, ta), (e) => c.pk.kPow(e)))
      throw new Rejected("BAD_LIMIT_PROOF");
    if (!sigmaVerify(tagStatement(c.pk.K, tct.alpha, tct.beta), x.tag.proof, "ballot-tag", tagContext(c.mh, cons, bodyDigest(x.selections, x.limit_proof)), fastFor(c.pk)))
      throw new Rejected("BAD_TAG_PROOF");
  } catch (e) {
    if (e instanceof Rejected) throw e;
    throw new Rejected("MALFORMED");
  }
}

/** Verify the private tag link; returns T. */
export function checkLink(c: BoxCtx, ballot: Ballot, Thex: string, link: SigmaProof): bigint {
  try {
    const T = fromHex(Thex);
    const tc = ctFromJson(ballot.tag.ciphertext);
    if (T === 1n || !isElement(T)) throw new Error();
    if (!sigmaVerify(linkStatement(c.pk.K, tc.alpha, tc.beta, T), link, "tag-link", linkContext(c.mh, trackingCode(ballot)), fastFor(c.pk))) throw new Error();
    return T;
  } catch {
    throw new Rejected("BAD_TAG_LINK");
  }
}

/** All stateless checks of a submission; returns the tag (hex) or a rejection code prefixed with "REJECT:". */
export function precheck(sub: unknown, c: BoxCtx): string {
  try {
    if (!keysAre(sub, ["ballot", "tag", "link"])) throw new Rejected("MALFORMED");
    const s = sub as Submission;
    checkBallot(s.ballot, c);
    return toHex(checkLink(c, s.ballot, s.tag, s.link));
  } catch (e) {
    return "REJECT:" + (e instanceof Rejected ? e.code : "MALFORMED");
  }
}

export { toHex };
