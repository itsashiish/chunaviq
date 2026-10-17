// Encrypted ballots and ballot-box acceptance rules. Mirrors src/chunaviq/election/ballot.py.
import { bytesToHex, fromHex, hexToBytes, toHex } from "./bigint";
import { credentialMessage, rsaVerify, type RSAPublic } from "./blind";
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
  gPow,
  isElement,
  PublicKey,
  Q,
  rand,
  type Ct,
} from "./crypto";
import { canonicalBytes, sha256Hex, type Json } from "./encoding";

export const selectionContext = (mh: string, cons: string, oid: string, tok: string) => [mh, "selection", cons, oid, tok];
export const limitContext = (mh: string, cons: string, tok: string) => [mh, "contest-limit", cons, tok];

export type Ballot = {
  election_id: string;
  constituency: string;
  credential: { token: string; signature: string };
  selections: { option_id: string; ciphertext: { alpha: string; beta: string }; proof: Record<string, string> }[];
  limit_proof: { a: string; b: string; v: string };
};

export type Prepared = { ballot: Ballot; choice: string; nonces: bigint[] };

export const trackingCode = (b: Ballot | Json) => sha256Hex(canonicalBytes(b as Json));

export function encryptBallot(pk: PublicKey, mh: string, eid: string, cons: string, optionIds: string[], choice: string, tokenHex: string, sigHex: string): Prepared {
  if (!optionIds.includes(choice)) throw new RangeError("choice is not on this ballot");
  const selections: Ballot["selections"] = [];
  const nonces: bigint[] = [];
  const cts: Ct[] = [];
  for (const oid of optionIds) {
    const m = oid === choice ? 1 : 0;
    const r = rand();
    const ct = pk.encrypt(BigInt(m), r);
    selections.push({ option_id: oid, ciphertext: ctToJson(ct), proof: disjToJson(disjProve(pk, ct, m, r, selectionContext(mh, cons, oid, tokenHex))) });
    nonces.push(r);
    cts.push(ct);
  }
  const agg = addCts(cts);
  const R = nonces.reduce((a, b) => (a + b) % Q, 0n);
  const lp = cpProve(R, pk.K, agg.alpha, div(agg.beta, gPow(1n)), "contest-limit", limitContext(mh, cons, tokenHex), (e) => pk.kPow(e));
  return {
    ballot: { election_id: eid, constituency: cons, credential: { token: tokenHex, signature: sigHex }, selections, limit_proof: cpToJson(lp) },
    choice,
    nonces,
  };
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

export type BoxCtx = { pk: PublicKey; mh: string; eid: string; options: Record<string, string[]>; issuers: Record<string, RSAPublic> };

const keysAre = (o: unknown, keys: readonly string[]) =>
  !!o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).length === keys.length && keys.every((k) => k in (o as object));

/** Stateless validity checks; throws Rejected(code). Exact schemas at every level (finding F-001). */
export function checkBallot(b: unknown, c: BoxCtx): void {
  try {
    if (!keysAre(b, ["election_id", "constituency", "credential", "selections", "limit_proof"])) throw new Rejected("MALFORMED");
    const x = b as Ballot;
    if (x.election_id !== c.eid) throw new Rejected("WRONG_ELECTION");
    const cons = x.constituency;
    if (typeof cons !== "string" || !(cons in c.options)) throw new Rejected("UNKNOWN_CONSTITUENCY");
    if (!keysAre(x.credential, ["token", "signature"])) throw new Rejected("MALFORMED");
    const tok = x.credential.token;
    if (typeof tok !== "string" || tok.length !== 64 || bytesToHex(hexToBytes(tok)) !== tok) throw new Rejected("MALFORMED");
    if (!rsaVerify(c.issuers[cons], credentialMessage(c.eid, cons, hexToBytes(tok)), fromHex(x.credential.signature))) throw new Rejected("BAD_CREDENTIAL");
    if (!Array.isArray(x.selections) || x.selections.map((s) => s?.option_id).join("\u0000") !== c.options[cons].join("\u0000")) throw new Rejected("WRONG_BALLOT_STYLE");
    const cts: Ct[] = [];
    for (const s of x.selections) {
      if (!keysAre(s, ["option_id", "ciphertext", "proof"]) || !keysAre(s.ciphertext, ["alpha", "beta"]) || !keysAre(s.proof, DISJ_KEYS)) throw new Rejected("MALFORMED");
      const ct = ctFromJson(s.ciphertext);
      if (!isElement(ct.alpha) || !isElement(ct.beta)) throw new Rejected("INVALID_CIPHERTEXT");
      if (!disjVerify(c.pk, ct, disjFromJson(s.proof), selectionContext(c.mh, cons, s.option_id, tok))) throw new Rejected("BAD_SELECTION_PROOF");
      cts.push(ct);
    }
    if (!keysAre(x.limit_proof, ["a", "b", "v"])) throw new Rejected("MALFORMED");
    const agg = addCts(cts);
    if (!cpVerify(c.pk.K, agg.alpha, div(agg.beta, gPow(1n)), cpFromJson(x.limit_proof), "contest-limit", limitContext(c.mh, cons, tok), (e) => c.pk.kPow(e)))
      throw new Rejected("BAD_LIMIT_PROOF");
  } catch (e) {
    if (e instanceof Rejected) throw e;
    throw new Rejected("MALFORMED");
  }
}

export function checkCode(b: unknown, c: BoxCtx): string | null {
  try {
    checkBallot(b, c);
    return null;
  } catch (e) {
    return (e as Rejected).code;
  }
}

export { toHex };
