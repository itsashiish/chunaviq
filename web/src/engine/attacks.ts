// Cheating attempts the demo lets visitors try. Each must be refused by the ballot box.
import { bytesToHex, randomBytes, toHex } from "./bigint";
import { selectionContext, type Ballot } from "./ballot";
import { ctToJson, disjProve, disjToJson, G, P, Q, rand } from "./crypto";
import { DemoElection, VoterDevice } from "./election";
import { canonicalJson, sha256Hex, type Json } from "./encoding";
import { MerkleTree } from "./merkle";
import type { Body } from "./sign";

const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));

export type Attack = { id: string; title: string; how: string; run: (e: DemoElection, me: VoterDevice) => void; explain: Record<string, string> };

export const ATTACKS: Attack[] = [
  {
    id: "twice",
    title: "Vote a second time",
    how: "Your device seals a new ballot with the credential you already used.",
    run: (e, me) => void e.submit(me.prepare("C1").ballot),
    explain: { CREDENTIAL_ALREADY_USED: "Each credential is accepted once. The ballot box remembers it without knowing whose it is." },
  },
  {
    id: "second-credential",
    title: "Ask for another credential",
    how: "You log in again and request a fresh credential.",
    run: (_e, me) => me.obtainCredential(),
    explain: { ALREADY_ISSUED: "The eligibility authority issues one credential per voter on the roll." },
  },
  {
    id: "forge",
    title: "Forge a credential",
    how: "You invent a token and a signature instead of asking the authority.",
    run: (e, me) => {
      const b = clone(me.prepare("C2").ballot);
      b.credential = { token: bytesToHex(randomBytes(32)), signature: toHex(BigInt("0x" + bytesToHex(randomBytes(380))) | 1n) };
      void e.submit(b);
    },
    explain: { BAD_CREDENTIAL: "The signature does not check out against the authority's published key." },
  },
  {
    id: "overvote",
    title: "Vote for two candidates",
    how: "Two boxes encrypt a 1. Each still proves it holds a 0 or a 1.",
    run: (e) => {
      const d = freshDevice(e);
      const b = clone(d.prepare("C1").ballot);
      const tok = b.credential.token;
      for (const j of [0, 1]) {
        const r = rand();
        const ct = e.pk!.encrypt(1n, r);
        b.selections[j].ciphertext = ctToJson(ct);
        b.selections[j].proof = disjToJson(disjProve(e.pk!, ct, 1, r, selectionContext(e.mh, b.constituency, b.selections[j].option_id, tok)));
      }
      b.limit_proof.v = toHex((BigInt("0x" + b.limit_proof.v) + 1n) % Q);
      void e.submit(b);
    },
    explain: { BAD_LIMIT_PROOF: "Every ballot must prove its boxes add up to exactly one vote. Two votes cannot produce that proof." },
  },
  {
    id: "copy",
    title: "Copy someone else's ballot",
    how: "You paste another voter's encrypted choices under your own fresh credential, to vote the way they did.",
    run: (e) => {
      const victim = e.board.of("ballot")[0].body.ballot as unknown as Ballot;
      const d = freshDevice(e);
      const b = clone(d.prepare("C3").ballot);
      b.selections = clone(victim.selections);
      b.limit_proof = clone(victim.limit_proof);
      void e.submit(b);
    },
    explain: { BAD_SELECTION_PROOF: "Each proof is tied to the credential it was made with, so copied proofs fail." },
  },
  {
    id: "mark",
    title: "Hide a marker in your ballot",
    how: "You add a note so a vote buyer can find your ballot in the public record.",
    run: (e) => {
      const d = freshDevice(e);
      const b = clone(d.prepare("C1").ballot) as Ballot & { marker?: string };
      (b.selections[0].ciphertext as Record<string, string>).marker = "paid-voter-17";
      void e.submit(b);
    },
    explain: { MALFORMED: "Ballots must match the exact format. Any extra field is refused, so ballots cannot be tagged." },
  },
];

/** A credentialed abstainer from the roll, used as the attacker's second identity. */
function freshDevice(e: DemoElection): VoterDevice {
  const id = [...e.elig.roll.entries()].reverse().find(([, r]) => !r.issued)?.[0];
  if (!id) throw new Error("no unused voters left on the roll");
  const d = e.device(id);
  d.obtainCredential();
  return d;
}

// ------------------------------------------------------------------ record tampering
export type Tamper = { id: string; title: string; who: string; apply: (e: DemoElection) => { entries: string; checkpoints: string }; expect: string };

const lines = (e: DemoElection) => e.board.export().entries.trimEnd().split("\n");

function resign(e: DemoElection, ls: string[]): string {
  const t = new MerkleTree();
  ls.forEach((l) => t.append(new TextEncoder().encode(l)));
  const last = JSON.parse(ls[ls.length - 1]);
  const cp = e.board.operator.signBody({ election_id: e.electionId, tree_size: ls.length, root: bytesToHex(t.root()), time_bucket: last.time_bucket, prev_tree_size: 0, consistency_proof: [] });
  return canonicalJson(cp) + "\n";
}

function bumpVote(ls: string[]): string[] {
  const i = ls.findIndex((l) => l.includes('"type":"ballot"'));
  const ent = JSON.parse(ls[i]);
  const ct = ent.body.ballot.selections[0].ciphertext;
  ct.beta = toHex((BigInt("0x" + ct.beta) * G) % P);
  ent.body.tracking_code = sha256Hex(new TextEncoder().encode(canonicalJson(ent.body.ballot)));
  const out = [...ls];
  out[i] = canonicalJson(ent);
  return out;
}

export const TAMPERS: Tamper[] = [
  {
    id: "outsider",
    title: "Change one encrypted vote",
    who: "Someone who can edit the published files but holds no keys.",
    apply: (e) => ({ entries: bumpVote(lines(e)).join("\n") + "\n", checkpoints: e.board.export().checkpoints }),
    expect: "board.checkpoints",
  },
  {
    id: "insider",
    title: "Change a vote and re-sign the record",
    who: "An insider who also holds the record operator's signing key.",
    apply: (e) => {
      const ls = bumpVote(lines(e));
      return { entries: ls.join("\n") + "\n", checkpoints: resign(e, ls) };
    },
    expect: "ballots.valid",
  },
  {
    id: "officer",
    title: "Move votes in the published result",
    who: "An insider holding both the officer's and the operator's keys.",
    apply: (e) => {
      const ls = lines(e);
      const i = ls.findIndex((l) => l.includes('"type":"result"'));
      const ent = JSON.parse(ls[i]);
      const { signature: _s, signer: _r, ...body } = ent.body as Body;
      const counts = body.counts as { option_id: string; votes: number }[];
      counts[0].votes += 3;
      counts[1].votes -= 3;
      ent.body = e.officer.signBody(body as Body);
      ls[i] = canonicalJson(ent as Json);
      return { entries: ls.join("\n") + "\n", checkpoints: resign(e, ls) };
    },
    expect: "tally.results",
  },
];

