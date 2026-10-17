// Cheating attempts the demo lets visitors try (protocol v2). Each must be refused.
import { bytesToHex, toHex } from "./bigint";
import { bodyDigest, encryptBallot, limitContext, linkContext, selectionContext, tagContext, trackingCode, type Ballot, type Submission } from "./ballot";
import {
  addCts,
  cpProve,
  cpToJson,
  ctToJson,
  disjProve,
  disjToJson,
  div,
  fastFor,
  G,
  gPow,
  linkStatement,
  P,
  Q,
  rand,
  sigmaProve,
  tagStatement,
} from "./crypto";
import { DemoElection, liveCapture, VoterDevice } from "./election";
import { canonicalJson, sha256Hex, type Json } from "./encoding";
import { MerkleTree } from "./merkle";
import type { Body } from "./sign";

const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));

export type Attack = { id: string; title: string; how: string; run: (e: DemoElection, me: VoterDevice) => void; explain: Record<string, string> };

export const ATTACKS: Attack[] = [
  {
    id: "insider-revote",
    title: "Vote for someone else, from inside",
    how: "You run the ballot box, so you know a voter's tag. You build a valid-looking revote under it, without the secret on their phone.",
    run: (e, me) => void e.submit(forgeUnderTag(e, me)),
    explain: { BAD_TAG_PROOF: "Every ballot proves knowledge of the secret behind its tag. Knowing the tag is not enough; only the voter's device has the secret." },
  },
  {
    id: "unregistered",
    title: "Vote without registering",
    how: "Your device invents a tag and votes with it, skipping identity checks.",
    run: (e) => {
      const fake = new VoterDevice(e.elig.people.values().next().value!, e);
      fake.t = rand();
      fake.T = gPow(fake.t);
      void e.submit(fake.submission(fake.prepare("C1")));
    },
    explain: { UNREGISTERED_TAG: "The ballot box only accepts tags the eligibility authority registered after checking Aadhaar or PAN." },
  },
  {
    id: "overvote",
    title: "Vote for two candidates",
    how: "Two boxes encrypt a 1. Each still proves it holds a 0 or a 1.",
    run: (e, me) => {
      const sub = me.submission(me.prepare("C1"));
      const b = sub.ballot;
      const ta = b.tag.ciphertext.alpha;
      for (const j of [0, 1]) {
        const r = rand();
        const ct = e.pk!.encrypt(1n, r);
        b.selections[j].ciphertext = ctToJson(ct);
        b.selections[j].proof = disjToJson(disjProve(e.pk!, ct, 1, r, selectionContext(e.mh, b.constituency, b.selections[j].option_id, ta)));
      }
      b.limit_proof.v = toHex((BigInt("0x" + b.limit_proof.v) + 1n) % Q);
      void e.submit(sub);
    },
    explain: { BAD_LIMIT_PROOF: "Every ballot must prove its boxes add up to exactly one vote. Two votes cannot produce that proof." },
  },
  {
    id: "copy",
    title: "Copy someone else's vote",
    how: "You paste another voter's encrypted choices into your own ballot, to vote the way they did.",
    run: (e, me) => {
      const victim = e.board.of("ballot").find((x) => e.tagOf(x.body.tracking_code as string) !== toHex(me.T!))!.body.ballot as unknown as Ballot;
      const sub = me.submission(me.prepare("C3"));
      sub.ballot.selections = clone(victim.selections);
      sub.ballot.limit_proof = clone(victim.limit_proof);
      void e.submit(sub);
    },
    explain: { BAD_SELECTION_PROOF: "Each proof is tied to the ballot's own encrypted tag, so copied proofs fail." },
  },
  {
    id: "resubmit",
    title: "Claim someone else's ballot as yours",
    how: "You resend another voter's whole ballot, saying it is under your tag.",
    run: (e, me) => {
      const victim = e.board.of("ballot").find((x) => e.tagOf(x.body.tracking_code as string) !== toHex(me.T!))!.body.ballot as unknown as Ballot;
      const mine = me.submission(me.prepare("C1"));
      void e.submit({ ballot: clone(victim), tag: mine.tag, link: mine.link });
    },
    explain: { BAD_TAG_LINK: "Your device must prove, privately to the ballot box, which tag a ballot is under. It cannot for someone else's ballot." },
  },
  {
    id: "mark",
    title: "Hide a marker in your ballot",
    how: "You add a note so a vote buyer can find your ballot in the public record.",
    run: (e, me) => {
      const sub = me.submission(me.prepare("C1"));
      (sub.ballot.selections[0].ciphertext as Record<string, string>).marker = "paid-voter-17";
      void e.submit(sub);
    },
    explain: { MALFORMED: "Ballots must match the exact format. Any extra field is refused, so ballots cannot be tagged." },
  },
  {
    id: "pan-only",
    title: "Register as someone using only their PAN",
    how: "You know a voter's PAN, name and birth date (all printed on the card) but not their phone or face.",
    run: (e) => {
      const p = [...e.elig.people.values()].find((x) => x.panRef && !e.elig.registrations.has(x.voterId))!;
      const txn = e.elig.panStart(p.panRef!, p.name, p.dob);
      e.elig.panFinish(p.panRef!, txn, "000000", liveCapture(p.face, false));
    },
    explain: {
      OTP_MISMATCH: "PAN alone proves nothing about who is holding the phone. The code goes to the mobile number on the electoral roll.",
      FACE_MISMATCH: "PAN registration also needs a face match against the roll photograph.",
    },
  },
  {
    id: "impostor",
    title: "Pass a face check as someone else",
    how: "You try Aadhaar face authentication for another voter with your own face.",
    run: (e) => {
      const p = [...e.elig.people.values()].find((x) => !e.elig.registrations.has(x.voterId))!;
      e.elig.aadhaarFace(p.aadhaarRef, liveCapture(p.face, false));
    },
    explain: { FACE_MISMATCH: "The face does not match the one UIDAI holds for that Aadhaar number." },
  },
];

/** The insider forgery: a ballot that encrypts a known tag T, with valid selection and limit proofs, and a fake tag proof. */
function forgeUnderTag(e: DemoElection, victim: VoterDevice): Submission {
  const pk = e.pk!;
  const T = victim.T!;
  const r = rand();
  const tct = { alpha: gPow(r), beta: (T * pk.kPow(r)) % P };
  const ta = toHex(tct.alpha);
  const nonces: bigint[] = [];
  const cts = e.optionIds.map((oid, j) => {
    const rr = rand();
    nonces.push(rr);
    return { oid, ct: pk.encrypt(j === 0 ? 1n : 0n, rr), m: (j === 0 ? 1 : 0) as 0 | 1, rr };
  });
  const sels = cts.map(({ oid, ct, m, rr }) => ({ option_id: oid, ciphertext: ctToJson(ct), proof: disjToJson(disjProve(pk, ct, m, rr, selectionContext(e.mh, victim.constituency, oid, ta))) }));
  const agg = addCts(cts.map((x) => x.ct));
  const lp = cpToJson(cpProve(nonces.reduce((a, b) => (a + b) % Q, 0n), pk.K, agg.alpha, div(agg.beta, G), "contest-limit", limitContext(e.mh, victim.constituency, ta), (x) => pk.kPow(x)));
  const proof = sigmaProve(tagStatement(pk.K, tct.alpha, tct.beta), [r, rand()], "ballot-tag", tagContext(e.mh, victim.constituency, bodyDigest(sels, lp)), fastFor(pk));
  const ballot: Ballot = { election_id: e.electionId, constituency: victim.constituency, tag: { ciphertext: ctToJson(tct), proof }, selections: sels, limit_proof: lp };
  const link = sigmaProve(linkStatement(pk.K, tct.alpha, tct.beta, T), [r], "tag-link", linkContext(e.mh, trackingCode(ballot)), fastFor(pk));
  return { ballot, tag: toHex(T), link };
}

export { encryptBallot };

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

function resignedEntry(ls: string[], type: string, edit: (body: Body) => void, sign: (b: Body) => Body): string[] {
  const i = ls.findIndex((l) => l.includes(`"type":"${type}"`));
  const ent = JSON.parse(ls[i]);
  const { signature: _s, signer: _r, ...body } = ent.body as Body;
  edit(body as Body);
  ent.body = sign(body as Body);
  const out = [...ls];
  out[i] = canonicalJson(ent as Json);
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
    id: "flag",
    title: "Count a ballot the voter replaced",
    who: "The ballot box, after polls close: it flips one ballot's 'counts' flag and re-signs.",
    apply: (e) => {
      const ls = resignedEntry(
        lines(e),
        "finalization",
        (b) => {
          const it = (b.items as Body[])[0];
          const f = it.flag as { alpha: string; beta: string };
          f.beta = toHex((BigInt("0x" + f.beta) * G) % P);
        },
        (b) => e.board.operator.signBody(b),
      );
      return { entries: ls.join("\n") + "\n", checkpoints: resign(e, ls) };
    },
    expect: "finalization.proofs",
  },
  {
    id: "mixer",
    title: "Swap a ballot while shuffling",
    who: "A trustee who mixes: it replaces one row with a copy of another and signs its output.",
    apply: (e) => {
      const ls = resignedEntry(
        lines(e),
        "shuffle",
        (b) => {
          const rows = b.rows as Json[];
          rows[0] = clone(rows[1]);
        },
        (b) => e.trustees.find((t) => t.trustee.index === (b.mixer as number))!.key.signBody(b),
      );
      return { entries: ls.join("\n") + "\n", checkpoints: resign(e, ls) };
    },
    expect: "mixing.shuffles",
  },
  {
    id: "officer",
    title: "Move votes in the published result",
    who: "An insider holding both the officer's and the operator's keys.",
    apply: (e) => {
      const ls = resignedEntry(
        lines(e),
        "result",
        (b) => {
          const counts = b.counts as { option_id: string; votes: number }[];
          counts[0].votes += 3;
          counts[1].votes -= 3;
        },
        (b) => e.officer.signBody(b),
      );
      return { entries: ls.join("\n") + "\n", checkpoints: resign(e, ls) };
    },
    expect: "tally.results",
  },
];
