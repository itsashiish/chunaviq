import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { modpow, FixedBase, randScalar, fromHex } from "../src/engine/bigint";
import { canonicalJson, hashToScalar } from "../src/engine/encoding";
import {
  G,
  P,
  Q,
  PublicKey,
  disjProve,
  disjVerify,
  dvBranches,
  fastFor,
  finalizeBranches,
  gPow,
  rand,
  shuffleAndProve,
  sigmaProve,
  sigmaProveOr,
  sigmaVerify,
  sigmaVerifyOr,
  tagStatement,
  generators,
} from "../src/engine/crypto";
import { MerkleTree, consistencyProof, leafHash, mth, verifyConsistency, verifyInclusion } from "../src/engine/merkle";
import { DemoElection, CONSTITUENCY } from "../src/engine/election";
import { Rejected, precheck, trackingCode } from "../src/engine/ballot";
import { shuffleOk, verifyRecord, verifyReceipt } from "../src/engine/verifier";

const ROOT = join(__dirname, "..", "..");
const PY = process.env.PYTHON ?? (existsSync(join(ROOT, ".venv/bin/python")) ? join(ROOT, ".venv/bin/python") : "python3");
const py = (code: string) => execFileSync(PY, ["-c", code], { cwd: ROOT, env: { ...process.env, PYTHONPATH: join(ROOT, "src") } }).toString().trim();
const hasPython = (() => {
  try {
    py("import chunaviq");
    return true;
  } catch {
    return false;
  }
})();

const code = (f: () => unknown) => {
  try {
    f();
    return "ACCEPTED";
  } catch (x) {
    return (x as Rejected).code ?? (x as Error).message;
  }
};

describe("byte-level compatibility with the Python implementation", () => {
  it.runIf(hasPython)("group constants, hash-to-scalar (including bytes) and shuffle generators match", () => {
    const out = py(`
from chunaviq.crypto import params as P
from chunaviq.crypto.encoding import hash_to_scalar, canonical_json
from chunaviq.crypto.group import get_group
from chunaviq.crypto.shuffle import generators
print(format(P.P_2048,'x')); print(format(P.Q_2048,'x')); print(format(P.G_2048,'x'))
print(format(hash_to_scalar(P.Q_2048, "selection-0or1", ["mh", "selection", "SYN-AC-01", "C1", "ab"*32], 0, 1, 2**300, "x", b"\\x00\\x01"), 'x'))
print(canonical_json({"b": [1, "\\u00e9 \\n"], "a": {"z": None, "y": True}}).decode())
print(format(generators(get_group("CHUNAVIQ-2048-256-V1"), 2)[2], 'x'))`).split("\n");
    expect(out[0]).toBe(P.toString(16));
    expect(out[1]).toBe(Q.toString(16));
    expect(out[2]).toBe(G.toString(16));
    expect(hashToScalar(Q, "selection-0or1", ["mh", "selection", "SYN-AC-01", "C1", "ab".repeat(32)], 0n, 1n, 2n ** 300n, "x", new Uint8Array([0, 1])).toString(16)).toBe(out[3]);
    expect(canonicalJson({ b: [1, "é \n"], a: { z: null, y: true } })).toBe(out[4]);
    expect(generators(2)[2].toString(16)).toBe(out[5]);
  });
});

describe("arithmetic and proofs", () => {
  it("modpow and fixed-base agree with naive exponentiation", () => {
    const fb = new FixedBase(G, P, 256);
    for (let i = 0; i < 5; i++) {
      const e = randScalar(Q);
      expect(fb.pow(e)).toBe(modpow(G, e, P));
    }
    expect(modpow(G, Q, P)).toBe(1n);
  });
  it("0/1 proofs are complete, sound against tampering and bound to context", () => {
    const pk = new PublicKey(gPow(rand()));
    for (const m of [0, 1] as const) {
      const r = rand();
      const ct = pk.encrypt(BigInt(m), r);
      const pr = disjProve(pk, ct, m, r, ["c"]);
      expect(disjVerify(pk, ct, pr, ["c"])).toBe(true);
      expect(disjVerify(pk, ct, pr, ["d"])).toBe(false);
      expect(disjVerify(pk, ct, { ...pr, v0: (pr.v0 + 1n) % Q }, ["c"])).toBe(false);
    }
  });
  it("tag proof needs the tag secret; OR-proofs and designated-verifier proofs behave", () => {
    const pk = new PublicKey(gPow(rand()));
    const t = rand();
    const r = rand();
    const a = gPow(r);
    const b = (gPow(t) * pk.kPow(r)) % P;
    const pr = sigmaProve(tagStatement(pk.K, a, b), [r, t], "ballot-tag", ["x"], fastFor(pk));
    expect(sigmaVerify(tagStatement(pk.K, a, b), pr, "ballot-tag", ["x"], fastFor(pk))).toBe(true);
    expect(sigmaVerify(tagStatement(pk.K, a, b), sigmaProve(tagStatement(pk.K, a, b), [r, rand()], "ballot-tag", ["x"], fastFor(pk)), "ballot-tag", ["x"])).toBe(false);
    for (const f of [0, 1] as const) {
      const votes = [pk.encrypt(1n, rand()), pk.encrypt(0n, rand())];
      const u = rand();
      const F = { alpha: gPow(u), beta: (gPow(BigInt(f)) * pk.kPow(u)) % P };
      const ws = [rand(), rand()];
      const masked = votes.map((v, i) => (f ? { alpha: (v.alpha * gPow(ws[i])) % P, beta: (v.beta * pk.kPow(ws[i])) % P } : { alpha: gPow(ws[i]), beta: pk.kPow(ws[i]) }));
      const br = finalizeBranches(pk.K, F, votes, masked);
      expect(sigmaVerifyOr(br, sigmaProveOr(br, f, [u, ...ws], "finalize", ["c"]), "finalize", ["c"])).toBe(true);
      expect(sigmaVerifyOr(br, sigmaProveOr(br, 1 - f, [u, ...ws], "finalize", ["c"]), "finalize", ["c"])).toBe(false);
      const T = gPow(t);
      const fake = sigmaProveOr(dvBranches(pk.K, F, T), 1, [t], "dv", []);
      expect(sigmaVerifyOr(dvBranches(pk.K, F, T), fake, "dv", [])).toBe(true); // the voter can always make one
    }
  });
  it("shuffle proofs verify with the independent verifier and catch a swapped row", () => {
    const pk = new PublicKey(gPow(rand()));
    const rows = Array.from({ length: 6 }, (_, i) => [pk.encrypt(BigInt(i % 2), rand()), pk.encrypt(1n, rand())]);
    const { out, proof } = shuffleAndProve(pk, rows, ["ctx"]);
    expect(shuffleOk(pk.K, rows, out, proof as never, ["ctx"])).toBe(true);
    expect(shuffleOk(pk.K, rows, out, proof as never, ["other"])).toBe(false);
    const bad = out.map((r) => [...r]);
    bad[0] = [...bad[1]];
    expect(shuffleOk(pk.K, rows, bad, proof as never, ["ctx"])).toBe(false);
  });
  it("Merkle tree matches RFC 6962 reference; inclusion and consistency verify", () => {
    for (const n of [1, 2, 3, 5, 8, 13, 33]) {
      const t = new MerkleTree();
      const data = Array.from({ length: n }, (_, i) => new Uint8Array([i]));
      data.forEach((d) => t.append(d));
      const leaves = data.map(leafHash);
      expect(t.root()).toEqual(mth(leaves));
      for (let i = 0; i < n; i++) expect(verifyInclusion(leaves[i], i, n, t.inclusionProof(i), t.root())).toBe(true);
      for (let m = 1; m <= n; m++) expect(verifyConsistency(m, n, mth(leaves.slice(0, m)), t.root(), consistencyProof(leaves, m))).toBe(true);
    }
  });
  it("hex parsing is canonical", () => {
    for (const bad of ["", "0a", "A", "x1"]) expect(() => fromHex(bad)).toThrow();
  });
});

describe("browser election end to end", () => {
  let e: DemoElection;
  const out = join(__dirname, "..", ".record-test");

  it("registers, votes, revotes, overrides, mixes, tallies correctly and self-verifies", async () => {
    e = await DemoElection.create({ eligible: 16 });
    const truth: Record<string, number> = { C1: 0, C2: 0, C3: 0, NOTA: 0 };
    const choices = ["C1", "C2", "C3", "NOTA", "C1", "C2", "C1", "C1", "C3", "NOTA"];
    const methods = ["aadhaar-otp", "aadhaar-face", "pan"] as const;
    const devices = choices.map((c, i) => {
      const d = e.device(`syn-v-${String(i + 1).padStart(7, "0")}`);
      d.register(d.person.panRef ? methods[i % 3] : "aadhaar-otp");
      const r = e.submit(d.submission(d.prepare(c)));
      d.cast.push(r.tracking_code);
      return d;
    });
    // voter 1 changes their mind; voter 2 re-registers a new phone and votes again; voter 3 votes at the booth
    const r1 = e.submit(devices[0].submission(devices[0].prepare("NOTA")));
    devices[0].cast.push(r1.tracking_code);
    expect(r1.revote).toBe(2);
    devices[1].register("aadhaar-otp");
    const r2 = e.submit(devices[1].submission(devices[1].prepare("C3")));
    devices[1].cast.push(r2.tracking_code);
    const final = [...choices];
    final[0] = "NOTA";
    final[1] = "C3";
    final.forEach((c, i) => i !== 2 && truth[c]++);

    const first = e.board.of("ballot")[0];
    const before = e.board.of("ballot").length;
    expect(e.submit({ ballot: first.body.ballot as never, tag: e.tagOf(first.body.tracking_code as string)!, link: {} as never }).duplicate_submission).toBe(true);
    expect(e.board.of("ballot").length).toBe(before);
    expect(code(() => e.device("syn-v-9999999"))).toBe("NOT_ON_ROLL");
    const marked = devices[3].submission(devices[3].prepare("C1"));
    (marked.ballot as unknown as Record<string, unknown>).marker = "voter-3";
    expect(precheck(marked, e.boxCtx)).toBe("REJECT:MALFORMED");

    const receipt = e.board.receipt(e.board.of("ballot")[3].seq);
    e.close(undefined, [devices[2].voterId]);
    await e.finalize();
    const res = await e.mixAndTally([1]);
    expect(res.counts).toEqual(truth);
    expect(res.cast).toBe(12);
    // the voter's private check: my latest ballot is the one counted; my replaced one is not
    const dv = e.dvProof(devices[0].cast[1])!;
    expect(devices[0].checkCounted(dv.flag, dv.proof)).toBe(true);
    expect(e.dvProof(devices[0].cast[0])).toBeNull();
    const { entries, checkpoints } = e.board.export();
    expect(verifyReceipt(entries, checkpoints, receipt)).toBe(true);
    expect(receipt.tracking_code).toBe(trackingCode(e.board.of("ballot")[3].body.ballot as never));
    const rep = await verifyRecord(entries, checkpoints, { expectManifestHash: e.mh });
    expect(rep.checks.filter((c) => c.status === "FAIL")).toEqual([]);
    expect(rep.status).toBe("VERIFIED");
    expect((rep.results[CONSTITUENCY] as { counts: unknown }).counts).toEqual(truth);
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, "entries.jsonl"), entries);
    writeFileSync(join(out, "checkpoints.jsonl"), checkpoints);
    writeFileSync(join(out, "manifest_hash.txt"), e.mh);
  });

  it.runIf(hasPython)("the Python verifier accepts the browser-made record", () => {
    const mh = readFileSync(join(out, "manifest_hash.txt"), "utf8");
    const res = py(`
from chunaviq_verify import verify_record
r = verify_record(${JSON.stringify(out)}, expect_manifest_hash=${JSON.stringify(mh)}).to_dict()
print(r["status"]); print(r["failures"]); print([c["id"] for c in r["checks"] if c["status"] != "PASS"])`).split("\n");
    expect(res[0]).toBe("VERIFIED");
    expect(res[1]).toBe("0");
    expect(res[2]).toBe("['lifecycle.early_close']");
  });

  it("the TypeScript verifier catches tampering", async () => {
    const { entries, checkpoints } = e.board.export();
    const lines = entries.trimEnd().split("\n");
    const i = lines.findIndex((l) => l.includes('"type":"ballot"'));
    const ent = JSON.parse(lines[i]);
    ent.body.ballot.selections[0].ciphertext.beta = ((fromHex(ent.body.ballot.selections[0].ciphertext.beta) * G) % P).toString(16);
    lines[i] = canonicalJson(ent);
    const rep = await verifyRecord(lines.join("\n") + "\n", checkpoints);
    expect(rep.status).toBe("NOT VERIFIED");
    expect(rep.checks.find((c) => c.id === "board.checkpoints")?.status).toBe("FAIL");
  });
});

describe("interop: TypeScript verifier on a Python-made record", () => {
  const rec = process.env.PY_RECORD;
  it.runIf(!!rec)("verifies", async () => {
    const rep = await verifyRecord(readFileSync(join(rec!, "entries.jsonl"), "utf8"), readFileSync(join(rec!, "checkpoints.jsonl"), "utf8"));
    expect(rep.checks.filter((c) => c.status === "FAIL")).toEqual([]);
  });
});

describe("attack lab and tamper lab", () => {
  it("every attack is refused with the documented reason; every tamper is caught", async () => {
    const { ATTACKS, TAMPERS } = await import("../src/engine/attacks");
    const e = await DemoElection.create({ eligible: 20 });
    const me = e.device("syn-v-0000001");
    me.register("aadhaar-otp");
    me.cast.push(e.submit(me.submission(me.prepare("C2"))).tracking_code);
    for (let i = 2; i <= 6; i++) {
      const d = e.device(`syn-v-${String(i).padStart(7, "0")}`);
      d.register("aadhaar-otp");
      e.submit(d.submission(d.prepare(i % 2 ? "C1" : "NOTA")));
    }
    e.submit(me.submission(me.prepare("C3"))); // a revote, so a superseded ballot exists
    for (const a of ATTACKS) {
      const c = code(() => a.run(e, me));
      expect(Object.keys(a.explain), a.id).toContain(c);
    }
    e.close();
    await e.finalize();
    await e.mixAndTally([1]);
    for (const t of TAMPERS) {
      const { entries, checkpoints } = t.apply(e);
      const rep = await verifyRecord(entries, checkpoints);
      expect(rep.status, t.id).toBe("NOT VERIFIED");
      expect(rep.checks.find((c) => c.id === t.expect)?.status, t.id).toBe("FAIL");
    }
  });
});
