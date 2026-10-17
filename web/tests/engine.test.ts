import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { modpow, FixedBase, randScalar, fromHex } from "../src/engine/bigint";
import { canonicalJson, hashToScalar } from "../src/engine/encoding";
import { G, P, Q, PublicKey, disjProve, disjVerify, gPow, rand } from "../src/engine/crypto";
import { MerkleTree, consistencyProof, leafHash, mth, verifyConsistency, verifyInclusion } from "../src/engine/merkle";
import { DemoElection, CONSTITUENCY } from "../src/engine/election";
import { Rejected, checkCode, selectionContext, trackingCode } from "../src/engine/ballot";
import { verifyRecord, verifyReceipt } from "../src/engine/verifier";

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

describe("byte-level compatibility with the Python implementation", () => {
  it.runIf(hasPython)("group constants and hash-to-scalar match", () => {
    const out = py(`
from chunaviq.crypto import params as P
from chunaviq.crypto.encoding import hash_to_scalar, canonical_json
print(format(P.P_2048,'x')); print(format(P.Q_2048,'x')); print(format(P.G_2048,'x'))
print(format(hash_to_scalar(P.Q_2048, "selection-0or1", ["mh", "selection", "SYN-AC-01", "C1", "ab"*32], 0, 1, 2**300, "x"), 'x'))
print(canonical_json({"b": [1, "\\u00e9 \\n"], "a": {"z": None, "y": True}}).decode())`).split("\n");
    expect(out[0]).toBe(P.toString(16));
    expect(out[1]).toBe(Q.toString(16));
    expect(out[2]).toBe(G.toString(16));
    expect(hashToScalar(Q, "selection-0or1", ["mh", "selection", "SYN-AC-01", "C1", "ab".repeat(32)], 0n, 1n, 2n ** 300n, "x").toString(16)).toBe(out[3]);
    expect(canonicalJson({ b: [1, "é \n"], a: { z: null, y: true } })).toBe(out[4]);
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
      expect(disjVerify(pk, { alpha: P - ct.alpha, beta: ct.beta }, pr, ["c"])).toBe(false);
    }
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

  it("runs, rejects attacks, tallies correctly and self-verifies", async () => {
    e = await DemoElection.create({ eligible: 14, rsaBits: 3072 });
    const truth: Record<string, number> = { C1: 0, C2: 0, C3: 0, NOTA: 0 };
    const choices = ["C1", "C2", "C3", "NOTA", "C1", "C2", "C1", "C1", "C3", "NOTA"];
    const devices = choices.map((c, i) => {
      const d = e.device(`syn-v-${String(i + 1).padStart(7, "0")}`);
      d.obtainCredential();
      e.submit(d.prepare(c).ballot);
      truth[c]++;
      return d;
    });
    const code = (f: () => unknown) => {
      try {
        f();
        return "ACCEPTED";
      } catch (x) {
        return (x as Rejected).code;
      }
    };
    expect(code(() => e.submit(devices[0].prepare("C2").ballot))).toBe("CREDENTIAL_ALREADY_USED");
    expect(code(() => devices[1].obtainCredential())).toBe("ALREADY_ISSUED");
    expect(code(() => e.device("syn-v-9999999"))).toBe("NOT_ON_ROLL");
    const marked = { ...devices[2].prepare("C1").ballot, marker: "voter-3" };
    expect(checkCode(marked, e.boxCtx)).toBe("MALFORMED");
    const victim = e.board.of("ballot")[0].body.ballot as never as { selections: unknown[]; limit_proof: unknown };
    const fresh = e.device("syn-v-0000011");
    fresh.obtainCredential();
    const copy = { ...fresh.prepare("C3").ballot, selections: victim.selections, limit_proof: victim.limit_proof } as never;
    expect(checkCode(copy, e.boxCtx)).toBe("BAD_SELECTION_PROOF");
    const tok = (copy as { credential: { token: string } }).credential.token;
    expect(selectionContext(e.mh, CONSTITUENCY, "C1", tok)[4]).toBe(tok);

    const receipt = e.board.receipt(e.board.of("ballot")[3].seq);
    e.close();
    const res = e.tally([1]);
    expect(res.counts).toEqual(truth);
    const { entries, checkpoints } = e.board.export();
    expect(verifyReceipt(entries, checkpoints, receipt)).toBe(true);
    expect(receipt.tracking_code).toBe(trackingCode(e.board.of("ballot")[3].body.ballot as never));
    const rep = await verifyRecord(entries, checkpoints, { expectManifestHash: e.mh });
    expect(rep.checks.filter((c) => c.status === "FAIL")).toEqual([]);
    expect(rep.status).toBe("VERIFIED");
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
    const e = await DemoElection.create({ eligible: 20, rsaBits: 3072 });
    const me = e.device("syn-v-0000001");
    me.obtainCredential();
    e.submit(me.prepare("C2").ballot);
    for (let i = 2; i <= 6; i++) {
      const d = e.device(`syn-v-${String(i).padStart(7, "0")}`);
      d.obtainCredential();
      e.submit(d.prepare(i % 2 ? "C1" : "NOTA").ballot);
    }
    for (const a of ATTACKS) {
      let code = "ACCEPTED";
      try {
        a.run(e, me);
      } catch (x) {
        code = (x as Rejected).code;
      }
      expect(Object.keys(a.explain), a.id).toContain(code);
    }
    e.close();
    e.tally([1]);
    for (const t of TAMPERS) {
      const { entries, checkpoints } = t.apply(e);
      const rep = await verifyRecord(entries, checkpoints);
      expect(rep.status, t.id).toBe("NOT VERIFIED");
      expect(rep.checks.find((c) => c.id === t.expect)?.status, t.id).toBe("FAIL");
    }
  });
});
