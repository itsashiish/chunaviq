// Web Worker: runs voter-device encryption, ballot-box checks, finalization, mixing and the
// verifier's checks off the UI thread.
import { encryptBallot, makeLink, precheck } from "./ballot";
import { gPow, PublicKey } from "./crypto";
import { finalizeOne, mixBatch, type FinalJob, type MixJob } from "./election";
import { verifyBallot, verifyFinalItem, verifyMixBatch, type FinalCheck, type MixCheck, type VerifyCtx } from "./verifier";
import type { Json } from "./encoding";

export type WireCtx = VerifyCtx;
export type Kind = "prepare" | "precheck" | "finalize" | "mix" | "vballot" | "vfinal" | "vmix";
export type Msg = { id: number; kind: Kind; ctx: WireCtx; items: unknown[] };

const pks = new Map<string, PublicKey>();
const pkOf = (K: string) => {
  if (!pks.has(K)) pks.set(K, new PublicKey(BigInt("0x" + K)));
  return pks.get(K)!;
};

/** Message handler, exported so tests can run the exact worker logic in-thread. */
export function handle(m: Msg, post: (data: unknown) => void): void {
  const out: unknown[] = [];
  const pk = pkOf(m.ctx.K);
  const box = { pk, mh: m.ctx.mh, eid: m.ctx.eid, options: m.ctx.options };
  m.items.forEach((it, i) => {
    switch (m.kind) {
      case "prepare": {
        const j = it as { cons: string; choice: string; t: string };
        const t = BigInt("0x" + j.t);
        const prep = encryptBallot(pk, m.ctx.mh, m.ctx.eid, j.cons, m.ctx.options[j.cons], j.choice, t);
        const T = gPow(t);
        out.push({ ballot: prep.ballot, tag: T.toString(16), link: makeLink(pk, m.ctx.mh, prep, T) });
        break;
      }
      case "precheck":
        out.push(precheck(it, box));
        break;
      case "finalize":
        out.push(finalizeOne(pk, m.ctx.mh, it as FinalJob));
        break;
      case "mix":
        out.push(mixBatch(pk, m.ctx.mh, it as MixJob));
        break;
      case "vballot":
        out.push(verifyBallot(it as Record<string, Json>, m.ctx));
        break;
      case "vfinal":
        out.push(verifyFinalItem(it as FinalCheck, m.ctx));
        break;
      case "vmix":
        out.push(verifyMixBatch(it as MixCheck, m.ctx));
        break;
    }
    post({ id: m.id, progress: i + 1 });
  });
  post({ id: m.id, done: out });
}

if (typeof WorkerGlobalScope !== "undefined" && self instanceof WorkerGlobalScope) {
  self.onmessage = (ev: MessageEvent<Msg>) => handle(ev.data, (d) => (self as unknown as Worker).postMessage(d));
}
