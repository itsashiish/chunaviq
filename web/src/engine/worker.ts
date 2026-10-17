// Web Worker: runs voter-device encryption, ballot-box checks and verifier checks off the UI thread.
import { checkCode, encryptBallot } from "./ballot";
import { rsaFromJson } from "./blind";
import { PublicKey } from "./crypto";
import { verifyBallot, type VerifyCtx } from "./verifier";
import type { Json } from "./encoding";

export type WireCtx = VerifyCtx;
export type Msg =
  | { id: number; kind: "prepare"; ctx: WireCtx; items: { cons: string; choice: string; token: string; sig: string }[] }
  | { id: number; kind: "boxCheck" | "verify"; ctx: WireCtx; items: Record<string, Json>[] };

const pks = new Map<string, PublicKey>();
const pkOf = (K: string) => {
  if (!pks.has(K)) pks.set(K, new PublicKey(BigInt("0x" + K)));
  return pks.get(K)!;
};

/** Message handler, exported so tests can run the exact worker logic in-thread. */
export function handle(m: Msg, post: (data: unknown) => void): void {
  const out: unknown[] = [];
  const pk = pkOf(m.ctx.K);
  const boxCtx = { pk, mh: m.ctx.mh, eid: m.ctx.eid, options: m.ctx.options, issuers: Object.fromEntries(Object.entries(m.ctx.issuers).map(([c, k]) => [c, rsaFromJson(k)])) };
  m.items.forEach((it, i) => {
    if (m.kind === "prepare") {
      const j = it as { cons: string; choice: string; token: string; sig: string };
      out.push(encryptBallot(pk, m.ctx.mh, m.ctx.eid, j.cons, m.ctx.options[j.cons], j.choice, j.token, j.sig).ballot);
    } else if (m.kind === "boxCheck") out.push(checkCode(it, boxCtx));
    else out.push(verifyBallot(it as Record<string, Json>, m.ctx));
    if (i % 4 === 3) post({ id: m.id, progress: i + 1 });
  });
  post({ id: m.id, done: out });
}

if (typeof WorkerGlobalScope !== "undefined" && self instanceof WorkerGlobalScope) {
  self.onmessage = (ev: MessageEvent<Msg>) => handle(ev.data, (d) => (self as unknown as Worker).postMessage(d));
}
