// A small pool of module workers; splits a list of items across them and reports progress.
import type { FinalJob, FinalOut, MixJob, MixOut, Runner } from "./election";
import type { VerifyRunner } from "./verifier";
import type { Kind, WireCtx } from "./worker";

export class Pool {
  private workers: Worker[];
  private nextId = 1;
  constructor(size = Math.max(1, Math.min(8, (navigator.hardwareConcurrency || 4) - 1))) {
    this.workers = Array.from({ length: size }, () => new Worker(new URL("./worker.ts", import.meta.url), { type: "module" }));
  }
  get size() {
    return this.workers.length;
  }
  run<T>(kind: Kind, ctx: WireCtx, items: unknown[], onProgress?: (done: number) => void): Promise<T[]> {
    const n = this.workers.length;
    // round-robin, so expensive items (mixing batches) spread evenly across workers
    const parts: { idx: number[]; items: unknown[] }[] = this.workers.map(() => ({ idx: [], items: [] }));
    items.forEach((it, i) => {
      parts[i % n].idx.push(i);
      parts[i % n].items.push(it);
    });
    const done = Array.from({ length: n }, () => 0);
    const result: T[] = Array.from({ length: items.length });
    return Promise.all(
      parts.map(
        (part, w) =>
          new Promise<void>((resolve, reject) => {
            if (!part.items.length) return resolve();
            const id = this.nextId++;
            const worker = this.workers[w];
            const onMsg = (ev: MessageEvent) => {
              if (ev.data.id !== id) return;
              if ("progress" in ev.data) {
                done[w] = ev.data.progress;
                onProgress?.(done.reduce((a, b) => a + b, 0));
              } else {
                worker.removeEventListener("message", onMsg);
                (ev.data.done as T[]).forEach((r, j) => (result[part.idx[j]] = r));
                resolve();
              }
            };
            worker.addEventListener("message", onMsg);
            worker.addEventListener("error", reject, { once: true });
            worker.postMessage({ id, kind, ctx, items: part.items });
          }),
      ),
    ).then(() => result);
  }
  runner(ctx: WireCtx): Runner {
    return {
      finalize: (jobs: FinalJob[], p) => this.run<FinalOut>("finalize", ctx, jobs, p),
      mix: (jobs: MixJob[], p) => this.run<MixOut>("mix", ctx, jobs, p),
    };
  }
  verifier(): VerifyRunner {
    return {
      ballots: (items, ctx, p) => this.run("vballot", ctx, items, p),
      finals: (items, ctx, p) => this.run("vfinal", ctx, items, p),
      mixes: (items, ctx, p) => this.run("vmix", ctx, items, p),
    };
  }
  terminate() {
    this.workers.forEach((w) => w.terminate());
  }
}
