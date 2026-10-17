// A small pool of module workers; splits a list of items across them and reports progress.
import type { Json } from "./encoding";
import type { WireCtx } from "./worker";
import type { BallotChecker } from "./verifier";

type Kind = "prepare" | "boxCheck" | "verify";

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
    const chunk = Math.ceil(items.length / n) || 1;
    const parts = this.workers.map((_, i) => items.slice(i * chunk, (i + 1) * chunk));
    const done = Array.from({ length: n }, () => 0);
    return Promise.all(
      parts.map(
        (part, i) =>
          new Promise<T[]>((resolve, reject) => {
            if (!part.length) return resolve([]);
            const id = this.nextId++;
            const w = this.workers[i];
            const onMsg = (ev: MessageEvent) => {
              if (ev.data.id !== id) return;
              if ("progress" in ev.data) {
                done[i] = ev.data.progress;
                onProgress?.(done.reduce((a, b) => a + b, 0));
              } else {
                w.removeEventListener("message", onMsg);
                done[i] = part.length;
                onProgress?.(done.reduce((a, b) => a + b, 0));
                resolve(ev.data.done as T[]);
              }
            };
            w.addEventListener("message", onMsg);
            w.addEventListener("error", reject, { once: true });
            w.postMessage({ id, kind, ctx, items: part });
          }),
      ),
    ).then((rs) => rs.flat());
  }
  checker(): BallotChecker {
    return (ballots: Record<string, Json>[], ctx, onProgress) => this.run<string | null>("verify", ctx, ballots, onProgress);
  }
  terminate() {
    this.workers.forEach((w) => w.terminate());
  }
}
