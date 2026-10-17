import type { Check } from "../engine/verifier";

export function Symbol({ kind }: { kind: string }) {
  const s = { fill: "none", stroke: "#1b1d21", strokeWidth: 3 } as const;
  return (
    <svg className="sym" viewBox="0 0 40 40" aria-hidden="true">
      {kind === "circle" && <circle cx="20" cy="20" r="13" {...s} />}
      {kind === "triangle" && <path d="M20 6 34 32H6z" {...s} strokeLinejoin="round" />}
      {kind === "square" && <rect x="8" y="8" width="24" height="24" {...s} />}
      {kind === "nota" && (
        <g {...s}>
          <rect x="7" y="7" width="26" height="26" rx="2" />
          <path d="M12 12l16 16M28 12 12 28" />
        </g>
      )}
    </svg>
  );
}

/** Left index fingertip with the indelible-ink line drawn across the nail fold. */
export function InkMark() {
  return (
    <svg className="finger" viewBox="0 0 150 190" role="img" aria-label="Violet indelible-ink mark on a fingernail">
      <path className="skin" d="M40 190V70c0-30 16-58 35-58s35 28 35 58v120" />
      <path className="nail" d="M53 74c0-22 10-40 22-40s22 18 22 40v26c0 6-10 10-22 10s-22-4-22-10z" />
      <path className="ink" d="M48 106c18 8 36 8 54 0" />
    </svg>
  );
}

export function Progress({ done, total, label }: { done: number; total: number; label: string }) {
  const pct = total ? Math.round((100 * done) / total) : 0;
  return (
    <div>
      <div className="progress" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={total} aria-valuenow={done}>
        <span style={{ width: `${pct}%` }} />
      </div>
      <div className="status">
        {label}: {done} of {total}
      </div>
    </div>
  );
}

export function Checks({ checks }: { checks: Check[] }) {
  return (
    <ul className="plain">
      {checks.map((c) => (
        <li key={c.id}>
          <span className={`mark ${c.status}`}>{c.status === "PASS" ? "Pass" : c.status === "WARN" ? "Note" : "Fail"}</span>
          <span>
            {c.title}
            {c.status !== "PASS" && c.detail && (
              <>
                <br />
                <small className="lede">{c.detail}</small>
              </>
            )}
          </span>
        </li>
      ))}
    </ul>
  );
}

export const short = (h: string, n = 10) => (h.length > 2 * n ? `${h.slice(0, n)}…${h.slice(-6)}` : h);

export const tick = () => new Promise<void>((r) => setTimeout(r, 0));
