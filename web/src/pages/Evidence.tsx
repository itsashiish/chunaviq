// "Evidence": the published dress-rehearsal results and the national capacity model, loaded from /evidence/*.json.
import { useEffect, useState } from "react";

type Phase = {
  seconds: number;
  honest_sent: number;
  honest_recorded: number;
  honest_recorded_pct: number | null;
  honest_recorded_within_30s?: number;
  honest_recorded_within_30s_pct?: number | null;
  latency_s: { p50: number | null; p95: number | null; p99: number | null };
  attack_requests: Record<string, number>;
};
type Rehearsal = {
  profile: string;
  machine: { cores: number; os: string };
  software: { version: string; source_digest: string };
  config: { honest_rate_per_s: number; options: number };
  fraction_of_design_rate: number;
  design_rate_largest_seat_per_s: number;
  cores_for_design_rate_at_this_cost: number;
  phases: Record<string, Phase>;
  every_receipt_is_on_the_board: boolean;
  ballots_on_board: number;
  expensive_checks_run: number;
  verification: { status: string; failures: number; warnings: number };
  stage_seconds: Record<string, number>;
};
type CapRow = Record<string, number | string>;
type Capacity = { model: CapRow[] };

const fmt = (x: number | null | undefined, d = 2) => (x === null || x === undefined ? "-" : x >= 1000 ? Math.round(x).toLocaleString("en-IN") : x.toFixed(d));

function useJson<T>(url: string): T | null | "missing" {
  const [v, setV] = useState<T | null | "missing">(null);
  useEffect(() => {
    if (typeof fetch === "undefined") return setV("missing");
    fetch(url)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then(setV, () => setV("missing"));
  }, [url]);
  return v;
}

function RehearsalCard({ name, data }: { name: string; data: Rehearsal | null | "missing" }) {
  if (data === null) return <p className="meta">Loading {name}…</p>;
  if (data === "missing")
    return (
      <p className="meta">
        No published {name} run yet. Run <code>make rehearsal-peak</code> and publish it as described in <code>docs/dos-and-rehearsal.md</code>.
      </p>
    );
  const atk = Object.values(data.phases).reduce((n, p) => n + Object.values(p.attack_requests).reduce((a, b) => a + b, 0), 0);
  return (
    <div className="panel wide">
      <h3>
        {data.profile}: <span className={data.verification.status === "VERIFIED" ? "PASS" : "FAIL"}>{data.verification.status}</span>
      </h3>
      <p>
        {data.machine.cores} cores, {data.config.options}-option ballots at {fmt(data.config.honest_rate_per_s, 1)} ballots/s ={" "}
        {fmt(100 * data.fraction_of_design_rate, 1)}% of the largest constituency's design rate ({fmt(data.design_rate_largest_seat_per_s, 0)}/s). {atk.toLocaleString("en-IN")}{" "}
        attack requests. {data.ballots_on_board.toLocaleString("en-IN")} ballots recorded; every receipt is on the board:{" "}
        <b>{String(data.every_receipt_is_on_the_board)}</b>.
      </p>
      <div className="table-wrap">
        <table className="methods-table">
          <thead>
            <tr>
              <th scope="col">Phase</th>
              <th scope="col">Honest sent</th>
              <th scope="col">Recorded in the end</th>
              <th scope="col">Within 30 s</th>
              <th scope="col">Latency p50 / p95 / p99</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(data.phases).map(([k, p]) => (
              <tr key={k}>
                <th scope="row">{k}</th>
                <td>{p.honest_sent}</td>
                <td>
                  {p.honest_recorded} ({p.honest_recorded_pct}%)
                </td>
                <td>{p.honest_recorded_within_30s === undefined ? "-" : `${p.honest_recorded_within_30s} (${p.honest_recorded_within_30s_pct}%)`}</td>
                <td>
                  {fmt(p.latency_s.p50)} / {fmt(p.latency_s.p95)} / {fmt(p.latency_s.p99)} s
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="meta">
        Software {data.software.version}, source digest <code>{data.software.source_digest.slice(0, 16)}…</code>. Full per-request and per-second data are in
        the repository.
      </p>
    </div>
  );
}

export function Evidence() {
  const smoke = useJson<Rehearsal>("/evidence/rehearsal-smoke.json");
  const mini = useJson<Rehearsal>("/evidence/rehearsal-mini-peak.json");
  const peak = useJson<Rehearsal>("/evidence/rehearsal-shard-peak.json");
  const cap = useJson<Capacity>("/evidence/capacity.json");
  const rows: [string, string, string][] = [
    ["Ballots cast (incl. revotes)", "ballots", ""],
    ["Design rate", "design_per_s", "/s"],
    ["Verifier cores at design rate", "verify_cores_at_design", ""],
    ["Public record size", "record_tb", " TB"],
    ["After close: finalize, mix, decrypt", "post_close_core_h", " core-h"],
    ["… or cores to finish in 24 h", "post_close_cores_for_24h", ""],
    ["Full re-verification on 2,000 cores", "full_reverify_h", " h"],
  ];
  return (
    <main className="page">
      <h1>Evidence</h1>
      <p className="lede">
        Every claim about scale and resilience comes from a run you can repeat. Results are published as raw files; this page only displays them.
      </p>
      <p>
        The research paper describing the design and these results:{" "}
        <a href="https://github.com/itsashiish/chunaviq/blob/main/paper/ChunavIQ-paper.pdf">ChunavIQ (preprint, 2026)</a>. The code and data behind it are
        archived at <a href="https://doi.org/10.5281/zenodo.23442948">doi.org/10.5281/zenodo.23442948</a>.
      </p>

      <h2>Dress rehearsals: an election over HTTP, under attack</h2>
      <p>
        A real constituency election runs end to end with the 2048-bit group and a real clock. Honest voters arrive as a random stream in three phases
        (baseline, under attack, a 1.5x surge) while seven kinds of attack run at once: junk, oversized bodies, unregistered tags, broken proofs from
        registered attackers, replays, slowloris and idle-connection floods. Then the votes are finalized, mixed, counted and independently verified.
      </p>
      <RehearsalCard name="smoke rehearsal" data={smoke} />
      <RehearsalCard name="mini-peak rehearsal" data={mini} />
      <RehearsalCard name="shard-peak rehearsal" data={peak} />
      <p>
        A national rehearsal is this, 543 times, on the real infrastructure: constituencies share nothing while voting, so capacity adds up. Network-level
        floods (gigabits per second) are stopped before they reach this server, by a CDN or anycast scrubbing service; that layer has to be tested with the
        provider and cannot be tested from a laptop.
      </p>

      <h2>National capacity model</h2>
      {cap === null && <p className="meta">Loading…</p>}
      {cap === "missing" && <p className="meta">Run <code>chunaviq capacity</code> to generate it.</p>}
      {cap && cap !== "missing" && (
        <div className="table-wrap">
          <table className="methods-table">
            <thead>
              <tr>
                <th scope="col" />
                {cap.model.map((r) => (
                  <th scope="col" key={`${r.electors}${r.turnout}`}>
                    {r.electors}, {r.turnout}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map(([label, key, unit]) => (
                <tr key={key}>
                  <th scope="row">{label}</th>
                  {cap.model.map((r) => (
                    <td key={`${r.electors}${r.turnout}`}>
                      {fmt(r[key] as number, 1)}
                      {unit}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="meta">
        Unit costs are measured on one machine; national figures are modelled from them with stated assumptions (7 days, 16 voting hours a day, busiest hour
        2x average, last-day 2x, 2x headroom, 10% revotes). See <code>docs/scale/capacity.md</code>.
      </p>
      <p>
        <a href="/report/">The 10,000-voter evidence run, verified</a>
      </p>
    </main>
  );
}
