import { useEffect, useMemo, useRef, useState } from "react";
import { strToU8, zipSync } from "fflate";
import { ATTACKS, TAMPERS } from "./engine/attacks";
import { bytesToHex, toHex } from "./engine/bigint";
import { rsaToJson } from "./engine/blind";
import { benalohAudit, Rejected, type Ballot, type Prepared } from "./engine/ballot";
import { CONSTITUENCY, DemoElection, OPTIONS, type VoterDevice } from "./engine/election";
import { Pool } from "./engine/pool";
import { verifyReceipt, verifyRecord, type Report } from "./engine/verifier";
import type { WireCtx } from "./engine/worker";
import { Checks, InkMark, Progress, short, Symbol, tick } from "./ui/parts";

const ELIGIBLE = 150;
const CROWD = 110;
const ME = "syn-v-0000001";

type Prog = { label: string; done: number; total: number } | null;

export default function App() {
  const [e, setE] = useState<DemoElection | null>(null);
  const [stage, setStage] = useState(0);
  const [busy, setBusy] = useState(false);
  const [prog, setProg] = useState<Prog>(null);
  const [error, setError] = useState<string | null>(null);
  const [me, setMe] = useState<VoterDevice | null>(null);
  const [choice, setChoice] = useState<string | null>(null);
  const [prepared, setPrepared] = useState<Prepared | null>(null);
  const [auditMsg, setAuditMsg] = useState<string | null>(null);
  const [cast, setCast] = useState<{ tracking_code: string; seq: number } | null>(null);
  const [attacks, setAttacks] = useState<Record<string, string>>({});
  const [report, setReport] = useState<Report | null>(null);
  const [receiptOk, setReceiptOk] = useState<boolean | null>(null);
  const [tampers, setTampers] = useState<Record<string, Report>>({});
  const [, setVersion] = useState(0);
  const pool = useRef<Pool | null>(null);

  useEffect(() => () => pool.current?.terminate(), []);
  useEffect(() => {
    if (!e) return;
    const f = () => setVersion((v) => v + 1);
    e.board.listeners.add(f);
    return () => void e.board.listeners.delete(f);
  }, [e]);

  const ctx = useMemo<WireCtx | null>(
    () =>
      e && e.pk
        ? { K: toHex(e.pk.K), mh: e.mh, eid: e.electionId, options: { [CONSTITUENCY]: e.optionIds }, issuers: { [CONSTITUENCY]: rsaToJson(e.elig.signers[CONSTITUENCY].pub) } }
        : null,
    [e],
  );

  async function guard(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await tick();
      await fn();
    } catch (x) {
      setError(x instanceof Rejected ? `Refused: ${x.code}` : (x as Error).message);
    } finally {
      setBusy(false);
      setProg(null);
    }
  }

  // ------------------------------------------------------------------ steps
  const start = () =>
    guard(async () => {
      pool.current ??= new Pool();
      setProg({ label: "Creating keys", done: 0, total: 1 });
      const el = await DemoElection.create({ eligible: ELIGIBLE });
      setE(el);
      setMe(null);
      setChoice(null);
      setPrepared(null);
      setAuditMsg(null);
      setCast(null);
      setAttacks({});
      setReport(null);
      setReceiptOk(null);
      setTampers({});
      setStage(1);
    });

  const getCredential = () =>
    guard(async () => {
      const d = e!.device(ME);
      d.obtainCredential();
      setMe(d);
      setStage(2);
    });

  const encrypt = () =>
    guard(async () => {
      setPrepared(me!.prepare(choice!));
      setAuditMsg(null);
      setStage(3);
    });

  const challenge = () =>
    guard(async () => {
      const ok = benalohAudit(e!.pk!, prepared!, e!.optionIds);
      const fresh = me!.prepare(choice!);
      setPrepared(fresh);
      setAuditMsg(
        ok
          ? `Your device revealed the secret numbers it used, and re-encrypting "${OPTIONS.find((o) => o.id === choice)!.name}" with them gave exactly the same ballot. That checked ballot is now spoiled. A fresh one, sealed with new numbers, is ready to cast.`
          : "The revealed numbers do not reproduce the ballot. This device is lying about your vote. Do not cast from it.",
      );
    });

  const castVote = () =>
    guard(async () => {
      const r = e!.submit(prepared!.ballot);
      e!.board.checkpoint();
      setCast(r);
      setStage(4);
    });

  const crowd = () =>
    guard(async () => {
      const el = e!;
      const weights = el.optionIds.map((o) => (o === "NOTA" ? 0.35 : 0.5 + Math.random()));
      const sum = weights.reduce((a, b) => a + b, 0);
      const pick = () => {
        let x = Math.random() * sum;
        for (let i = 0; i < weights.length; i++) if ((x -= weights[i]) < 0) return el.optionIds[i];
        return el.optionIds[0];
      };
      const jobs: { cons: string; choice: string; token: string; sig: string }[] = [];
      for (let i = 2; i < 2 + CROWD; i++) {
        const d = el.device(`syn-v-${String(i).padStart(7, "0")}`);
        d.obtainCredential();
        jobs.push({ cons: CONSTITUENCY, choice: pick(), token: bytesToHex(d.token!), sig: toHex(d.signature!) });
        if (i % 5 === 0) {
          setProg({ label: "Voters getting credentials", done: i - 1, total: CROWD });
          await tick();
        }
      }
      const ballots = await pool.current!.run<Ballot>("prepare", ctx!, jobs, (n) => setProg({ label: "Voters' devices encrypting ballots", done: n, total: CROWD }));
      const codes = await pool.current!.run<string | null>("boxCheck", ctx!, ballots, (n) => setProg({ label: "Ballot box checking proofs", done: n, total: CROWD }));
      ballots.forEach((b, i) => {
        if (codes[i]) el.rejections[codes[i]!] = (el.rejections[codes[i]!] ?? 0) + 1;
        else el.submit(b, true);
      });
      el.board.checkpoint();
      setStage(5);
    });

  const tryAttack = (id: string) =>
    guard(async () => {
      const a = ATTACKS.find((x) => x.id === id)!;
      let code = "ACCEPTED";
      try {
        a.run(e!, me!);
      } catch (x) {
        code = x instanceof Rejected ? x.code : (x as Error).message;
      }
      setAttacks((s) => ({ ...s, [id]: code }));
    });

  const count = () =>
    guard(async () => {
      e!.close();
      e!.tally([1]);
      setStage(6);
    });

  const verify = () =>
    guard(async () => {
      const { entries, checkpoints } = e!.board.export();
      const rep = await verifyRecord(entries, checkpoints, {
        expectManifestHash: e!.mh,
        checker: pool.current!.checker(),
        onProgress: (label, done, total) => setProg({ label, done, total }),
      });
      setReport(rep);
      setReceiptOk(verifyReceipt(entries, checkpoints, e!.board.receipt(cast!.seq)));
      setStage(7);
    });

  const tamper = (id: string) =>
    guard(async () => {
      const t = TAMPERS.find((x) => x.id === id)!;
      const { entries, checkpoints } = t.apply(e!);
      const rep = await verifyRecord(entries, checkpoints, { checker: pool.current!.checker(), onProgress: (label, done, total) => setProg({ label, done, total }) });
      setTampers((s) => ({ ...s, [id]: rep }));
    });

  const download = () => {
    const { entries, checkpoints } = e!.board.export();
    const zip = zipSync({
      [`${e!.electionId}/record/entries.jsonl`]: strToU8(entries),
      [`${e!.electionId}/record/checkpoints.jsonl`]: strToU8(checkpoints),
      [`${e!.electionId}/MANIFEST_HASH.txt`]: strToU8(e!.mh + "\n"),
      [`${e!.electionId}/my-receipt.json`]: strToU8(JSON.stringify(e!.board.receipt(cast!.seq), null, 2) + "\n"),
    });
    const url = URL.createObjectURL(new Blob([zip], { type: "application/zip" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${e!.electionId}.zip`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  // ------------------------------------------------------------------ render
  const step = (n: number) => `step${stage > n ? " done" : ""}${stage < n ? " locked" : ""}`;
  const results = e?.results as { counts: Record<string, number>; quorum: number[]; ballots: number; winner: string | null; tied: string[]; nota_exceeds_winner: boolean } | undefined;
  const maxVotes = results ? Math.max(...Object.values(results.counts), 1) : 1;
  const nameOf = (id: string) => OPTIONS.find((o) => o.id === id)?.name ?? id;

  return (
    <>
      <div className="demo-strip" role="note">
        Demo with synthetic voters and candidates. Nothing here is a real election, and nothing leaves your browser.
      </div>
      <header className="top">
        <a className="wordmark" href="/" aria-label="ChunavIQ home">
          <span className="deva" lang="hi">
            चुनाव
          </span>
          <span className="latin">ChunavIQ</span>
        </a>
        <nav aria-label="Elsewhere">
          <a href="/report/">10,000-voter report</a>
        </nav>
      </header>

      <div className="layout">
        <main>
          <section className="hero">
            <h1>Cast a secret ballot. Then check it was counted.</h1>
            <p>
              You are one of {ELIGIBLE} synthetic voters in a small election that runs entirely in this browser tab. Your vote is encrypted on your
              device, no single official can read it, and at the end you can verify the whole count yourself.
            </p>
            <p>Takes about two minutes. Every step shows what each party actually saw.</p>
            <div className="actions">
              <button className="btn primary" onClick={start} disabled={busy}>
                {stage === 0 ? "Start a demo election" : "Start a new election"}
              </button>
            </div>
          </section>

          <div aria-live="polite">
            {prog && <Progress {...prog} />}
            {error && (
              <p className="status FAIL" role="alert">
                {error}
              </p>
            )}
          </div>

          {/* 1 ---------------------------------------------------------------- */}
          <section className={step(1)} aria-labelledby="s1">
            <h2 id="s1">
              <span className="num">1</span>Set up the election
            </h2>
            <p className="lede">Five trustees each create one share of the election key. Any three together can decrypt totals; fewer can decrypt nothing.</p>
            {e && (
              <>
                <div className="trustees">
                  {e.trustees.map((t) => (
                    <span key={t.key.role} className="trustee">
                      Trustee {t.trustee.index} <code>{t.key.publicHex.slice(0, 8)}</code>
                    </span>
                  ))}
                </div>
                <div className="pair">
                  <div className="panel">
                    <h3>Election</h3>
                    <code>{e.electionId}</code>
                    <p>Synthetic Constituency 1, {ELIGIBLE} voters on the roll, polls open now.</p>
                  </div>
                  <div className="panel">
                    <h3>Manifest fingerprint</h3>
                    <code>{short(e.mh, 12)}</code>
                    <p>Write this down. The verifier will check the record against it at the end.</p>
                  </div>
                </div>
              </>
            )}
          </section>

          {/* 2 ---------------------------------------------------------------- */}
          <section className={step(2)} aria-labelledby="s2">
            <h2 id="s2">
              <span className="num">2</span>Prove you can vote
            </h2>
            <p className="lede">
              You are voter <code>{ME}</code>. Your device makes a random token, scrambles it, and the eligibility authority signs the scrambled version after
              checking you are on the roll.
            </p>
            {stage >= 1 && !me && (
              <button className="btn primary" onClick={getCredential} disabled={busy}>
                Get my voting credential
              </button>
            )}
            {me && (
              <div className="pair">
                <div className="panel">
                  <h3>What the authority saw</h3>
                  <code>{short(me.lastBlinded!, 14)}</code>
                  <p>A scrambled number, plus your name on the roll.</p>
                </div>
                <div className="panel">
                  <h3>Your credential</h3>
                  <code>{short(bytesToHex(me.token!), 14)}</code>
                  <p>Unscrambled on your device. It never matches what the authority saw, so it cannot link your ballot to you.</p>
                </div>
              </div>
            )}
          </section>

          {/* 3 ---------------------------------------------------------------- */}
          <section className={step(3)} aria-labelledby="s3">
            <h2 id="s3">
              <span className="num">3</span>Mark your ballot
            </h2>
            <p className="lede">Press the blue button next to your choice. The lamp lights to confirm it.</p>
            <div className="evm" role="radiogroup" aria-label="Ballot unit, Synthetic Constituency 1">
              <div className="evm-head">
                <span>Ballot unit, Synthetic Constituency 1</span>
                <span className="ready">
                  <i aria-hidden="true" /> Ready
                </span>
              </div>
              {OPTIONS.map((o, i) => (
                <div className="evm-row" key={o.id}>
                  <span className="sl">{i + 1}</span>
                  <span className="who">
                    <b>{o.name}</b>
                    <small>{o.party === "-" ? "NOTA" : o.party}</small>
                  </span>
                  <Symbol kind={o.symbol} />
                  <span className={`lamp${choice === o.id ? " on" : ""}`} aria-hidden="true" />
                  <button
                    className="evm-btn"
                    role="radio"
                    aria-checked={choice === o.id}
                    aria-pressed={choice === o.id}
                    aria-label={`Vote for ${o.name}${o.party !== "-" ? `, ${o.party}` : ""}`}
                    disabled={stage !== 2 || busy}
                    onClick={() => setChoice(o.id)}
                  />
                </div>
              ))}
            </div>
            {stage === 2 && (
              <button className="btn primary" onClick={encrypt} disabled={!choice || busy}>
                Seal my ballot
              </button>
            )}
            {prepared && (
              <p>
                Sealed as {prepared.ballot.selections.length} encrypted boxes, one per option, each with a proof that it holds a 0 or a 1, plus a proof that
                exactly one box holds a 1. Nobody can tell which.
              </p>
            )}
          </section>

          {/* 4 ---------------------------------------------------------------- */}
          <section className={step(4)} aria-labelledby="s4">
            <h2 id="s4">
              <span className="num">4</span>Check or cast
            </h2>
            <p className="lede">
              You can test your device first: it reveals how it sealed this ballot, you confirm it matches your choice, and that ballot is thrown away. Cast
              whenever you trust it.
            </p>
            {stage === 3 && (
              <div className="actions" style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                <button className="btn" onClick={challenge} disabled={busy}>
                  Check my device
                </button>
                <button className="btn primary" onClick={castVote} disabled={busy}>
                  Cast my vote
                </button>
              </div>
            )}
            {auditMsg && <p className="status">{auditMsg}</p>}
            {cast && (
              <div className="cast">
                <InkMark />
                <div className="slip" aria-label="Your receipt">
                  <strong>Your receipt</strong>
                  <span className="code">{cast.tracking_code}</span>
                  Entry {cast.seq} in the public record. It proves your ballot is there, not how you voted.
                </div>
              </div>
            )}
          </section>

          {/* 5 ---------------------------------------------------------------- */}
          <section className={step(5)} aria-labelledby="s5">
            <h2 id="s5">
              <span className="num">5</span>Everyone else votes
            </h2>
            <p className="lede">
              {CROWD} other synthetic voters get credentials and cast encrypted ballots. Their devices and the ballot box run on your computer's spare cores.
            </p>
            {stage === 4 && (
              <button className="btn primary" onClick={crowd} disabled={busy}>
                Let {CROWD} voters vote
              </button>
            )}
            {stage >= 5 && (
              <>
                <p>{e!.board.of("ballot").length} ballots are in the ballot box. Now try to cheat.</p>
                <ul className="plain lab">
                  {ATTACKS.map((a) => (
                    <li key={a.id}>
                      <span className="what">
                        <b>{a.title}</b>
                        <small>{a.how}</small>
                      </span>
                      <button className="btn small" onClick={() => tryAttack(a.id)} disabled={busy || stage > 5 || !!attacks[a.id]}>
                        {attacks[a.id] ? "Tried" : "Try it"}
                      </button>
                      {attacks[a.id] && (
                        <span className="outcome">
                          <span className={a.explain[attacks[a.id]] ? "PASS" : "FAIL"}>Refused ({attacks[a.id]}).</span> {a.explain[attacks[a.id]] ?? "Unexpected outcome."}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </section>

          {/* 6 ---------------------------------------------------------------- */}
          <section className={step(6)} aria-labelledby="s6">
            <h2 id="s6">
              <span className="num">6</span>Count the votes
            </h2>
            <p className="lede">
              The polls close. Ballots are multiplied together while still encrypted, so only the totals are ever decrypted. Trustee 1 is offline; three of the
              remaining four are enough.
            </p>
            {stage === 5 && (
              <button className="btn primary" onClick={count} disabled={busy}>
                Close the polls and count
              </button>
            )}
            {results && (
              <>
                <div className="trustees">
                  {e!.trustees.map((t) => (
                    <span key={t.key.role} className={`trustee ${results.quorum.includes(t.trustee.index) ? "on" : t.trustee.index === 1 ? "off" : ""}`}>
                      Trustee {t.trustee.index}
                      {t.trustee.index === 1 ? ", offline" : results.quorum.includes(t.trustee.index) ? ", decrypted" : ", not needed"}
                    </span>
                  ))}
                </div>
                <table className="results">
                  <thead>
                    <tr>
                      <th scope="col">Option</th>
                      <th scope="col">Votes</th>
                      <th scope="col">
                        <span className="sr-only">Share</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {OPTIONS.map((o) => (
                      <tr key={o.id} className={results.winner === o.id ? "win" : ""}>
                        <td>
                          {o.name}
                          {results.winner === o.id ? " (elected)" : ""}
                        </td>
                        <td className="n">{results.counts[o.id]}</td>
                        <td style={{ width: "45%" }} aria-hidden="true">
                          <div className="bar" style={{ width: `${(100 * results.counts[o.id]) / maxVotes}%` }} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {results.tied.length > 0 && <p>Tie between {results.tied.map(nameOf).join(" and ")}. Software does not break ties; a returning officer draws lots.</p>}
                {results.nota_exceeds_winner && <p>NOTA beat every candidate. Under the rule used here it is counted and published, but cannot win.</p>}
              </>
            )}
          </section>

          {/* 7 ---------------------------------------------------------------- */}
          <section className={step(7)} aria-labelledby="s7">
            <h2 id="s7">
              <span className="num">7</span>Verify everything
            </h2>
            <p className="lede">
              The verifier reads only the public record and redoes every check: signatures, the record's fingerprints, each ballot's proofs, the trustees'
              decryption, the totals.
            </p>
            {stage === 6 && (
              <button className="btn primary" onClick={verify} disabled={busy}>
                Verify the election
              </button>
            )}
            {report && (
              <>
                <p>
                  <strong className={report.status === "VERIFIED" ? "PASS" : "FAIL"}>{report.status === "VERIFIED" ? "Verified." : "Not verified."}</strong>{" "}
                  {report.checks.length} checks, {report.failures} failed.
                  {report.warnings > 0 && " The note below is expected: you closed the polls early."}
                </p>
                <p>
                  <strong className={receiptOk ? "PASS" : "FAIL"}>{receiptOk ? "Your ballot is in the record." : "Your receipt did not verify."}</strong> Your tracking
                  code sits inside the final signed fingerprint of the record.
                </p>
                <Checks checks={report.checks} />

                <h3>Now try to falsify the record</h3>
                <ul className="plain lab">
                  {TAMPERS.map((t) => {
                    const r = tampers[t.id];
                    const caught = r?.checks.filter((c) => c.status === "FAIL");
                    return (
                      <li key={t.id}>
                        <span className="what">
                          <b>{t.title}</b>
                          <small>{t.who}</small>
                        </span>
                        <button className="btn small" onClick={() => tamper(t.id)} disabled={busy || !!r}>
                          {r ? "Done" : "Tamper and re-verify"}
                        </button>
                        {r && (
                          <span className="outcome">
                            <span className={r.status === "VERIFIED" ? "FAIL" : "PASS"}>{r.status === "VERIFIED" ? "Not caught." : "Caught."}</span> Failed:{" "}
                            {caught!.map((c) => c.title.toLowerCase()).join("; ")}.
                          </span>
                        )}
                      </li>
                    );
                  })}
                </ul>

                <h3>Check it with a different program</h3>
                <p>
                  Download this election's record and your receipt. The ChunavIQ Python verifier, written separately, checks the same record:{" "}
                  <code>chunaviq verify record --expect-manifest-hash {short(e!.mh, 8)}</code>
                </p>
                <button className="btn" onClick={download}>
                  Download the record
                </button>
              </>
            )}
          </section>
        </main>

        <aside className="record" aria-labelledby="rec">
          <h2 id="rec">Public record</h2>
          {e ? (
            <>
              <p className="meta">
                {e.board.entries.length} entries, state {e.board.state.toLowerCase()}. Latest signed fingerprint{" "}
                <code>{String(e.board.checkpoints[e.board.checkpoints.length - 1]?.root ?? "").slice(0, 12)}</code>
              </p>
              <ol aria-label="Latest entries">
                {e.board.entries
                  .slice(-9)
                  .reverse()
                  .map((en, i) => (
                    <li key={en.seq} className={i === 0 ? "new" : ""}>
                      <span className="seq">{en.seq}</span>
                      <span>
                        {describe(en.type, en.body)}
                      </span>
                    </li>
                  ))}
              </ol>
            </>
          ) : (
            <p className="meta">Empty until you start an election. Everything any party publishes appears here, in order, and can never be changed.</p>
          )}
        </aside>
      </div>

      <footer>
        ChunavIQ is a research prototype. It is not certified or authorised for any public election; in India only the Election Commission or a State
        Election Commission can authorise a voting method. Coercion, compromised devices and denial of service remain open problems for online voting.
      </footer>
    </>
  );
}

function describe(type: string, body: Record<string, unknown>): string {
  switch (type) {
    case "manifest":
      return "Election rules published";
    case "lifecycle":
      return `Officer: ${String(body.state).toLowerCase().replace("_", " ")}`;
    case "trustee_commitment":
      return `Trustee ${(body.commitment as { index: number }).index} key share committed`;
    case "trustee_ack":
      return `Trustee ${body.index} checked all shares`;
    case "joint_key":
      return "Joint election key published";
    case "issuer_keys":
      return "Credential signing key published";
    case "ballot":
      return `Ballot ${String(body.tracking_code).slice(0, 10)}`;
    case "participation_summary":
      return "Turnout summary published";
    case "aggregate":
      return "Encrypted totals published";
    case "decryption_shares":
      return `Trustee ${body.index} decrypted totals`;
    case "result":
      return "Result published";
    default:
      return type;
  }
}
