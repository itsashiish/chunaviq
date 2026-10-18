import { useEffect, useMemo, useRef, useState } from "react";
import { strToU8, zipSync } from "fflate";
import { ATTACKS, TAMPERS } from "./engine/attacks";
import { toHex } from "./engine/bigint";
import { benalohAudit, Rejected, type Prepared, type Submission } from "./engine/ballot";
import { CONSTITUENCY, DemoElection, OPTIONS, type AuthMethod, type VoterDevice } from "./engine/election";
import { Pool } from "./engine/pool";
import { verifyReceipt, verifyRecord, type Report } from "./engine/verifier";
import type { WireCtx } from "./engine/worker";
import { Checks, InkMark, Progress, short, Symbol, tick } from "./ui/parts";
import { Evidence } from "./pages/Evidence";
import { Law } from "./pages/Law";
import { Methods } from "./pages/Methods";

const ELIGIBLE = 150;
const CROWD = 110;
const CROWD_REVOTES = 8;
const CROWD_BOOTH = 3;
const ME = "syn-v-0000001";

type Prog = { label: string; done: number; total: number } | null;
type Receipt = { tracking_code: string; seq: number; revote?: number };

const METHODS: { id: AuthMethod; title: string; how: string }[] = [
  { id: "aadhaar-otp", title: "Aadhaar + OTP", how: "A one-time code goes to the mobile number linked to your Aadhaar." },
  { id: "aadhaar-face", title: "Aadhaar + face", how: "Your face is matched against the photograph UIDAI holds." },
  { id: "pan", title: "PAN + OTP + face", how: "PAN only proves you know a number, name and birth date, so it also needs a code to the mobile on the electoral roll and a face match to the roll photograph." },
];

function useRoute() {
  const [route, setRoute] = useState(() => (typeof location !== "undefined" ? location.hash : ""));
  useEffect(() => {
    const f = () => {
      setRoute(location.hash);
      window.scrollTo?.(0, 0);
    };
    window.addEventListener("hashchange", f);
    return () => window.removeEventListener("hashchange", f);
  }, []);
  return route;
}

export default function App() {
  const route = useRoute();
  const page = route.startsWith("#/methods") ? "methods" : route.startsWith("#/law") ? "law" : route.startsWith("#/evidence") ? "evidence" : "demo";
  return (
    <>
      <div className="demo-strip" role="note">
        Demo with synthetic voters, identities and candidates. Nothing here is a real election, and nothing leaves your browser.
      </div>
      <header className="top">
        <a className="wordmark" href="#/" aria-label="ChunavIQ home">
          <span className="deva" lang="hi">
            चुनाव
          </span>
          <span className="latin">ChunavIQ</span>
        </a>
        <nav aria-label="Sections">
          <a href="#/" aria-current={page === "demo" ? "page" : undefined}>
            Demo
          </a>
          <a href="#/methods" aria-current={page === "methods" ? "page" : undefined}>
            How it works
          </a>
          <a href="#/law" aria-current={page === "law" ? "page" : undefined}>
            The law needed
          </a>
          <a href="#/evidence" aria-current={page === "evidence" ? "page" : undefined}>
            Evidence
          </a>
        </nav>
      </header>
      {page === "methods" ? <Methods /> : page === "law" ? <Law /> : page === "evidence" ? <Evidence /> : <Demo />}
      <footer>
        ChunavIQ is a research prototype. It is not certified or authorised for any public election; in India only the Election Commission or a State
        Election Commission, under laws made by Parliament or a State legislature, can authorise a voting method. See <a href="#/law">the law needed</a>.
        <br />
        <a href="https://doi.org/10.5281/zenodo.23447533">Paper (preprint), DOI 10.5281/zenodo.23447533</a> ·{" "}
        <a href="https://github.com/itsashiish/chunaviq">Source code</a> ·{" "}
        <a href="https://doi.org/10.5281/zenodo.23442948">Code archive, DOI 10.5281/zenodo.23442948</a>
      </footer>
    </>
  );
}

function Demo() {
  const [e, setE] = useState<DemoElection | null>(null);
  const [stage, setStage] = useState(0);
  const [busy, setBusy] = useState(false);
  const [prog, setProg] = useState<Prog>(null);
  const [error, setError] = useState<string | null>(null);
  const [method, setMethod] = useState<AuthMethod>("aadhaar-otp");
  const [me, setMe] = useState<VoterDevice | null>(null);
  const [choice, setChoice] = useState<string | null>(null);
  const [prepared, setPrepared] = useState<Prepared | null>(null);
  const [auditMsg, setAuditMsg] = useState<string | null>(null);
  const [casts, setCasts] = useState<{ receipt: Receipt; choice: string; note: string }[]>([]);
  const [attacks, setAttacks] = useState<Record<string, string>>({});
  const [report, setReport] = useState<Report | null>(null);
  const [receiptOk, setReceiptOk] = useState<boolean | null>(null);
  const [counted, setCounted] = useState<{ real: boolean; fake: boolean } | null>(null);
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

  const ctx = useMemo<WireCtx | null>(() => (e && e.pk ? { K: toHex(e.pk.K), mh: e.mh, eid: e.electionId, options: { [CONSTITUENCY]: e.optionIds } } : null), [e]);
  const nameOf = (id: string) => OPTIONS.find((o) => o.id === id)?.name ?? id;

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
      setProg({ label: "Trustees creating the election key", done: 0, total: 1 });
      const el = await DemoElection.create({ eligible: ELIGIBLE });
      setE(el);
      setMe(null);
      setChoice(null);
      setPrepared(null);
      setAuditMsg(null);
      setCasts([]);
      setAttacks({});
      setReport(null);
      setReceiptOk(null);
      setCounted(null);
      setTampers({});
      setStage(1);
    });

  const register = () =>
    guard(async () => {
      const d = e!.device(ME);
      d.register(method);
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
      setPrepared(me!.prepare(choice!));
      setAuditMsg(
        ok
          ? `Your device revealed the secret numbers it used, and re-encrypting "${nameOf(choice!)}" with them gave exactly the same ballot. That checked ballot is now spoiled. A fresh one, sealed with new numbers, is ready to cast.`
          : "The revealed numbers do not reproduce the ballot. This device is lying about your vote. Do not cast from it.",
      );
    });

  const castBallot = (prep: Prepared, note: string) => {
    const r = e!.submit(me!.submission(prep));
    me!.cast.push(r.tracking_code);
    e!.board.checkpoint();
    setCasts((c) => [...c, { receipt: r, choice: prep.choice, note }]);
  };

  const castVote = () =>
    guard(async () => {
      castBallot(prepared!, "Watched by a coercer standing next to you.");
      setStage(4);
    });

  const revote = (opt: string) =>
    guard(async () => {
      castBallot(me!.prepare(opt), "Later, alone. Only your last ballot counts.");
    });

  const newPhone = () =>
    guard(async () => {
      me!.register("aadhaar-otp");
      setCasts((c) => [...c, { receipt: { tracking_code: "", seq: -1 }, choice: "", note: "Re-registered a new phone: every ballot from the old one stops counting. Vote again below." }]);
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
      const jobs: { cons: string; choice: string; t: string }[] = [];
      const methods: AuthMethod[] = ["aadhaar-otp", "aadhaar-face", "pan"];
      for (let i = 2; i < 2 + CROWD; i++) {
        const d = el.device(`syn-v-${String(i).padStart(7, "0")}`);
        d.register(d.person.panRef ? methods[i % 3] : "aadhaar-otp");
        jobs.push({ cons: CONSTITUENCY, choice: pick(), t: toHex(d.t!) });
        if (i - 2 < CROWD_REVOTES) jobs.push({ cons: CONSTITUENCY, choice: pick(), t: toHex(d.t!) });
        if (i % 5 === 0) {
          setProg({ label: "Voters verifying identity and registering their phones", done: i - 1, total: CROWD });
          await tick();
        }
      }
      // first ballots, then revotes, in order
      const firsts = jobs.filter((_, i) => i < 2 * CROWD_REVOTES ? i % 2 === 0 : true);
      const seconds = jobs.filter((_, i) => i < 2 * CROWD_REVOTES && i % 2 === 1);
      const all = [...firsts, ...seconds];
      const subs = await pool.current!.run<Submission>("prepare", ctx!, all, (n) => setProg({ label: "Voters' devices encrypting ballots", done: n, total: all.length }));
      const tags = await pool.current!.run<string>("precheck", ctx!, subs, (n) => setProg({ label: "Ballot box checking proofs", done: n, total: subs.length }));
      subs.forEach((s, i) => {
        if (tags[i].startsWith("REJECT:")) el.rejections[tags[i].slice(7)] = (el.rejections[tags[i].slice(7)] ?? 0) + 1;
        else el.submit(s, tags[i]);
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
      const el = e!;
      const booth = Array.from({ length: CROWD_BOOTH }, (_, i) => `syn-v-${String(2 + CROWD - 1 - i).padStart(7, "0")}`);
      el.close(undefined, booth);
      const runner = pool.current!.runner(ctx!);
      const p = (label: string, done: number, total: number) => setProg({ label, done, total });
      await el.finalize(runner, p);
      await el.mixAndTally([1], runner, p);
      setStage(6);
    });

  const verify = () =>
    guard(async () => {
      const { entries, checkpoints } = e!.board.export();
      const rep = await verifyRecord(entries, checkpoints, {
        expectManifestHash: e!.mh,
        runner: pool.current!.verifier(),
        onProgress: (label, done, total) => setProg({ label, done, total }),
      });
      setReport(rep);
      const lastReal = [...casts].reverse().find((c) => c.receipt.seq >= 0)!;
      setReceiptOk(verifyReceipt(entries, checkpoints, e!.board.receipt(lastReal.receipt.seq)));
      const dv = e!.dvProof(me!.cast[me!.cast.length - 1]);
      const firstTc = me!.cast[0];
      const firstFlag = e!.board.of("finalization").flatMap((x) => x.body.items as { tracking_code: string; flag: { alpha: string; beta: string } }[]).find((it) => it.tracking_code === firstTc)!.flag;
      setCounted({ real: !!dv && me!.checkCounted(dv.flag, dv.proof), fake: me!.checkCounted(firstFlag, me!.fakeCountedProof(firstFlag, firstTc), firstTc) });
      setStage(7);
    });

  const tamper = (id: string) =>
    guard(async () => {
      const t = TAMPERS.find((x) => x.id === id)!;
      const { entries, checkpoints } = t.apply(e!);
      const rep = await verifyRecord(entries, checkpoints, { runner: pool.current!.verifier(), onProgress: (label, done, total) => setProg({ label, done, total }) });
      setTampers((s) => ({ ...s, [id]: rep }));
    });

  const download = () => {
    const { entries, checkpoints } = e!.board.export();
    const last = [...casts].reverse().find((c) => c.receipt.seq >= 0)!;
    const zip = zipSync({
      [`${e!.electionId}/record/entries.jsonl`]: strToU8(entries),
      [`${e!.electionId}/record/checkpoints.jsonl`]: strToU8(checkpoints),
      [`${e!.electionId}/MANIFEST_HASH.txt`]: strToU8(e!.mh + "\n"),
      [`${e!.electionId}/my-receipt.json`]: strToU8(JSON.stringify(e!.board.receipt(last.receipt.seq), null, 2) + "\n"),
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
  const results = e?.results as { counts: Record<string, number>; quorum: number[]; ballots: number; cast: number; winner: string | null; tied: string[]; nota_exceeds_winner: boolean } | undefined;
  const maxVotes = results ? Math.max(...Object.values(results.counts), 1) : 1;
  const realCasts = casts.filter((c) => c.receipt.seq >= 0);
  const myLast = realCasts[realCasts.length - 1];

  return (
    <div className="layout">
      <main>
        <section className="hero">
          <h1>Cast a secret ballot. Change it in private. Then check it was counted.</h1>
          <p>
            You are one of {ELIGIBLE} synthetic voters in an election that runs entirely in this browser tab. You prove who you are with a synthetic Aadhaar or
            PAN, your vote is encrypted on your device, no single official can read it, and if someone watches you vote you can quietly vote again. Only your
            last vote counts, and nobody can see which one that was.
          </p>
          <p>Takes about three minutes. Every step shows what each party actually saw.</p>
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
          <p className="lede">
            Five trustees each create one share of a single election key. Any three can decrypt totals; fewer can decrypt nothing. In a real election each share
            lives inside that trustee's hardware security module and is used only after polls close, with two of three operator cards and two independent
            observers approving.
          </p>
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
            <span className="num">2</span>Prove who you are
          </h2>
          <p className="lede">
            You are voter <code>{ME}</code>. Pick how to prove it. Either way you end up as the same one entry on the electoral roll, and your phone registers a
            fresh voting tag whose secret never leaves it.
          </p>
          <div className="methods" role="radiogroup" aria-label="Identity method">
            {METHODS.map((m) => (
              <label key={m.id} className={`method${method === m.id ? " on" : ""}`}>
                <input type="radio" name="method" value={m.id} checked={method === m.id} disabled={stage !== 1 || busy} onChange={() => setMethod(m.id)} />
                <span>
                  <b>{m.title}</b>
                  <small>{m.how}</small>
                </span>
              </label>
            ))}
          </div>
          {stage === 1 && (
            <button className="btn primary" onClick={register} disabled={busy}>
              Verify me and register this phone
            </button>
          )}
          {me && (
            <div className="pair">
              <div className="panel">
                <h3>What the authority saw</h3>
                <p>
                  {method === "aadhaar-face" ? "A face match against UIDAI's photograph" : `A one-time code ${me.lastOtp} sent to your synthetic phone`}
                  {method === "pan" ? ", your PAN details and a face match against the roll photograph" : ""}. Then your new tag:
                </p>
                <code>{short(toHex(me.T!), 12)}</code>
              </div>
              <div className="panel">
                <h3>What stays on your phone</h3>
                <code>{short(toHex(me.t!), 12)}</code>
                <p>The tag's secret. Only a device holding it can make a ballot under your tag; not the authority, not the ballot box.</p>
              </div>
            </div>
          )}
        </section>

        {/* 3 ---------------------------------------------------------------- */}
        <section className={step(3)} aria-labelledby="s3">
          <h2 id="s3">
            <span className="num">3</span>Mark your ballot
          </h2>
          <p className="lede">Imagine someone is standing next to you, telling you how to vote. Press the blue button next to the choice they want.</p>
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
              Sealed as {prepared.ballot.selections.length} encrypted boxes with proofs that exactly one holds a 1, plus your tag, encrypted, with a proof that
              your phone knows its secret. Nobody can tell which box, or whose tag.
            </p>
          )}
        </section>

        {/* 4 ---------------------------------------------------------------- */}
        <section className={step(4)} aria-labelledby="s4">
          <h2 id="s4">
            <span className="num">4</span>Check, cast, and vote again
          </h2>
          <p className="lede">
            Test your device first if you like: it reveals how it sealed this ballot and that ballot is thrown away. Then cast. Afterwards, alone, you can vote
            again as often as you like during the week; only the last ballot counts.
          </p>
          {stage === 3 && (
            <div className="actions row">
              <button className="btn" onClick={challenge} disabled={busy}>
                Check my device
              </button>
              <button className="btn primary" onClick={castVote} disabled={busy}>
                Cast my vote
              </button>
            </div>
          )}
          {auditMsg && <p className="status">{auditMsg}</p>}
          {casts.length > 0 && (
            <>
              <div className="cast">
                <InkMark />
                <div className="slip" aria-label="Your receipt">
                  <strong>Your latest receipt</strong>
                  <span className="code">{myLast.receipt.tracking_code}</span>
                  Entry {myLast.receipt.seq} in the public record. It proves your ballot is there, not how you voted, and not whether it is your last.
                </div>
              </div>
              <ol className="history" aria-label="Your ballots">
                {casts.map((c, i) => (
                  <li key={i}>
                    {c.receipt.seq >= 0 ? (
                      <>
                        <b>{nameOf(c.choice)}</b> <code>{short(c.receipt.tracking_code, 6)}</code>
                      </>
                    ) : (
                      <b>New phone</b>
                    )}{" "}
                    <small>{c.note}</small>
                  </li>
                ))}
              </ol>
              {stage === 4 && (
                <>
                  <p>The coercer has left. Vote again for who you actually want:</p>
                  <div className="actions row">
                    {OPTIONS.map((o) => (
                      <button key={o.id} className="btn small" onClick={() => revote(o.id)} disabled={busy}>
                        Vote again: {o.name}
                      </button>
                    ))}
                  </div>
                  <p>
                    Or, if the coercer kept your phone:{" "}
                    <button className="btn small" onClick={newPhone} disabled={busy}>
                      Re-register a new phone
                    </button>
                  </p>
                </>
              )}
            </>
          )}
        </section>

        {/* 5 ---------------------------------------------------------------- */}
        <section className={step(5)} aria-labelledby="s5">
          <h2 id="s5">
            <span className="num">5</span>Everyone else votes
          </h2>
          <p className="lede">
            {CROWD} other synthetic voters prove who they are and cast encrypted ballots; {CROWD_REVOTES} of them change their minds later, and {CROWD_BOOTH} will
            vote at a polling station on polling day instead, which cancels their online ballot.
          </p>
          {stage === 4 && (
            <button className="btn primary" onClick={crowd} disabled={busy || !realCasts.length || casts[casts.length - 1].receipt.seq < 0}>
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
            Polls close and polling-day voters cancel their online ballots. The ballot box marks, in secret, the last ballot of each valid voter, and proves it
            did only that. Three trustees shuffle the ballots so nobody can tell which ones counted. Then only the totals are decrypted. Trustee 1 is offline;
            three of the other four are enough.
          </p>
          {stage === 5 && (
            <button className="btn primary" onClick={count} disabled={busy}>
              Close the polls and count
            </button>
          )}
          {results && (
            <>
              <p>
                {results.cast} ballots cast, <strong>{results.ballots} counted</strong>: one per voter. {e!.stats.superseded} were replaced by a later vote and{" "}
                {e!.stats.revoked} came from a phone that was replaced or a voter who voted in person.
              </p>
              <div className="trustees">
                {e!.trustees.map((t) => (
                  <span key={t.key.role} className={`trustee ${results.quorum.includes(t.trustee.index) ? "on" : t.trustee.index === 1 ? "off" : ""}`}>
                    Trustee {t.trustee.index}
                    {t.trustee.index === 1 ? ", offline" : results.quorum.includes(t.trustee.index) ? ", mixed and decrypted" : ", not needed"}
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
            The verifier reads only the public record and redoes every check: signatures, the record's fingerprints, every ballot's proofs, the ballot box's
            finalization proofs, the three shuffles, every decryption, and that the counted ballots belong to distinct, valid registrations.
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
              {counted && (
                <>
                  <p>
                    <strong className={counted.real ? "PASS" : "FAIL"}>{counted.real ? "Your last ballot is the one that counted." : "Could not confirm your last ballot counted."}</strong>{" "}
                    The ballot box sent your phone a proof only your phone can check.
                  </p>
                  <p>
                    <strong className={counted.fake ? "PASS" : "FAIL"}>And the coercer learns nothing from it.</strong> Your phone just made an equally valid
                    "proof" that your <em>first</em> ballot counted, the one the coercer watched. Because you can fake it, the coercer cannot trust it.
                  </p>
                </>
              )}
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
                    <span>{describe(en.type, en.body)}</span>
                  </li>
                ))}
            </ol>
            <p className="meta">Ballots show only an encrypted tag. Nobody reading the record can tell which ballots are revotes of one another.</p>
          </>
        ) : (
          <p className="meta">Empty until you start an election. Everything any party publishes appears here, in order, and can never be changed.</p>
        )}
      </aside>
    </div>
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
    case "ballot":
      return `Ballot ${String(body.tracking_code).slice(0, 10)}`;
    case "registration_summary":
      return "Registration counts published";
    case "registration_list":
      return `Registered ${String(body.list).replace("_", " ")} published`;
    case "finalization":
      return "Ballot box: secret 'counts' flags, with proofs";
    case "shuffle":
      return `Trustee ${body.mixer} shuffled batch ${body.batch}`;
    case "flag_shares":
      return `Trustee ${body.index} decrypted shuffled flags`;
    case "tag_shares":
      return `Trustee ${body.index} decrypted counted tags`;
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
