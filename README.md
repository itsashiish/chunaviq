# ChunavIQ

*Chunav* (चुनाव) means election.

**Research prototype** of an end-to-end verifiable, secret-ballot online election, with an **independent verifier** and an adversarial test suite. Legal and audit scope tailored to **India**.

Live demo: **https://chunaviq.oglic.com** — prove who you are with a synthetic Aadhaar or PAN, cast a secret ballot, vote again in private, try to cheat, count, and verify it yourself, all in the browser. Also on the site: **How it works** (every method and algorithm, stage by stage), **Law** (what Indian law would need to say), and **Evidence** (dress-rehearsal and capacity results). The 10,000-voter observer report is at `/report`.

> ⚠️ **Synthetic data only. Not certified. Not authorised. Not for any binding election.**
> Only the Election Commission of India (Art. 324) or a State Election Commission (Arts. 243K, 243ZA) can authorise a voting method for a real election. A passing test suite is evidence for researchers, not permission to run an election. See [`docs/legal-scope-india.md`](docs/legal-scope-india.md).

## What it does

```
voter device ──Aadhaar or PAN check + T = g^t──▶ eligibility authority   (one registered tag per voter)
voter device ──encrypted ballot + Enc(T) + ZK proofs──▶ ballot box ──▶ public record   (vote again any time; last counts)
polling station ──voted in person──▶ eligibility authority   (online registration revoked)
after close: ballot box ──encrypted "last ballot" flags + proofs──▶ record
             3 trustees ──verifiable shuffles──▶ record ──▶ threshold decryption in HSMs: flags, counted tags, totals
public record ──▶ two independent verifiers (Python, TypeScript) ──▶ VERIFIED / NOT VERIFIED
```

| Property | How |
|---|---|
| Only eligible voters, once each | Identity check (Aadhaar OTP/face, or PAN + roll-mobile OTP + face) registers one tag per roll entry; counted tags are proven distinct and registered |
| Coercion and vote buying | Revote in private; polling-day override; re-register a seized phone; nobody can tell which ballot counted; the voter's "it counted" proof is fakeable ([`docs/coercion.md`](docs/coercion.md)) |
| Secret ballot | Threshold ElGamal with shares in HSMs; tags encrypted; mixing before any flag or tag is decrypted; votes decrypted only as totals |
| Valid ballots only | Zero-knowledge proofs: every option 0 or 1, exactly one selected (NOTA included), tag known and bound to the ballot |
| Voter can check their ballot | Tracking code + Merkle inclusion proof; Benaloh cast-or-challenge; designated-verifier proof that the last ballot counted |
| Anyone can check the result | Append-only RFC 6962 log, signed checkpoints, finalization OR-proofs, Terelius–Wikström shuffle proofs, proven decryption |
| Survives abuse | Ten DoS layers, cheapest first; dress rehearsal under seven attack kinds with published raw data ([`docs/dos-and-rehearsal.md`](docs/dos-and-rehearsal.md)) |

What it **does not** solve — a coercer who controls a voter for the whole week and polling day, a malicious device that hides from challenges, network-layer floods (need a CDN/anycast layer), registration of abstainers by a dishonest eligibility authority, and the law — is written down in [`docs/threat-model.md`](docs/threat-model.md).

## National scale

Designed and tested for a 100–150 crore elector, seven-day election: one independent shard per constituency under one national HSM-held key, a signed national layer, streaming finalization, mixing and verification with bounded memory, and counting at 58 lakh votes per option. Unit costs are measured and the national figures modelled from them ([`docs/scale/capacity.md`](docs/scale/capacity.md)). Details, and what remains open: [`docs/scale.md`](docs/scale.md).

```bash
make scale-national                         # national-scale property tests
chunaviq federate out --shards 24 && chunaviq verify-federation out
make capacity                               # re-measure and regenerate docs/scale/capacity.md
make rehearsal-smoke                        # an election over HTTP under attack, end to end (minutes)
make rehearsal-peak                         # the largest constituency's design rate (1-2 h on 16 threads)
```

## The browser demo (`web/`)

A second, independent implementation of the protocol in TypeScript (React + Vite) that runs a complete election inside one browser tab: key ceremony, Aadhaar-or-PAN registration, ballot encryption on the voter's device with a Benaloh check, revoting and a new phone, a 110-voter synthetic crowd (with revotes and polling-day voters), eight cheating attempts, finalization, three verifiable shuffles, threshold tally, full verification with the voter's "it counted" check, and five record-tampering attempts.

* Heavy cryptography runs in Web Workers; nothing is sent anywhere. There is no backend.
* Records made in the browser pass the **Python** verifier, and Python-made records pass the **TypeScript** verifier. CI checks both directions on every push.
* In the demo all roles (officer, trustees, eligibility authority, ballot box) live in the same tab so you can watch them. That is for teaching only; the security argument depends on those roles being run by different institutions.

```bash
make web-install && make web-test     # engine, interop and full UI-flow tests
make web-dev                          # http://localhost:5173
```

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
make install            # hash-locked deps, editable install
make test               # ~200 tests, a few minutes
make demo               # 1,000-voter synthetic election → verify → run/observer-report.html
```

Run a full-size election and verify it yourself:

```bash
chunaviq simulate out --voters 10000
chunaviq verify out/record --expect-manifest-hash "$(python -c "import json;print(json.load(open('out/summary.json'))['manifest_hash'])")" --json out/verify.json
chunaviq report out/verify.json out/observer-report.html
```

## Evidence

| | |
|---|---|
| 10,000-voter run | [`audits/scale-10k/`](audits/scale-10k/) — v0.1.0 run, independently VERIFIED, counts equal ground truth (regenerate for v2 with `make scale`) |
| Dress rehearsals | [`audits/`](audits/) `rehearsal-*` — elections over HTTP under seven attack kinds, with every request and every second of server state |
| Self-assessment | [`audits/2026-10-17-self-assessment.md`](audits/2026-10-17-self-assessment.md) — including a receipt-freeness defect the fuzzer found and its fix |
| Invariants → tests | [`spec/invariants.md`](spec/invariants.md) |

## Repository map

| Path | Contents |
|---|---|
| `src/chunaviq/crypto/` | Group (seed-derived), ElGamal, ZK and generic sigma/OR proofs, verifiable shuffle, threshold keys, Merkle log, Ed25519 roles |
| `src/chunaviq/election/` | Manifest, synthetic roll and identity services, eligibility authority, voter device, ballot box + finalization, board, mixing/tally, simulation, federation |
| `src/chunaviq/custody.py` | Trustee applet that runs inside an HSM |
| `src/chunaviq/service/` | Hardened HTTP ballot intake, load generator, dress rehearsal |
| `src/chunaviq_verify/` | **Independent verifier** — imports nothing from `chunaviq` |
| `src/chunaviq/report.py` | Accessible, script-free observer report |
| `spec/` | Protocol, record format, invariants |
| `docs/` | Architecture, threat model, coercion, identity, DoS and rehearsal, India legal scope, privacy, key ceremony, audit procedures, scale, test strategy, roadmap |
| `audits/` | Findings, remediation, scale evidence |
| `tests/` | Crypto, rules, concurrency, recovery, privacy, tamper (outsider + insider), end-to-end, scale |
| `tools/` | Group re-derivation, synthetic-data guard |
| `web/` | Browser demo and TypeScript engine + verifier (`web/src/engine`), UI (`web/src/App.tsx`), Methods / Law / Evidence pages (`web/src/pages`), tests (`web/tests`) |
| `vercel.json` | Vercel build of `web/` with a strict Content-Security-Policy |
| `scripts/setup-github.sh` | Creates the GitHub repo with branch protection, security features and least-privilege Actions |

## Status

Stage 03 of 06 (see [`docs/roadmap.md`](docs/roadmap.md)). Not independently reviewed. Security reports: [`SECURITY.md`](SECURITY.md). Licence: Apache-2.0.
