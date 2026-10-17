# ChunavIQ

*Chunav* (चुनाव) means election.

**Research prototype** of an end-to-end verifiable, secret-ballot online election, with an **independent verifier** and an adversarial test suite. Legal and audit scope tailored to **India**.

Live demo: **https://chunaviq.oglic.com** — cast a secret ballot in a synthetic election, try to cheat, count, and verify it yourself, all in the browser. The 10,000-voter observer report is at `/report`.

> ⚠️ **Synthetic data only. Not certified. Not authorised. Not for any binding election.**
> Only the Election Commission of India (Art. 324) or a State Election Commission (Arts. 243K, 243ZA) can authorise a voting method for a real election. A passing test suite is evidence for researchers, not permission to run an election. See [`docs/legal-scope-india.md`](docs/legal-scope-india.md).

## What it does

```
voter device ──identity + blinded token──▶ eligibility authority ──blind signature──▶ voter device
voter device ──anonymous credential + encrypted ballot + ZK proofs──▶ ballot box ──▶ public record
k-of-n trustees ──proven partial decryptions of per-option totals──▶ public record
public record ──▶ independent verifier ──▶ VERIFIED / NOT VERIFIED + observer report
```

| Property | How |
|---|---|
| Only eligible voters, once each | Authenticated, blind-signed, constituency-bound credential; one per voter; one ballot per credential |
| Secret ballot | Threshold ElGamal (no single party can decrypt; individual ballots are never decrypted) + unlinkable credentials |
| Valid ballots only | Zero-knowledge proofs: every option is 0 or 1, exactly one selected (NOTA included) |
| Voter can check their ballot | Tracking code + Merkle inclusion proof; Benaloh cast-or-challenge to catch a lying device |
| Anyone can check the result | Append-only RFC 6962 log, signed checkpoints, homomorphic tally, proven decryption, independent verifier |

What it **does not** solve — coercion, vote-buying via self-revealed receipts, malicious devices that suppress challenges, denial of service, and credential minting by a dishonest eligibility authority — is written down in [`docs/threat-model.md`](docs/threat-model.md). Those gaps are the main reason this project does not recommend remote online voting for binding public elections.

## National scale

Designed and tested for a 100–150 crore elector, seven-day election: one independent shard per constituency, a signed national layer, streaming verification with bounded memory, and counting that works at 58 lakh votes per option. Unit costs are measured and the national figures modelled from them: about 3,200 CPU cores verify ballots at the busiest hour. Details, and what remains open: [`docs/scale.md`](docs/scale.md).

```bash
make scale-national                         # national-scale property tests
chunaviq federate out --shards 24 && chunaviq verify-federation out
make capacity                               # re-measure and regenerate docs/scale/capacity.md
```

## The browser demo (`web/`)

A second, independent implementation of the protocol in TypeScript (React + Vite) that runs a complete election inside one browser tab: key ceremony, blind credential, ballot encryption on the voter's device with a Benaloh check, a 110-voter synthetic crowd, six cheating attempts, threshold tally, full verification, and three record-tampering attempts.

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
make test               # ~150 tests, about a minute
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
| 10,000-voter run | [`audits/scale-10k/`](audits/scale-10k/) — 6,837 ballots, 5 constituencies, every injected attack refused (an identical replay gets its original receipt), independently VERIFIED, counts equal ground truth |
| Self-assessment | [`audits/2026-10-17-self-assessment.md`](audits/2026-10-17-self-assessment.md) — including a receipt-freeness defect the fuzzer found and its fix |
| Invariants → tests | [`spec/invariants.md`](spec/invariants.md) |

## Repository map

| Path | Contents |
|---|---|
| `src/chunaviq/crypto/` | Group (seed-derived), ElGamal, ZK proofs, threshold keys, blind credentials, Merkle log, Ed25519 roles |
| `src/chunaviq/election/` | Manifest, synthetic roll, eligibility authority, voter device, ballot box, board, administration/tally, simulation |
| `src/chunaviq_verify/` | **Independent verifier** — imports nothing from `chunaviq` |
| `src/chunaviq/report.py` | Accessible, script-free observer report |
| `spec/` | Protocol, record format, invariants |
| `docs/` | Architecture, threat model, India legal scope, privacy, key ceremony, audit procedures, test strategy, roadmap |
| `audits/` | Findings, remediation, scale evidence |
| `tests/` | Crypto, rules, concurrency, recovery, privacy, tamper (outsider + insider), end-to-end, scale |
| `tools/` | Group re-derivation, synthetic-data guard |
| `web/` | Browser demo and TypeScript engine + verifier (`web/src/engine`), UI (`web/src/App.tsx`), tests (`web/tests`) |
| `vercel.json` | Vercel build of `web/` with a strict Content-Security-Policy |
| `scripts/setup-github.sh` | Creates the GitHub repo with branch protection, security features and least-privilege Actions |

## Status

Stage 03 of 06 (see [`docs/roadmap.md`](docs/roadmap.md)). Not independently reviewed. Security reports: [`SECURITY.md`](SECURITY.md). Licence: Apache-2.0.
