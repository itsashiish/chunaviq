# Dress rehearsal: smoke

**Verification: VERIFIED** (0 failures, 0 warnings). Every receipt handed to an honest voter is on the board: **True**.

Machine: 16 cores, Linux-7.0.0-38-generic-x86_64-with-glibc2.43, Python 3.14.4 (gmpy2). Software 0.2.0, source digest `0f2e3acdcc7ab3cbf88a4e3923a1183c301b393a4fdd384a51c59f267dca50d5`.

Honest rate 2.0 ballots/s = 1.6% of the largest constituency's design rate (128/s). Verifying one 4-option ballot costs 20 ms of one core here, so the full design rate needs about 2 cores at this cost.

| Phase | Honest sent | Recorded | p50 / p95 / p99 latency | Mean attempts | Attack requests |
|---|---|---|---|---|---|
| 1-baseline | 50 | 50 (100.0%) | 0.09s / 0.09s / 0.28s | 1 | 0 |
| 2-under-attack | 84 | 84 (100.0%) | 0.09s / 0.09s / 0.09s | 1 | 1210 |
| 3-surge-1.5x | 73 | 73 (100.0%) | 0.09s / 0.09s / 3.09s | 1.014 | 469 |

## What the attacks got

| Attack | Outcomes (HTTP status, code: count) |
|---|---|
| junk | 400 MALFORMED: 519 |
| oversize | 413 BODY_TOO_LARGE: 106 |
| unregistered | 403 UNREGISTERED_TAG: 484 |
| bad_proof | 400 BAD_SELECTION_PROOF: 170, 429 TAG_RATE_LIMITED: 76 |
| replay | 200 IDEMPOTENT: 240, 403 UNREGISTERED_TAG: 4, 429 TAG_RATE_LIMITED: 2 |
| slowloris | 0 CLOSED_BY_SERVER: 25 |
| idle_conns | 0 CLOSED_BY_SERVER: 53 |

Expensive proof checks actually run by the server: 377 (honest ballots plus at most one per attacker tag per interval).

## Stages

| Stage | Seconds |
|---|---|
| setup_s | 0.2 |
| registration_s | 0.8 |
| device_encryption_s | 1.0 |
| load_s | 104.1 |
| finalization_s | 0.8 |
| mix_and_tally_s | 9.7 |
| independent_verification_s | 15.8 |
| total_s | 207.7 |

Files: `summary.json` (everything above), `requests.csv` (every request), `server-metrics.csv` (server state every second), `verify.json` (independent verifier), `election/record/` (the public record), `election/hsm/` (trustee HSM logs).
