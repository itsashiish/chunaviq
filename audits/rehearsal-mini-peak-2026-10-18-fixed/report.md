# Dress rehearsal: mini-peak

**Verification: VERIFIED** (0 failures, 0 warnings). Every receipt handed to an honest voter is on the board: **True**.

Machine: 16 cores, Linux-7.0.0-38-generic-x86_64-with-glibc2.43, Python 3.14.4 (gmpy2). Software 0.2.0, source digest `36fc377f369b80229ec0240f51ce51dd6169d3b0a013968e60708f6791f1134c`.

Honest rate 99.7 ballots/s = 77.9% of the largest constituency's design rate (128/s). Verifying one 16-option ballot costs 60 ms of one core here, so the full design rate needs about 8 cores at this cost.

| Phase | Honest sent | Recorded in the end | Recorded within 30 s | p50 / p95 / p99 latency | Mean attempts | Attack requests |
|---|---|---|---|---|---|---|
| 1-baseline | 3606 | 3606 (100.0%) | 3606 (100.0%) | 0.43s / 0.65s / 0.74s | 1 | 0 |
| 2-under-attack | 4728 | 4728 (100.0%) | 4728 (100.0%) | 0.32s / 0.60s / 0.68s | 1 | 8192 |
| 3-surge-1.5x | 5345 | 5345 (100.0%) | 5203 (97.343%) | 5.24s / 26.76s / 34.11s | 3.761 | 3139 |

## What the attacks got

| Attack | Outcomes (HTTP status, code: count) |
|---|---|
| junk | 400 MALFORMED: 2328, 429 RATE_LIMITED: 953, 503 OVERLOADED: 645 |
| oversize | 413 BODY_TOO_LARGE: 398 |
| unregistered | 403 UNREGISTERED_TAG: 2353, 429 RATE_LIMITED: 953, 503 OVERLOADED: 657 |
| bad_proof | 400 BAD_SELECTION_PROOF: 268, 429 RATE_LIMITED: 185, 429 TAG_RATE_LIMITED: 181, 503 OVERLOADED: 135 |
| replay | 200 IDEMPOTENT: 1203, 429 RATE_LIMITED: 475, 503 OVERLOADED: 300, 429 TAG_RATE_LIMITED: 7 |
| slowloris | 0 CLOSED_BY_SERVER: 61 |
| idle_conns | 0 CLOSED_BY_SERVER: 229 |

Expensive proof checks actually run by the server: 13947 (honest ballots plus at most one per attacker tag per interval).

## Stages

| Stage | Seconds |
|---|---|
| setup_s | 0.3 |
| registration_s | 32.5 |
| device_encryption_s | 78.5 |
| load_s | 137.7 |
| finalization_s | 90.8 |
| mix_and_tally_s | 194.4 |
| independent_verification_s | 360.9 |
| total_s | 988.2 |

Files: `summary.json` (everything above), `requests.csv` (every request), `server-metrics.csv` (server state every second), `verify.json` (independent verifier), `election/record/` (the public record), `election/hsm/` (trustee HSM logs).
