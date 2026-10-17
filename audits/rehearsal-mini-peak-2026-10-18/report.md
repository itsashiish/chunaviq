# Dress rehearsal: mini-peak

**Verification: VERIFIED** (0 failures, 0 warnings). Every receipt handed to an honest voter is on the board: **True**.

Machine: 16 cores, Linux-7.0.0-38-generic-x86_64-with-glibc2.43, Python 3.14.4 (gmpy2). Software 0.2.0, source digest `9056c64ee6984d504df964b5910ab61916435f074b52ac86e6303554dc841852`.

Honest rate 128.0 ballots/s = 100.0% of the largest constituency's design rate (128/s). Verifying one 16-option ballot costs 62 ms of one core here, so the full design rate needs about 8 cores at this cost.

| Phase | Honest sent | Recorded | p50 / p95 / p99 latency | Mean attempts | Attack requests |
|---|---|---|---|---|---|
| 1-baseline | 4514 | 4469 (99.003%) | 3.39s / 7.58s / 17.13s | 1.478 | 0 |
| 2-under-attack | 6149 | 5128 (83.396%) | 6.59s / 21.68s / 28.92s | 4.718 | 8426 |
| 3-surge-1.5x | 6840 | 4944 (72.281%) | 11.04s / 29.71s / 34.42s | 6.632 | 3097 |

## What the attacks got

| Attack | Outcomes (HTTP status, code: count) |
|---|---|
| junk | 503 OVERLOADED: 2379, 429 RATE_LIMITED: 1046, 400 MALFORMED: 480, 0 CONNECTION: 8 |
| oversize | 413 BODY_TOO_LARGE: 430, 0 CONNECTION: 2 |
| unregistered | 503 OVERLOADED: 2490, 429 RATE_LIMITED: 996, 403 UNREGISTERED_TAG: 485, 0 CONNECTION: 14 |
| bad_proof | 503 OVERLOADED: 516, 429 RATE_LIMITED: 213, 400 BAD_SELECTION_PROOF: 87, 429 TAG_RATE_LIMITED: 12, 0 CONNECTION: 4 |
| replay | 503 OVERLOADED: 1273, 429 RATE_LIMITED: 501, 200 IDEMPOTENT: 250, 0 CONNECTION: 8, 429 TAG_RATE_LIMITED: 2 |
| slowloris | 0 CLOSED_BY_SERVER: 83 |
| idle_conns | 0 CLOSED_BY_SERVER: 243, 0 CONNECTION: 1 |

Expensive proof checks actually run by the server: 14859 (honest ballots plus at most one per attacker tag per interval).

## Stages

| Stage | Seconds |
|---|---|
| setup_s | 0.3 |
| registration_s | 43.1 |
| device_encryption_s | 95.7 |
| load_s | 142.8 |
| finalization_s | 96.0 |
| mix_and_tally_s | 204.6 |
| independent_verification_s | 381.9 |
| total_s | 1059.2 |

Files: `summary.json` (everything above), `requests.csv` (every request), `server-metrics.csv` (server state every second), `verify.json` (independent verifier), `election/record/` (the public record), `election/hsm/` (trustee HSM logs).
