# Denial of service and dress rehearsals

**Verdict.** Application-level abuse (junk, oversized bodies, unregistered or replayed ballots, broken proofs from registered attackers, slow and idle connections) is handled in the server and tested end to end under load. Network-level floods (volumetric, SYN, UDP reflection) must be absorbed **before** traffic reaches the server, by a CDN or anycast scrubbing provider; that layer is tested with the provider, not from a laptop. Every rehearsal publishes its raw data.

## Defences in the ballot-intake server (`service/sequencer.py`, `service/httpd.py`)

Cheapest first; an attacker must pass each layer before costing the next.

| # | Layer | Default | Refusal |
|---|---|---|---|
| 1 | Connection cap; header and body deadlines; idle timeout | 20,000 connections; 5 s headers; 10 s body; 30 s idle | connection closed |
| 2 | Body and header size, from `Content-Length` | 512 KiB body, 8 KiB headers | 413 / 431 |
| 3 | Per-client token bucket (the edge sets `X-Client`) | 2/s, burst 10 | 429 `RATE_LIMITED` |
| 4 | Load shedding: bounded verification queue | 32 per worker | 503 `OVERLOADED` + `Retry-After` |
| 5 | Exact JSON schema, election, constituency | — | 400 `MALFORMED` … |
| 6 | Idempotent replay of a recorded ballot (same tag) | — | 200 with the original receipt, no proof work |
| 7 | Tag must be registered (database lookup) | — | 403 `UNREGISTERED_TAG` |
| 8 | Per-tag interval: one expensive check per tag per interval | 2 s | 429 `TAG_RATE_LIMITED` |
| 9 | Proof verification in a bounded process pool | CPU − 1 workers | 400 `BAD_*` |
| 10 | Group commit: one transaction + fsync per batch; receipt only after fsync | ≤ 256 per batch, ≤ 50 ms wait | — |

Clients retry with exponential backoff and jitter; retries are safe because of layer 6. Revocations are not visible at any layer (a revoked tag is still "registered"), so the server leaks nothing to a coercer.

What a botnet can still do: spend layers 1–8 (cheap) at whatever rate the edge lets through, and a registered attacker can force one proof check per 2 s per registration it controls. With identity-checked registration, that bounds proof-check abuse by the number of real identities an attacker controls.

## Dress rehearsal (`chunaviq rehearse`)

A real constituency election, end to end, over HTTP, with the 2048-bit group and a real clock:

1. Manifest, trustee HSM key ceremony, synthetic roll.
2. Every participating voter verifies identity (Aadhaar or PAN, synthetic) and registers a tag.
3. Devices pre-encrypt ballots and ~10% revotes (on real phones this is not server load).
4. The hardened server starts as its own process.
5. Honest voters arrive as a Poisson stream in three phases — **baseline**, **under attack** (all seven floods at once), **surge at 1.5×** — while server metrics are sampled every second.
6. Close; finalization; mixing by three trustees; HSM-gated decryption; result.
7. The independent verifier checks the record.
8. Outputs: `summary.json`, `requests.csv` (every request), `server-metrics.csv` (every second), `verify.json`, `report.md`, and the full election record.

| Profile | Ballot | Load | Attack rates (per second) | Runs where |
|---|---|---|---|---|
| `smoke` | 4 options | 90 s at 2 ballots/s | junk 10, oversize 2, unregistered 10, bad proof 5, replay 5, slowloris 0.5, idle 1 | CI on every push; any laptop |
| `mini-peak` | 16 options | 120 s at the design rate or 70% of this machine's capacity | junk 60, oversize 6, unregistered 60, bad proof 12, replay 30, slowloris 1, idle 4 | `make check-mini` (with the 2,000-voter end-to-end test); ~5–8 min on 16 threads |
| `shard-peak` | 16 options | 600 s at the largest constituency's design rate (128/s), or 70% of what this machine can verify | junk 300, oversize 30, unregistered 300, bad proof 60, replay 150, slowloris 5, idle 20 | a desktop or server; ~1–2 h on 16 threads |

Pass criteria: every honest ballot recorded (after retries), every receipt on the board, every attack refused, record **VERIFIED**, counts equal ground truth.

### Run and publish on your machine

```bash
make rehearsal-peak                                   # writes rehearsal/shard-peak/
d=audits/rehearsal-shard-peak-$(date +%F) && mkdir -p "$d" && \
cp rehearsal/shard-peak/{summary.json,verify.json,report.md,server-metrics.csv} "$d"/ && \
gzip -c rehearsal/shard-peak/requests.csv > "$d/requests.csv.gz" && \
cp rehearsal/shard-peak/summary.json web/public/evidence/rehearsal-shard-peak.json && \
git add "$d" web/public/evidence && git commit -m "Publish shard-peak dress rehearsal" && git push
```

The website's *Evidence* page reads `web/public/evidence/rehearsal-*.json`.

## Full national rehearsal (what it would take)

Constituencies share nothing while voting, so a national rehearsal is 543 shard rehearsals in parallel on the production infrastructure:

1. Deploy the production topology: edge (CDN/anycast, TLS, rate limits) → stateless verifier fleet → 543 sequencers with hot standbys and synchronous replication to a second region.
2. Generate synthetic electorates per shard (`chunaviq federate` already produces the national manifest, one national HSM key ceremony and shard records).
3. Drive load from many regions with `service/loadgen.py` at each shard's design rate for at least the busiest-hour duration, with the attack mix above, plus provider-run volumetric floods against the edge.
4. Kill sequencers, drop a region, and take a trustee offline during the run; confirm standbys take over and nothing is recorded twice.
5. Close, finalize, mix, decrypt, publish; run the federation verifier on independent machines; publish everything.

None of that can be done from this repository. What the repository proves is the per-shard behaviour under attack and the absence of cross-shard coupling.
