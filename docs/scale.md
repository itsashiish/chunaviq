# Running ChunavIQ for 100–150 crore electors over seven days

**Bottom line.** The cryptography and data structures now scale to a national election, and that claim rests on measured unit costs and tests at real constituency sizes, not on running 150 crore ballots. Throughput is a CPU-provisioning problem, not a design limit (cores at the busiest hour are in [`capacity.md`](scale/capacity.md)). Protocol v2 added revoting against coercion, Aadhaar-or-PAN registration, HSM key custody and hardened DoS handling, each tested; what software cannot settle is listed at the end.

All numbers below come from [`docs/scale/capacity.md`](scale/capacity.md), which `chunaviq capacity` regenerates from fresh measurements.

## 1. Shape of the system

```mermaid
flowchart LR
  V[150 crore voter devices<br/>encrypt + prove locally] --> LB[Anycast / CDN edge<br/>rate limits, TLS]
  LB --> VF[Stateless verifier fleet<br/>autoscaled, any region]
  VF -->|valid ballots, by constituency| S1[Sequencer PC-001<br/>single writer + standby]
  VF --> S2[Sequencer PC-002]
  VF --> S3[... 543 sequencers]
  E[Eligibility shards<br/>Aadhaar or PAN, one tag per voter] -.registered tags.-> S1
  S1 --> R1[(Record PC-001<br/>append-only, signed checkpoints)]
  S2 --> R2[(Record PC-002)]
  S3 --> R3[(Records ...)]
  R1 & R2 & R3 --> N[National index + result<br/>signed by national officer]
  R1 & R2 & R3 --> O[Observers / independent verifiers<br/>verify continuously during the week]
```

**Why one shard per constituency works with no coordination.** A voting tag is registered in exactly one constituency, and every ballot proof is bound to it, so "which ballot is this voter's last?" is a question one sequencer answers alone. Copied ciphertexts fail across shards too, because every proof is bound to its constituency. No global lock, database or cross-shard transaction exists on the voting path. After close, finalization and mixing are also per shard, in batches; only the trustees' HSMs (one national key) are shared.

| Component | Count | State | Scales by |
|---|---|---|---|
| Voter device | 150 crore | its own ballot secrets | n/a (each does ~70 ms of work) |
| Verifier fleet | see `capacity.md` (design rate) | none | adding machines |
| Sequencer (ballot box + record) | 543, one per Lok Sabha seat | registered tags, tag ↔ ballot index, ciphertext index, append-only log | adding shards (could split to ~4,120 assembly segments) |
| Eligibility service | sharded by constituency | roll, identity linkage, tags | adding shards |
| Trustees | 5, k = 3, ≥ 3 mix each batch | **one** share of the national key each, in an HSM | mixing and decryption after close: core-hours in `capacity.md` |
| National layer | 1 | signed manifest, shard index, result | n/a |

Federation format: [`spec/federation.md`](../spec/federation.md). Run one: `chunaviq federate out --shards 24`; verify it: `chunaviq verify-federation out`.

## 2. What changed in the code to make this true

| Problem found | Fix | Proof |
|---|---|---|
| Counting a seat with ~58 lakh votes by linear search: hours per option | Baby-step giant-step in all four implementations (Python and TypeScript, election and verifier) | `test_count_recovery_at_constituency_scale_both_implementations`, `test_threshold_tally_of_a_58_lakh_vote_total`: 70 ms |
| Board, tally and verifier held the **whole record in RAM**. The largest seat at 150 crore electors is ~330 GB of record | Board keeps only Merkle hashes, byte offsets and counters; tally streams; verifier streams in bounded chunks with an on-disk duplicate index | `test_verifier_memory_does_not_grow_with_record_size` (4× ballots, < 1.5× memory), `test_board_keeps_bodies_on_disk`; 10,000-voter record verified in 106 MB |
| One `fsync` per ballot | Group commit: one transaction and one `fsync` per batch; voters are acknowledged only after it | `test_group_commit_enforces_uniqueness_and_revote_limits`, `test_sequencer_ingest_beats_largest_constituency_need` |
| A device retrying after a dropped connection lost its receipt | Identical resubmissions under the same tag return the original receipt; nothing is recorded twice; the same ballot under another tag is refused | `test_identical_retry_returns_original_receipt`, 16-way concurrent retry test |
| One election = one log | National federation: per-constituency records bound to a signed national manifest and shard index | `test_federation_*`: verifies; catches a missing shard, swapped shards, an altered national result |

## 3. Your ten points, checked

| # | Point | Verdict | Detail |
|---|---|---|---|
| 1 | Distributed infrastructure | **Right, with a specific shape** | Stateless verifiers spread anywhere and autoscale. Sequencers are *stateful single writers*, one per constituency, each with a hot standby and synchronous log replication to a second region. Avoid a single global database. |
| 2 | 1,653–2,480 votes/s | **Arithmetic right, assumption wrong** | That spreads votes evenly over 24×7. People vote in daylight and rush at the end: busiest hour ≈ **14,900/s** at 150 crore and 100% turnout, **design for ~29,800/s**. More importantly, verifying a ballot costs tens of milliseconds of CPU, so this is a *CPU* problem (cores in `capacity.md`), not a requests-per-second problem. |
| 3 | Horizontal scaling, durability, idempotent retries | **Right; idempotency was missing** | Added (section 2). Durability: acknowledge only after the batch is fsynced and replicated. |
| 4 | Separate eligibility service | **Right; sharded, Aadhaar or PAN** | Aadhaar OTP/face, or PAN + roll-mobile OTP + face, all synthetic here (`docs/identity.md`). Real use needs legal authorisation (website *Law* page). |
| 5 | Secret ballot, reviewed cryptography | **Right** | Threshold decryption of totals only; tags encrypted; mixing before flags or tags are decrypted. Arrival-order linkage by a network-level observer remains (finding F-005). |
| 6 | Verifiable counting, tamper-evident logs | **Right; add timing** | Observers should **verify continuously during the week** (core counts in `capacity.md`), so only the last hours remain at close. Two independent verifier implementations already exist. |
| 7 | Pen tests, key management, DoS, insiders | **Right; HSM custody and DoS layers done** | One national key, one share per trustee, inside an HSM applet with operator and observer quorums (`docs/key-ceremony.md`). DoS layers and rehearsals under attack (`docs/dos-and-rehearsal.md`). With revoting, the seven-day window *helps* against coercion. |
| 8 | Simulate 1.5 billion synthetic electors | **Partly wrong** | Not needed for correctness and not sufficient for availability. Correctness comes from per-shard tests at real sizes, plus the fact that shards are independent, so capacity adds linearly. Availability needs a **full-volume dress rehearsal on the real infrastructure**. The repository runs one constituency end to end over HTTP under attack (`chunaviq rehearse`), at the largest seat's design rate where the machine allows; the national run is 543 of those in parallel (`docs/dos-and-rehearsal.md`). |
| 9 | GitHub for code, not votes | **Right** | Already in place: CI, reviews, SHA-pinned actions, hash-locked dependencies, release attestations. |
| 10 | Legal authorisation | **Right** | For Lok Sabha and assembly elections, remote online voting would need changes under the Representation of the People Act and Conduct of Election Rules, decided by Parliament and the Election Commission. Software readiness does not substitute. |

**Missing from the list:**
- **Record size.** Tens of TB at 150 crore electors (exact figure, with finalization and shuffles, in `capacity.md`). Switching from the 2048-bit group to an elliptic-curve group would cut ballot size and CPU several-fold. That is an estimate, not measured here, and it is the single biggest optimisation available.
- **Voter devices.** Encrypting a 16-option ballot takes ~70 ms on a server core; low-end phones are perhaps 10–30× slower, which is still seconds.
- **Constituencies with many candidates.** A 50-option ballot costs ~3× as much to verify; plan cores for the worst seat, not the average.
- **Coverage, languages and connectivity.** 22 scheduled languages, screen readers, and voters with poor connectivity. Retries are now safe, but offline voting is not possible.

## 4. What is proven, modelled and open

| Status | What |
|---|---|
| **Proven by tests** | Counting at 58 lakh votes per option; threshold tally at that size; federation verification and tamper detection; bounded verifier and board memory; group-commit uniqueness; idempotent retries; sequencer ingest above the largest seat's need |
| **Measured, then modelled** | Cores, bandwidth, storage, tally and re-verification times (`docs/scale/capacity.md`). Assumptions are explicit and editable |
| **Proven by rehearsal** | One constituency end to end over HTTP under seven attack kinds, verified, with raw data published (`audits/rehearsal-*`) |
| **Not done (needs real infrastructure)** | National 543-shard rehearsal; network-layer DDoS with a provider; multi-region failover drills; HSM applet on real vendor hardware |
| **Not solvable in software alone** | A coercer who controls a voter all week and on polling day; identity-provider compromise; legal authorisation |

## 5. Running the scale checks

```bash
make scale-national    # pytest -m scale: counting at constituency scale, federation, memory, ingest (~1-2 min)
make capacity          # re-measure unit costs, regenerate docs/scale/capacity.md
chunaviq federate out --shards 24 --voters-per-shard 300 && chunaviq verify-federation out
```
