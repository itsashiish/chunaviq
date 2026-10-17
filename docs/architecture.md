# Architecture (protocol v2)

```mermaid
flowchart LR
  subgraph Voter side
    D[Voter device<br/>chunaviq.election.client]
  end
  subgraph Separated services
    E[Eligibility authority<br/>roll · Aadhaar or PAN check · one tag per voter]
    B[Ballot box / sequencer<br/>DoS layers · proof checks · last-ballot finalization]
    T1[Trustee 1 HSM]:::t
    T2[Trustee 2 HSM]:::t
    Tn[Trustee n HSM]:::t
    O[Election officer<br/>lifecycle · aggregates · results]
    PS[Polling station<br/>in-person override]
  end
  R[(Public record<br/>append-only Merkle log<br/>signed checkpoints)]
  V[Independent verifiers<br/>Python + TypeScript]
  OBS[Observers / voters]

  D -- "identity check + T = g^t with proof" --> E
  D -- "encrypted ballot + Enc(T) + proofs;<br/>privately: T + link proof" --> B
  PS -- "voted in person" --> E
  E -- "registered tags (private)" --> B
  B -- "accepted ballots, then<br/>finalization flags + masked votes" --> R
  E -- "registration summary,<br/>sorted commitments, valid tags" --> R
  T1 & T2 & Tn -- "ceremony, shuffles,<br/>flag / tag / total decryption shares" --> R
  O -- "signed lifecycle, aggregates, results" --> R
  R --> V --> OBS
  R -- "receipt: tracking code + inclusion proof" --> D
  B -- "designated-verifier 'it counted' proof" --> D
  classDef t fill:#eee,stroke:#555
```

## Two implementations

| | Python (`src/`) | TypeScript (`web/src/engine/`) |
|---|---|---|
| Purpose | Reference engine, HTTP service, simulation, dress rehearsal, CLI | Interactive browser demo |
| Verifier | `chunaviq_verify` (no imports from `chunaviq`) | `verifier.ts` (no imports from the TS election engine) |
| Big integers | Python ints, optional GMP | `BigInt`, fixed-window exponentiation |
| Hashes / signatures | `hashlib` / `cryptography` | `@noble/hashes` (SHA-256, SHAKE-256) / `@noble/curves` |
| Parallelism | process pools (finalize, mix, verify) | Web Worker pool (prepare, precheck, finalize, mix, verify) |

Both write and read `chunaviq-record/2` byte for byte; CI cross-verifies in both directions.

## Components → code

| Component | Module | Notes |
|---|---|---|
| Identity (synthetic UIDAI, PAN, SMS, face) | `election/identity.py` | Aadhaar OTP / face; PAN name+DOB **plus** roll-mobile OTP **plus** face; HMAC-hashed identifiers |
| Eligibility & registration | `election/eligibility.py` | Roll, lockout, one tag per voter, re-registration, polling-day override, registration publication |
| Ballot protocol | `crypto/{elgamal,proofs,sigma}.py`, `election/ballot.py` | Exponential ElGamal, CDS 0/1, CP limit, tag PoK bound to body, private link proof |
| Voter device | `election/client.py` | Register, prepare, Benaloh, cast, revote, check "it counted", fake that proof |
| Ballot box | `election/ballotbox.py`, `election/board.py` | Tag-aware idempotency, revote limit, group commit, finalization with OR-proofs |
| Network service | `service/{httpd,sequencer}.py` | asyncio HTTP with limits; token bucket, load shedding, cheap-checks-first, process-pool proofs |
| Mixing | `crypto/shuffle.py`, `election/administration.py` | Terelius–Wikström shuffles by ≥ 3 trustees per batch |
| Key custody | `custody.py`, `crypto/threshold.py` | HSM applet: in-HSM DKG, sealed transport, policy-gated decryption, signed audit log, seal/clone |
| Tally | `election/administration.py` | Flags → counted tags → masked totals; BSGS |
| Federation | `election/federation.py`, `chunaviq_verify/federation.py` | One national key ceremony; 543 independent shards |
| Load & rehearsal | `service/{loadgen,rehearsal}.py` | Poisson honest voters + 7 attack kinds; full election under attack; published outputs |
| Observer interface | `report.py`, website `#/evidence` | Static report; rehearsal and capacity pages |

## Data separation

| Store | Contents | Never contains |
|---|---|---|
| `private/eligibility.db` | voter_id, HMAC'd identity references, status, tag, generation, commitment + salt, in-person flag | ballots, tracking codes |
| `private/ballotbox.db` | registered tags; tag ↔ ballot sequence (for finalization); α index | voter ids, identity data |
| `record/` (public) | everything in `spec/record-format.md` | voter ids, plaintext tags, link proofs, IPs, exact timestamps |
| Trustee HSM | one share of the national key, attestation and transport keys, audit log | other shares, the joint secret |

The ballot box's tag ↔ ballot index is private and is needed to finalize. Losing it after close means restoring the sequencer backup; it cannot be rebuilt from the public record (by design: the public cannot see which ballots share a tag).

## Concurrency and failure model

* Single writer per constituency to the board; any number of readers.
* Expensive proofs run outside the lock (process pool); uniqueness, revote limit and the board append run inside one lock and one IMMEDIATE transaction per batch.
* Finalization, mixing and decryption are refused while the election is open; all of them stream in bounded batches.
* Tally aborts **before publishing anything** without a quorum.
