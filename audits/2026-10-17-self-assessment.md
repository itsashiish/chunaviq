# Self-assessment — 2026-10-17 (v0.1.0)

**Type:** internal review by the authors. **Not** an independent audit; it does not satisfy the stage-04 exit criterion.
**Source digest:** `88b1000fbcce8b25105eeb54b38e397a8babee49bdfebb9b30d6c4d57393cae3`

## Findings

| ID | Severity | Status | Finding | Resolution / plan |
|---|---|---|---|---|
| F-001 | High | **Fixed** | Ballot box and verifier accepted unknown fields inside nested ballot objects (ciphertext, proof, limit proof). A voter could embed a marker (e.g. `"marker": "voter-1234"`) and prove to a vote buyer which public ballot is theirs. **Found by the property-based fuzzer** (`test_fuzzed_ballots_never_crash_and_never_accepted`). | Exact schemas at every nesting level in `ballot.py` and, independently, in `chunaviq_verify`. Regression: `test_marked_ballot_rejected` (5 positions). |
| F-002 | Medium | **Fixed** | Key ceremony destroyed each trustee's polynomial coefficients as soon as that trustee finished receiving shares, before later trustees had received theirs. Integrity was not at risk (Feldman checks failed closed) but the ceremony could not complete. Caught by the first end-to-end smoke test. | Two-phase ceremony: distribute and verify all shares, then finalise and destroy. |
| F-003 | High | Open (design) | The eligibility authority can mint credentials for registered voters who abstain and cast ballots with them (threat R2). The participation check `ballots ≤ issued ≤ eligible` cannot detect this. | Plan: multi-authority issuance; participation-sampling audit (A3 in `docs/audit-procedures.md`). |
| F-004 | High | Open (inherent) | No coercion resistance or receipt-freeness: a voter can reveal device nonces; a coercer can watch the voter vote. | Documented residual risk; the reason the project does not recommend remote voting for binding elections. |
| F-005 | Medium | Open | Ballots appear in arrival order; a party able to observe both the eligibility service and the ballot box network traffic can correlate. Hour buckets do not remove ordering. | Batching or a verifiable mixnet before posting. |
| F-006 | Medium | Partly addressed | The verifier was independent in code but not in authorship, language or specification. | A TypeScript verifier now exists and cross-verifies Python records (and vice versa) in CI. Same author and same specification remain; a verifier by another team is still needed. |
| F-007 | Medium | Partly addressed | No voter-facing UI existed. | Browser demo added with semantic controls, keyboard operation, visible focus, reduced-motion support and an automated UI-flow test. Not yet audited against WCAG 2.2 AA or tested with screen-reader users; English only. |
| F-008 | Low | Open | Credentials use RSA-FDH blind signatures rather than the standardised RFC 9474 RSABSSA. | Replace with an audited RFC 9474 implementation. |
| F-009 | Low | Mitigated | The manifest declares its own role keys, so a wholly substituted record is self-consistent. | Verifier warns unless `--expect-manifest-hash` is supplied; audit step B3 publishes the hash out-of-band. |
| F-010 | Low | Open | Constituencies with very few ballots, or unanimous results, reveal individual votes through aggregates. | Document a minimum reporting-unit size for any pilot. |
| F-012 | Low | Open (accepted for demo) | The browser engine uses JavaScript `BigInt`, which is not constant-time; a hostile script on the same page could in principle learn secrets from timing. | Acceptable for a single-tab demo with a strict Content-Security-Policy and no third-party scripts. A real client would need constant-time arithmetic (e.g. WebAssembly). |
| F-011 | Info | Accepted | `random.Random` is used for synthetic choices and roll sizes; all key material, nonces and tokens use `secrets`. | Lint rule S311 suppressed with that justification. |

## Evidence summary

* `pytest -m "not slow"`: all tests pass on Python 3.13 with the gmpy2 backend (CI matrix also runs 3.11/3.12 and the pure-Python backend).
* Deep property-based profile (500 examples per property): see CI weekly run.
* 10,000-voter election: [`scale-10k/`](scale-10k/) — independently **VERIFIED** with manifest and source-digest pins; published counts equal the simulation's ground truth in all 5 constituencies; all 9 injected attacks rejected with the expected reason codes; 149 Benaloh challenges passed; index/board reconciliation consistent.

## Capacity (2 vCPU, Python 3.13, gmpy2)

| Stage | 6,837 ballots (10,000 eligible) |
|---|---|
| Key ceremony (5 trustees, k = 3) | 0.3 s |
| Credential issuance (RSA-3072 blind signing) | 38 s |
| Client-side encryption + proofs (5 options) | 85 s (≈ 25 ms per ballot per core) |
| Server-side proof verification | 122 s (≈ 36 ms per ballot per core) |
| Sequential acceptance + board append (fsync each) | 12 s |
| Threshold tally | 2.8 s |
| **Independent verification of the whole record** | **111 s** |
| Public record size | 128 MB (6,882 entries) |

Server verification throughput (~56 ballots/s on 2 cores) is the bottleneck and scales with cores, because checks run outside the acceptance lock.
