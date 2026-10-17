# Test strategy

The suite checks that the system works **and that it fails safely**. Invariant-to-test mapping: `spec/invariants.md`.

| Category | Files | What is covered | Not covered (and why) |
|---|---|---|---|
| Functional | `test_end_to_end.py`, `test_election_rules.py` | Open/close, valid and invalid ballots, ballot styles, totals equal ground truth, FPTP/NOTA/tie rule | — |
| Eligibility | `test_election_rules.py`, `test_concurrency_recovery.py` | Not on roll, wrong secret + lockout, revoked, revoke-after-issue refused, one credential per voter, 16-way concurrent requests | Real authentication factors (simulated) |
| Privacy | `test_privacy.py` | Identity absent from record, ballot-box DB, logs; eligibility DB never sees tokens/ballots; hour-granular time; sorted commitments; trustees decrypt only aggregates | Network-level correlation (no network layer) |
| Cryptography | `test_crypto_core.py`, `test_threshold_blind_merkle.py` | Group soundness, subgroup checks incl. order-2 element, fixed-base equivalence, injective hash encoding, homomorphism, proof completeness and soundness (every field tampered), context binding, every k-subset decrypts, k−1 cannot, forged shares, blind-signature binding, RFC 6962 trees/inclusion/consistency vs reference | Formal proofs; side channels |
| Property-based / fuzzing | Hypothesis across the above; `test_fuzzed_ballots_never_crash_and_never_accepted` | Random structural mutations of ballots never crash and are never accepted; Merkle properties for all sizes | Coverage-guided fuzzing (e.g. Atheris) — roadmap |
| Concurrency | `test_concurrency_recovery.py` | Same ballot ×16, same credential different ballots ×16, same voter credential ×16, distinct voters in parallel | Multi-process writers (single-writer by design) |
| Adversarial | `test_tamper.py`, simulation attacks | Outsider edits, deletes, truncates, forks; insider with board key re-signs; insider with officer + board keys changes counts or winner; forged shares; post-close injection; manifest swap; insecure group; pins | Compromised trustee quorum (by assumption) |
| Availability / recovery | `test_concurrency_recovery.py` | Board reload; truncated history refused; forged checkpoint refused; DB loss; crash between append and commit; tally without quorum aborts before publishing; exactly-k tally; backup restore | Load/DoS against a network service |
| Scale | `test_end_to_end.py::test_scale_10000_voters` (`-m slow`), `audits/scale-10k/` | 10,000 eligible voters, 5 constituencies, full verification | Peak-concurrency load testing of a deployed service |
| Accessibility | — | The observer report uses semantic tables, `lang`, no colour-only meaning, no scripts | **No voter UI exists yet**, so keyboard/screen-reader/mobile/language testing has nothing to test. Required before any tier-2 pilot. |
| Independence | `test_end_to_end.py` | Verifier imports nothing from `evlab`; constants match; groups re-derive from seed | A second implementation by another team |

## Running

```bash
pip install -e ".[dev,fast]"
pytest -m "not slow"                       # ~1 minute
HYPOTHESIS_PROFILE=deep pytest -m "not slow"   # 500 examples per property
pytest -m slow                             # 10,000-voter election (~tens of minutes on 2 cores)
```
