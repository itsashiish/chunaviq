# Test strategy

The suite checks that the system works **and that it fails safely**. Invariant-to-test mapping: `spec/invariants.md`.

| Category | Files | What is covered | Not covered (and why) |
|---|---|---|---|
| Functional | `test_end_to_end.py`, `test_election_rules.py` | Open/close, valid and invalid ballots, ballot styles, totals equal ground truth, FPTP/NOTA/tie rule | — |
| Eligibility & identity | `test_election_rules.py`, `test_concurrency_recovery.py` | Every identity method; unknown Aadhaar; not on roll; wrong OTP + lockout; impostor face; PAN alone refused; Aadhaar and PAN resolve to one roll entry; session-bound proofs; tag reuse; re-registration limit; in-person override; 16-way concurrent registrations | Real UIDAI / PAN services (synthetic) |
| Revoting & coercion | `test_election_rules.py`, `test_end_to_end.py`, `test_v2_proofs.py` | Revotes numbered and limited; revoked tags accepted while voting; last ballot counts; re-register and in-person scenarios; designated-verifier proof convinces only the voter | Human factors |
| Privacy | `test_privacy.py` | Identity absent from record, ballot-box DB, logs; identity numbers HMAC'd; revotes unlinkable in the record; hour-granular time; sorted lists; trustees never decrypt an individual vote | Network-level correlation |
| Cryptography | `test_crypto_core.py`, `test_threshold_merkle.py`, `test_v2_proofs.py` | Group soundness, subgroup checks, injective hash encoding, homomorphism, proof completeness and soundness (every field tampered), context binding, tag proofs, finalization OR-proofs, shuffle completeness and soundness, generator independence, every k-subset decrypts, k−1 cannot, forged shares, RFC 6962 trees | Formal proofs; side channels |
| Key custody | `test_custody.py` | In-HSM ceremony, share never in plaintext, every policy refusal, observer refusal, chained signed log, seal/unseal/clone, Feldman check inside | Real HSM firmware |
| Property-based / fuzzing | Hypothesis across the above; `test_fuzzed_ballots_never_crash_and_never_accepted` | Random structural mutations of ballots never crash and are never accepted; Merkle properties for all sizes | Coverage-guided fuzzing (e.g. Atheris) — roadmap |
| Concurrency | `test_concurrency_recovery.py`, `test_scale.py` | Same ballot ×16, concurrent revotes, concurrent registrations of one voter, distinct voters in parallel, group-commit races | Multi-process writers (single-writer by design) |
| Adversarial | `test_tamper.py`, simulation attacks, web attacks | Outsider edits, deletes, truncates, forks; insider re-signs; ballot box counts two ballots of one voter or a revoked tag; finalization flipped after mixing; mixer replaces a row; officer changes counts or winner; forged shares; post-close injection; manifest swap; pins | Compromised trustee quorum (by assumption) |
| Availability / recovery | `test_concurrency_recovery.py` | Board reload; truncated history refused; forged checkpoint refused; board/index divergence detected; finalization refused while open; tally without quorum aborts before publishing; exactly-k tally; backup restore | Multi-region failover |
| DoS & rehearsal | `test_service.py` (`-m rehearsal`), CI `rehearsal` job | Token bucket, HTTP limits, connection cap; full smoke election over HTTP under seven attack kinds, verified | Network-layer floods; multi-machine load |
| Scale | `test_scale.py` (`-m scale`), `test_end_to_end.py::test_scale_10000_voters` (`-m slow`), `audits/scale-10k/` | Counting at 58 lakh; federation with one national key; bounded memory; ingest; 10,000 voters end to end | 150 crore ballots (modelled, `docs/scale/capacity.md`) |
| Web app | `web/tests/` | Engine and verifier, Python↔TS interop, full UI flow (register, cast, revote, crowd, 8 attacks, count, verify, 5 tampers), Methods/Law/Evidence pages | Screen-reader and language testing with users |
| Independence | `test_end_to_end.py` | Verifier imports nothing from `chunaviq`; constants match; groups re-derive from seed | A second implementation by another team |

## Running

```bash
pip install -e ".[dev,fast]"
make test                 # pytest -m "not slow and not scale and not rehearsal", a few minutes
make deep                 # 500 examples per property
make scale-national       # pytest -m scale
make scale                # 10,000-voter election (-m slow)
pytest -m rehearsal       # service tests + smoke dress rehearsal
make web-test             # TypeScript engine, interop and UI
```
