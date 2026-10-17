# Roadmap and stage gates

| Stage | Scope | Status | Exit criterion |
|---|---|---|---|
| 01 Requirements & governance | Jurisdiction (India), legal scope, threat model, invariants | **Done (draft)** | Requirements and threat model reviewed by at least one external reviewer |
| 02 Repository & reproducible development | CI, lint, SHA-pinned actions, hash-locked deps, CodeQL, dependency review, security policy, branch protection script | **Done** | Clean clone → passing tests on CI |
| 03 Synthetic election prototype | Roll, credentials, ballot box, board, lifecycle, threshold tally, observer report | **Done** | Invariants hold under automated tests (`spec/invariants.md`) |
| 04 Protocol & security verification | Independent cryptographic review; second verifier in another language (**TypeScript verifier done, same author**) and by another team; coverage-guided fuzzing; formal model of the lifecycle (e.g. TLA+ or Tamarin for the protocol) | Partial | No unresolved critical findings |
| 05 Scale & resilience | 10,000-voter simulation **done**; national federation, streaming verification, group commit, idempotent retries, constituency-scale counting **done** (`docs/scale.md`); networked service, full-volume dress rehearsal, DoS testing, continuous checkpoint gossip still to do | Partial | Documented capacity and tested recovery under network faults |
| 06 Independent evaluation & legal gate | Pen test, privacy assessment, operational audit, authority approval | Out of scope for this repository | Written authorisation from a competent election authority |

## Open design items (highest risk first)

1. **Credential minting by the eligibility authority (R2).** Implement multi-authority issuance (each credential needs signatures from ≥ 2 independent issuers) and a participation-sampling audit tool.
2. **Coercion (R3).** Evaluate re-voting with last-vote-counts and JCJ-style fake credentials; document the usability cost.
3. **Voter UI.** A browser demo now exists (`web/`). Still needed for any pilot: Benaloh challenge on a second device, constant-time big-integer arithmetic, a WCAG 2.2 AA audit with screen-reader users, Hindi + English first, then scheduled languages.
4. **Standardised credentials.** Replace RSA-FDH with an audited RFC 9474 implementation.
5. **Mixnet or batched posting** to remove arrival-order correlation.
6. **Second verifier** (Rust or Go) maintained by a different team.
