# Roadmap and stage gates

| Stage | Scope | Status | Exit criterion |
|---|---|---|---|
| 01 Requirements & governance | Jurisdiction (India), legal scope, threat model, invariants | **Done (draft)** | Requirements and threat model reviewed by at least one external reviewer |
| 02 Repository & reproducible development | CI, lint, SHA-pinned actions, hash-locked deps, CodeQL, dependency review, security policy, branch protection script | **Done** | Clean clone → passing tests on CI |
| 03 Synthetic election prototype | Roll, Aadhaar-or-PAN registration, revoting, ballot box, finalization, mixing, HSM custody, threshold tally, observer report (protocol v2) | **Done** | Invariants hold under automated tests (`spec/invariants.md`) |
| 04 Protocol & security verification | Independent cryptographic review; second verifier in another language (**TypeScript verifier done, same author**) and by another team; coverage-guided fuzzing; formal model of the lifecycle (e.g. TLA+ or Tamarin for the protocol) | Partial | No unresolved critical findings |
| 05 Scale & resilience | 10,000-voter simulation, national federation with one HSM-held key, streaming verification, group commit, idempotent retries, constituency-scale counting **done** (`docs/scale.md`); hardened HTTP service, DoS layers and single-shard dress rehearsals under attack **done** (`docs/dos-and-rehearsal.md`); multi-machine national rehearsal, network-layer DDoS with a provider, failover drills and checkpoint gossip still to do | Partial | Documented capacity and tested recovery under network faults |
| 06 Independent evaluation & legal gate | Pen test, privacy assessment, operational audit, authority approval | Out of scope for this repository | Written authorisation from a competent election authority |

## Open design items (highest risk first)

1. **Registration of abstainers by the eligibility authority (R2).** Split registration across two independent authorities (a tag counts only if both registered it) and build the participation-sampling audit tool.
2. **Coercion residuals (R3).** The published valid-tag list lets a coercer who copied `t` see a re-registration or in-person vote; evaluate publishing only a proof that counted tags are valid (e.g. a mixed, encrypted valid-tag set) instead of the list.
3. **Revoting leak.** Ballot box + eligibility collusion learns who voted when; evaluate anonymous submission channels and dummy traffic.
4. **Elliptic-curve group.** Moving from the 2048-bit group to a 256-bit curve would cut ballot size and CPU several-fold.
5. **HSM port.** Port `custody.TrusteeApplet` to one vendor SDK and have it reviewed.
6. **Voter UI.** Benaloh challenge on a second device; constant-time arithmetic; WCAG 2.2 AA audit; Hindi and English first, then scheduled languages.
7. **Second verifier** maintained by a different team (Rust or Go).
