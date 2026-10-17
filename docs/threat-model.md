# Threat model (protocol v2)

Attackers may have money, expertise, insider access, control of a voter's device, or physical power over a voter. No single administrator, operator or provider is assumed honest. Trust is split across roles so that most attacks need **collusion between roles meant to be held by different institutions**.

## Roles and what each can do alone

| Role | Holds | Can do alone | Cannot do alone |
|---|---|---|---|
| Election officer | Officer signing key | Publish manifest, lifecycle, aggregates, results; refuse service | Decrypt; change a count (verifiers re-derive it); add a ballot |
| Ballot box (sequencer + board) | Board key, registered-tag set, private tag ↔ ballot index | Refuse to post; sign checkpoints; see which ballots share a tag (never who); see *when* a tag voted | Alter, drop or reorder entries without breaking checkpoints; flag the wrong ballot (OR-proof + counted-tag check); learn votes |
| Eligibility authority | Roll, identity linkage, voter → tag | Refuse registration; **register tags for abstainers** (R2) | Learn any vote; know which ballot counted |
| Any one trustee (in an HSM) | One share of the national key | Refuse to take part; mix honestly or refuse | Decrypt (needs k, after close, with operator and observer quorums); forge a shuffle or share (ZK proofs) |
| Voter device | Choice, tag secret `t`, randomness | Leak the vote; encrypt a different choice (R4) | Cast for another voter; get two ballots counted |
| Network / hosting | Traffic | Deny service; observe timing | Read or alter ballots undetected |

## Threats, controls, residual risk

| Threat | Control | Evidence | Residual risk |
|---|---|---|---|
| Ineligible participation | Roll check; Aadhaar OTP/face or PAN + roll-mobile OTP + face; lockout; session-bound tag proof | I3 tests; demo attacks *PAN only*, *face of someone else* | Wrong or compromised roll; identity-provider compromise; SIM swap on the OTP path (mitigated by face on PAN path) |
| Duplicate counting | One valid tag per voter; last-ballot flag; counted tags distinct and valid | I2 tests; tamper tests *ballot box counts two ballots of one voter / a revoked tag* | — |
| Outsider ballot stuffing | Registered tag + proof of its secret | `test_unregistered_tag_rejected`, `test_insider_stuffs_a_ballot_without_tag_proof` | — |
| **Ballot stuffing by the eligibility authority** (R2) | Published `registered ≤ eligible`, sorted participation commitments each voter can look up with their salt; valid-tag list must contain every counted tag | `registration.summary` | **Reduced, not closed.** The authority can still register tags for abstainers. Detection needs voters or authorised auditors to check commitments. Splitting registration across two authorities is the next step. |
| Vote alteration in transit or storage | Ciphertexts + ZK proofs; signed append-only log | I4, I6 tests | — |
| Altering the count | Finalization OR-proofs, Terelius–Wikström shuffles, CP-proven decryption | I7 tests | — |
| Identity-to-vote linkage | Threshold decryption of totals only; encrypted tags; mixing before decrypting flags or tags | I8, I9 tests | ≥ k trustees colluding; all mixers colluding links counted tags to ballots (still not to votes unless also ≥ k) |
| Ballot copying | Every proof bound to the tag ciphertext; tag proof bound to the body; α uniqueness | I5 tests; demo attack *copy* | — |
| Ballot marking | Exact schema at every level | `test_marked_ballot_rejected` | A voter can reveal randomness for a ballot, but cannot prove it was their last |
| **Coercion / vote buying** (R3) | Revoting (last counts), polling-day override, re-registration from a new phone, hidden revocations, fakeable "it counted" proof (`docs/coercion.md`) | I17 tests; demo step 4 and 7 | **Bounded.** Fails against a coercer who controls the voter for the whole week *and* polling day. A coercer holding `t` sees in the published valid-tag list that the voter re-registered or voted in person (not a plain revote). Ballot box + eligibility collusion learns *who* voted *when*. |
| **Malicious voter device** (R4) | Benaloh cast-or-challenge; revoting from another device | demo step 4 | A device can leak the vote or hide the challenge UI |
| Lifecycle abuse | Board enforces transitions; ballot box enforces window independently; early close recorded and flagged | I1 tests | Officer can refuse to open (availability) |
| Trustee key theft or misuse | Shares generated and held in HSMs; decryption only after signed CLOSED, with 2-of-3 operator approvals and 2-of-3 observer attestations, nonce, budget; signed hash-chained audit log | I18 tests | HSM vendor or firmware compromise; the applet port to the vendor SDK must be audited |
| Database compromise / loss | Board authoritative; reconcile; backup/restore re-verifies | I11 tests | The tag ↔ ballot index is private; losing it after close means finalization must be rebuilt from the sequencer's backup |
| Split view / fork | Consistency proofs between signed checkpoints | `test_outsider_forks_checkpoint_history` | Observers must gossip checkpoints |
| **Denial of service** (R5) | Rate limits, load shedding, cheap-checks-first, per-tag interval, process-pool proofs, HTTP limits; rehearsal under 7 attack kinds (`docs/dos-and-rehearsal.md`) | I19 tests; published rehearsal | Network-layer floods need CDN/anycast scrubbing; a week-long window and polling stations reduce the impact of an outage |
| Supply chain | SHA-pinned actions, hash-locked deps, CodeQL, source digest in manifest | `.github/` | Maintainer compromise; shared dependency bugs |
| Shared defect between election code and verifier | Two verifiers (Python, TypeScript), no shared imports, re-derived group; cross-verification in CI | I12 tests | Same author; independent review is the next milestone |
| Small-subgroup / malformed elements | Membership checks on challenge-exponentiated values | crypto core tests | — |

## National scale

| Threat | Control | Residual |
|---|---|---|
| National officer drops or substitutes a constituency | Shards fixed in the signed national manifest; every shard required, bound, and using the national key | None if observers pin the national manifest hash |
| One constituency's servers compromised | Separate sequencer, board, eligibility service and record per shard | That constituency's availability; the national key is shared, but its shares sit in HSMs that decrypt only attested totals |
| Week-long window | Group commit, idempotent retries, standby sequencers; revoting turns the long window into a defence | Longer exposure for DoS |
| Traffic analysis | Hour-bucketed timestamps | A network-wide observer can link arrivals to devices |

## The browser demo

The demo at chunaviq.oglic.com runs every role in one tab, so it shows the mechanics and the evidence, not the separation of trust. Its records are independently checkable and its attacks and tampering use the real checks.

## Explicit assumptions

1. At most k − 1 trustees collude, and at least one mixer per batch is honest.
2. The eligibility authority and the ballot box are different institutions with no shared logs.
3. Observers obtain the manifest hash out of band.
4. Discrete log and DDH are hard in the 256-bit-order subgroup of a 2048-bit prime field; SHA-256 behaves as a random oracle for Fiat–Shamir.
5. The HSM enforces its applet's policy and does not leak the share.
6. A coerced voter has some private moment during the voting week or on polling day.
