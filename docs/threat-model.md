# Threat model

Attackers may have money, expertise, insider access, or control of a voter's device. No single administrator, operator or infrastructure provider is assumed honest. Trust is split across roles so that most attacks need **collusion between roles that are meant to be held by different institutions**.

## Roles and what each can do alone

| Role | Holds | Can do alone | Cannot do alone |
|---|---|---|---|
| Election officer | Officer signing key | Publish manifest, lifecycle steps, aggregates and results; refuse service | Decrypt any ballot; change a count (verifier re-derives it); add a ballot (needs a credential) |
| Board operator | Board signing key | Refuse to post; sign checkpoints | Alter/remove/reorder entries without breaking earlier checkpoints others hold; forge ballot proofs |
| Eligibility authority | Roll, RSA issuing keys | Refuse credentials; **mint credentials for non-voters** (see R2) | Learn which ballot is whose (blind signatures); decrypt |
| Any one trustee | One key share | Refuse to take part | Decrypt anything (needs k); forge a decryption share (CP proof) |
| Voter device | The voter's choice, token, nonces | Leak the vote; encrypt a different choice (see R4) | Cast twice; cast in another constituency |
| Network / hosting | Traffic | Deny service; observe timing | Read or alter ballots without detection |

## Threats, controls, residual risk

| Threat | Control in this prototype | Evidence | Residual risk |
|---|---|---|---|
| Ineligible participation | Roll check, auth with lockout, revocation, per-constituency blind-signed credentials | I3 tests | Wrong or compromised roll; credential theft from a voter's device |
| Duplicate voting | Unique issuance; unique token; verifier recounts | I2 tests incl. 16-thread races | — |
| Ballot stuffing by an outsider | Credential required; proofs bound to token | `test_insider_stuffs_a_ballot_without_credential` | — |
| **Ballot stuffing by the eligibility authority** (R2) | Published per-constituency issued count, `ballots ≤ issued ≤ eligible` check, salted participation commitments each voter can look up | `reconciliation.participation` | **Open.** The authority can mint credentials for abstainers. Detection relies on voters (or authorised auditors holding salts) checking participation commitments. Mitigation candidates: split issuance across ≥ 2 independent authorities (every credential needs all signatures); risk-limiting sampling of commitments by an authorised auditor. |
| Vote alteration in transit or storage | Ciphertexts + ZK proofs; signed, append-only log | I4, I6 tests; insider re-signing tests | — |
| Altering the published result | Homomorphic tally + CP-proven threshold decryption; verifier recomputes | `test_insider_with_officer_key_changes_result` | — |
| Identity-to-vote linkage by an official | Threshold decryption (no individual decryption ever); blind credentials separate identity from ballot | I8, I9 tests | Collusion of ≥ k trustees decrypts individual ballots. Timing: issuance and casting are separate services, record uses hour buckets, but a network observer sees both. |
| Ballot copying (vote "the same as" a target) | Proofs bound to token; α uniqueness | I5 tests | — |
| Ballot marking for a vote buyer | Exact schema at every level | `test_marked_ballot_rejected` | Voter can still reveal their nonces (receipt). Remote voting is not receipt-free. |
| **Coercion / vote buying** (R3) | None technical | — | **Open.** Remote voting cannot guarantee a private, coercion-free setting. Re-voting (last vote counts) and fake-credential schemes (JCJ/Civitas) are research directions; neither is implemented. This is the main reason the project does not recommend remote voting for binding public elections. |
| **Malicious voter device** (R4) | Benaloh cast-or-challenge | `benaloh_audits` in simulation summary | A device can still leak the vote, or suppress the challenge UI. Detection needs a second, independent device for audits. |
| Malicious administrator changes lifecycle | Board enforces transition order; window enforced by ballot box independently of the officer; early close must be recorded and is flagged | I1 tests | Officer can refuse to open (availability). |
| Database compromise / loss | Board authoritative; index rebuildable; reconciliation | I11 tests | Loss of the board itself before observers mirror it — mitigate by continuous public mirroring of checkpoints. |
| Split view / fork of the record | Consistency proofs between signed checkpoints | `test_outsider_forks_checkpoint_history` | Observers must compare the checkpoints they each received (gossip). Not automated. |
| Denial of service | Out of scope in-process | — | **Open.** A targeted outage can disenfranchise voters. |
| Supply chain | SHA-pinned actions, hash-locked dependencies, CodeQL, dependency review, published source digest in manifest, release attestations | `.github/` | Compromised maintainer credentials; shared dependency bugs (`cryptography`, optional `gmpy2`). |
| Shared defect between election code and verifier | Separate package, no imports, own constants, re-derived group | I12 tests | Same author, same language, same spec. A second verifier written by a different team in a different language is the next milestone. |
| Small-subgroup / malformed elements | Membership checks on every challenge-exponentiated value; range checks on commitments | `test_is_element_rejects_small_order_and_out_of_range`, `test_chaum_pedersen` | — |

## The browser demo

The demo at chunaviq.oglic.com runs every role in one tab so a visitor can watch them interact. It therefore demonstrates the *mechanics* and the *evidence*, not the separation of trust: whoever controls that tab controls every role. Its records are still independently checkable, and its cheating and tampering experiments use the real checks.

## Explicit assumptions

1. At most k − 1 trustees collude.
2. The eligibility authority and the ballot box are operated by different parties with no shared logs.
3. Observers obtain the manifest hash through a channel the attacker does not control.
4. Discrete log in the 256-bit-order subgroup of a 2048-bit prime field and the one-more-RSA-inversion problem are hard; SHA-256 behaves as a random oracle for Fiat–Shamir.
5. The `cryptography` library's Ed25519 and RSA key generation are correct.
