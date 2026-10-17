# Privacy analysis (protocol v2)

## What each party learns

| Party | Learns | Does not learn |
|---|---|---|
| Eligibility authority | Who registered, how (Aadhaar or PAN), their tag `T`, re-registrations, who voted in person | Any ballot, any vote, whether or when they voted online |
| Ballot box | Encrypted ballots, which ballots share a tag, when each tag voted | Who owns a tag; any vote |
| Board / public | Encrypted ballots (with encrypted tags), finalization flags (encrypted), shuffles, totals, registration counts, sorted commitments, sorted valid tags, the set of counted tags (after mixing) | Any vote; any identity; which ballots share a tag; which ballot counted |
| Any single trustee | Its share; decrypted totals, mixed flags and mixed counted tags (all public) | Any vote; which ballot counted (unless every mixer of that batch colludes) |
| ≥ k colluding trustees | Could decrypt individual ballots | Who cast them (unless also colluding with eligibility and the ballot box) |
| Voter | Own tracking codes, inclusion proofs, commitment, designated-verifier proof that their last ballot counted | Others' votes |

Linking a vote to a person needs ≥ k trustees **and** the ballot box **and** the eligibility authority. The price of revoting is that **ballot box + eligibility** together learn *who voted online and when* — never how.

## Leakage channels and mitigations

| Channel | Mitigation | Status |
|---|---|---|
| Timestamps | Record carries UTC hour buckets only | Done; tested |
| Which ballots are revotes | Tags are encrypted in the record; the plaintext tag and its link proof go only to the ballot box | Done; `test_public_record_does_not_link_revotes` |
| Which ballot counted | Flags are encrypted; rows are mixed by ≥ 3 trustees before flags and tags are decrypted | Done |
| Revocation (re-registration / in person) | Not published until after close; revoked tags still accepted while voting | Done; the published valid-tag list does reveal it after close to someone who knows `t` |
| Arrival order | Ballots on the board in arrival order; a network observer of both services could correlate | Residual |
| Logs | Reason codes only; tests assert no ids or tags in logs | Done; tested |
| Commitments and tag lists | Salted commitments; both lists published sorted | Done; tested |
| Identity numbers | Aadhaar and PAN references stored as keyed HMACs | Done; `test_eligibility_database_stores_no_raw_identity_numbers` |
| Small constituencies | Totals of a tiny unit can reveal votes | Documented |
| Ballot marking | Exact schemas | Done |

## Personal data

None. Aadhaar, PAN, phone numbers and faces are synthetic and generated in formats real systems would reject (`docs/identity.md`); `tools/scan_pii.py` blocks real-looking identifiers in CI. A real deployment would be significant processing under the DPDP Act, 2023; see the website's *Law* page and `docs/legal-scope-india.md`.
