# Privacy analysis

## What each party learns

| Party | Learns | Does not learn |
|---|---|---|
| Eligibility authority | Who requested a credential and when (hour) | The token, the signature, which ballot is theirs, any vote |
| Ballot box | An anonymous ballot, its credential, arrival order | Who cast it; the vote (encrypted) |
| Board / public | Encrypted ballots, aggregate counts, participation counts and sorted commitments | Any individual vote; any voter identity |
| Any single trustee | Its share; partial decryptions of aggregates | Any individual vote |
| ≥ k colluding trustees | **Could decrypt individual ballots** | Who cast them (unless also colluding with eligibility + timing data) |
| Voter | Own tracking code, inclusion proof, participation commitment | Others' votes |

Linking a vote to a person requires **both** decrypting the ballot (≥ k trustees) **and** linking the ballot to the person (eligibility authority + network timing, since blind signatures remove the cryptographic link). This is defence in depth, not perfect secrecy.

## Leakage channels and mitigations

| Channel | Mitigation | Status |
|---|---|---|
| Timestamps | Record carries UTC hour buckets only; issuance stored as hour bucket | Done; tested |
| Arrival order | Ballots appear in arrival order on the board. Combined with network logs, a party watching both services could correlate. | Residual; mixnet or batching is future work |
| Logs | Loggers emit reason codes only; tests assert no voter ids or tokens in logs | Done; tested |
| Participation commitments | Salted; published sorted, not in issuance order | Done; tested |
| Small constituencies | Aggregate counts for a constituency with very few ballots (or unanimous ones) reveal votes. Real elections face the same issue at booth level; ECI totalisation practice exists for this reason. | Documented; prototype does not pool small units |
| Ballot marking | Exact schemas at every nesting level | Done (finding F-001) |
| Voter-revealed nonces | Not preventable without receipt-free protocols | Residual |
| Device / endpoint | Out of the protocol's control | Residual |

## Personal data

None. The roll consists of generated `syn-v-NNNNNNN` identifiers and random authentication secrets. No names, ages, genders, addresses, phone numbers, photographs or biometrics are generated, because the protocol needs none of them. Under the DPDP Act, 2023 a real deployment would be a significant processing activity with its own obligations; see `docs/legal-scope-india.md`.
