# Coercion and vote buying

**Verdict.** Remote voting cannot guarantee a private booth, so v2 does not try to stop someone *watching* a vote. It makes a watched or bought vote **worthless**: the voter can quietly replace it, and nobody — including the coercer — can tell which ballot counted. This holds unless the coercer controls the voter for the whole voting week **and** polling day.

## Mechanisms

| Mechanism | What the voter does | Why the coercer cannot tell |
|---|---|---|
| **Revoting** | Votes again, any time in the week, from the same phone; only the last ballot counts (max 30 per registration) | Tags are encrypted in the public record, so nobody sees that two ballots belong to the same voter |
| **Hidden "which one counted"** | — | After close the ballot box marks each voter's last ballot with an *encrypted* flag and proves it did so correctly; trustees shuffle the rows before decrypting flags, so the counted set cannot be linked back to ballots |
| **Fakeable "it counted" proof** | Can ask the ballot box to prove their last ballot counted | The proof says *[this ballot counted] OR [I know the phone's secret]*. The voter's phone can make an equally valid proof for **any** ballot, so it convinces the voter and nobody else |
| **New phone** | If the coercer keeps the phone: re-registers on another phone with Aadhaar or PAN (up to 5 times). The old phone's ballots stop counting | The old phone keeps working normally during voting: revocations are not published until after close |
| **Polling-day override** | Votes in person at the polling station. The online registration is revoked and no online ballot counts | Same as above: the coercer's phone keeps accepting ballots |
| **No receipts of content** | — | The record has exact schemas (no field to hide a marker), and a receipt only proves a ballot is *recorded*, not that it is the last |

## What remains (honest residual risk)

| Attack | Effect | Why it is accepted |
|---|---|---|
| Coercer holds the voter for the whole week and polling day | Coercion succeeds | No remote or postal method prevents this; polling stations stay open |
| Coercer copies the phone secret `t`, and after close checks the published valid-tag list | Learns that the voter re-registered or voted in person (not that they merely revoted) | The valid-tag list is needed to prove only valid voters were counted. Plain revoting stays undetectable |
| Ballot box + eligibility authority collude | Learn *who* voted online and *when* (not how) | The price of revoting: the box must know which ballots share a tag. Different institutions, no shared logs (`threat-model.md` assumption 2) |
| Vote buyer demands the phone *after* close | Nothing to see: the phone cannot prove which ballot counted | — |
| Family voting (watching at home) | The voter can revote later alone, or vote in person | Same as postal ballots today |

## Why this design and not JCJ / Civitas fake credentials

JCJ-style schemes give coerced voters fake credentials that look real. They need the voter to keep a secret credential *and* a pre-arranged lie, cost quadratic or heavy plaintext-equivalence work at tally, and are hard to explain. Revoting with a polling-day override matches how Estonia has run internet voting since 2005, needs nothing from the voter beyond "vote again", and fits the existing polling-station system. The cost is the collusion leak above.

## Where to see it

* Demo step 4 (vote, then vote again), step 7 ("Your last ballot is the one that counted" and the fake proof).
* Tests: `test_coercion_scenarios`, `test_designated_verifier_proof_convinces_only_the_voter`, `test_revoked_tag_is_still_accepted_while_voting`, `test_public_record_does_not_link_revotes`.
* Spec: `spec/protocol.md` §5–7.
