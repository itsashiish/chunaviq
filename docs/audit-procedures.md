# Audit procedures

Written for a synthetic or mock election run with this prototype. Each step names the command or check that produces the evidence. "Observer" means anyone with a copy of the public record; "authorised auditor" means a person with legal access to private data (in a real election, someone appointed by the authority).

## Before voting

| # | Step | Evidence |
|---|---|---|
| B1 | Tag the release; publish the commit SHA, the wheel/sdist SHA-256 checksums and the build attestation | `release.yml` artifacts |
| B2 | Publish the **source digest** (`python -c "from chunaviq.election.manifest import source_digest; print(source_digest())"`) and confirm it equals `manifest.software.source_digest` | Verifier `--expect-source-digest` |
| B3 | Publish the **manifest hash** through a second channel (website + press note + signed letter) | Verifier `--expect-manifest-hash` |
| B4 | Re-derive the group from its seed | `chunaviq check-group`; test `test_groups_rederive_from_public_seed_independently` |
| B5 | Witness the key ceremony (`docs/key-ceremony.md`); confirm every trustee ack is in the record | `ceremony.*` checks |
| B6 | Run a complete mock election with the frozen release and verify it | `chunaviq simulate` + `chunaviq verify` |
| B7 | Test eligibility controls, recovery and incident procedures | `pytest -m "not slow"` |

## During voting

| # | Step | Evidence |
|---|---|---|
| D1 | Observers fetch each new signed checkpoint and keep a copy; at least two observers compare what they received | `checkpoints.jsonl`; consistency proofs |
| D2 | Monitor service health, rejection counts by reason and lockouts — **never** individual choices (they are encrypted) | Ballot box `rejections` |
| D3 | Voters may run Benaloh challenges and check their receipts | `verify_receipt` |
| D4 | Record every incident with time, effect and action; an early close needs a written reason, which is published | `early_close_reason`; verifier WARN |

## After voting

| # | Step | Evidence |
|---|---|---|
| A1 | Close; confirm `ballots_accepted` equals the ballots on the board | `lifecycle.close_count` |
| A2 | Eligibility publishes the participation summary; check `ballots ≤ issued ≤ eligible` per constituency | `reconciliation.participation` |
| A3 | **Participation sampling (authorised auditor):** draw a random sample of commitments, contact those voters through an independent channel, and confirm they did request a credential. Unexplained commitments are evidence of credential minting (threat R2). | Audit worksheet |
| A4 | Trustees independently recompute the aggregates before contributing shares | Trustee runs the verifier on the record up to `aggregate` |
| A5 | Run the independent verifier with both pins; archive the JSON report | `chunaviq verify … --json` |
| A6 | Render and publish the observer report with the record, checkpoints, report JSON and software identifiers | `chunaviq report` |
| A7 | Publish exceptions: rejected-ballot counts, early close, unavailable trustees, warnings | Observer report |

## Why there is no risk-limiting audit

A risk-limiting audit samples a **voter-verified paper record** and compares it to the electronic count. Remote online voting produces no such paper record, so an RLA cannot be applied to this protocol as designed. The verifiability here comes from cryptographic proofs instead. If a future tier pairs online casting with a paper trail, RLA procedures should be added at that point, not assumed.

## Sign-off

The election may be described as *verified* only if the verifier status is `VERIFIED` with both pins supplied, and every warning is explained in the published exceptions.
