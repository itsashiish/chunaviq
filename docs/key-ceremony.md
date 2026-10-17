# Key ceremony and key custody

The prototype runs the ceremony in one process. This page specifies what a witnessed ceremony would need, so the gap is explicit.

## Roles

* **n trustees** (default 5), each from a different institution; **threshold k** (default 3). Recommended: k > n/2 so a minority cannot decrypt and a minority cannot block.
* **Witnesses**: at least two observers independent of the trustees and the officer.
* **Officer**: publishes the joint key after all acknowledgements.

## Lifecycle of a key share

| Stage | Prototype | Required for a real ceremony |
|---|---|---|
| Generation | `Trustee.__init__` draws coefficients from `secrets` | Air-gapped machine per trustee; hardware RNG health-checked; fresh OS image; witnessed |
| Commitment | Signed `trustee_commitment` with Schnorr proofs | Same, signed with a trustee key whose fingerprint was published in advance |
| Share distribution | In-memory call | Authenticated encryption to each recipient's published key; transfer by removable media under witness |
| Share verification | Feldman check; `CeremonyError` on failure; signed `trustee_ack` | Same; a failed check triggers a public complaint and the dealer is excluded or the ceremony restarts |
| Coefficient destruction | `Trustee.finalize` clears the list | Wipe and witness; record destruction in the ceremony log |
| Storage | Process memory | HSM or encrypted media in tamper-evident bags, held in separate locations |
| Use | `decryption_share` on aggregates only | Each trustee checks that the aggregate it is asked to decrypt equals the product of the published ballots before contributing (the verifier code can be used for this) |
| Recovery | Any k of n | Same; losing n − k + 1 shares makes the election undecryptable — plan storage accordingly |
| Destruction | — | After the legal challenge period closes, destroy all shares under witness and publish the record of destruction |

## What must never happen

* A trustee decrypting anything other than a published aggregate.
* Shares, coefficients or the joint secret existing on a networked machine.
* The officer, the eligibility authority or the board operator acting as a trustee.
