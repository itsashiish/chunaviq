# Federation format — `chunaviq-federation/2`

A national election is a directory:

```
national/manifest.json      signed body {manifest, manifest_hash}            role: national-officer
national/ceremony.json      signed body {national_manifest_hash, entries[],  role: national-officer
                                         joint_public_key}
national/shard-index.json   signed body {national_manifest_hash, shards[]}   role: national-officer
national/results.json       signed body {national_manifest_hash, constituencies, seats_by_party,
                                         votes_by_party, undecided_ties}    role: national-officer
shards/<constituency-id>/record/{entries.jsonl, checkpoints.jsonl}           one chunaviq-record/2 each
```

Each file is one line of canonical JSON (see `record-format.md`), signed exactly like record entries.

## National manifest

`spec_version`, `election_id`, `title`, `notice`, `voting_rule`, `group`, `window {opens_at, closes_at}`, `trustees {threshold, members[{index, role, public_key}]}` (the national trustee committee), `mixing`, `revoting`, `keys {national_officer}`, `shards[{id, eligible_voters}]`, `software`.

## Binding a shard to the national election

Each shard record's manifest:

* has exactly one constituency, whose `id` and `eligible_voters` match the national manifest;
* carries `federation = {national_election_id, national_manifest_hash, shard_id}`;
* uses the national `window`, `group`, trustee `threshold` and committee public keys;
* carries a copy of the national ceremony (`trustee_commitment`, `trustee_ack`, `joint_key`), so it verifies on its own, and its joint key equals the national one.

## One national key

There is ONE key ceremony, held inside the trustees' HSMs and bound to the national manifest hash (`national/ceremony.json`). Every constituency encrypts under the same joint key, so each trustee's HSM holds one share. Separate per-constituency keys would only multiply the shares to guard (543 per trustee) without adding protection: the same trustees would hold all of them. Decryption is still per constituency and per purpose, because every HSM request names the ciphertexts and the observers attest to them (`docs/key-ceremony.md`).
* has `officer`, `board` and `eligibility` keys and a final checkpoint (`tree_size`, `root`) equal to its shard-index entry.

## Verification (`chunaviq verify-federation`)

1. National manifest hash, signature and (optionally) pin.
2. National ceremony signed, bound to the manifest, by the declared committee; joint key = product of the constant commitments.
3. Shard index signed and bound to the manifest; declared, indexed and published shard sets are identical.
4. Every shard passes full single-election verification, pinned to the manifest hash in the index.
5. Every shard is bound as above and uses the national joint key.
6. The published national result equals the sum of verified shard results: winners, seats by party and votes by party.

Any missing, extra, unbound or unverifiable shard fails the national election.
