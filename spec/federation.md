# Federation format — `chunaviq-federation/1`

A national election is a directory:

```
national/manifest.json      signed body {manifest, manifest_hash}            role: national-officer
national/shard-index.json   signed body {national_manifest_hash, shards[]}   role: national-officer
national/results.json       signed body {national_manifest_hash, constituencies, seats_by_party,
                                         votes_by_party, undecided_ties}    role: national-officer
shards/<constituency-id>/record/{entries.jsonl, checkpoints.jsonl}           one chunaviq-record/1 each
```

Each file is one line of canonical JSON (see `record-format.md`), signed exactly like record entries.

## National manifest

`spec_version`, `election_id`, `title`, `notice`, `voting_rule`, `group`, `window {opens_at, closes_at}`, `trustees {threshold, members[{index, role, public_key}]}` (the national trustee committee), `keys {national_officer}`, `shards[{id, eligible_voters}]`, `software`.

## Binding a shard to the national election

Each shard record's manifest:

* has exactly one constituency, whose `id` and `eligible_voters` match the national manifest;
* carries `federation = {national_election_id, national_manifest_hash, shard_id}`;
* uses the national `window`, `group`, trustee `threshold` and committee public keys (each shard runs its own key ceremony, so key shares differ per shard; the people and their signing keys are the same);
* has `officer`, `board` and `eligibility` keys and a final checkpoint (`tree_size`, `root`) equal to its shard-index entry.

## Verification (`chunaviq verify-federation`)

1. National manifest hash, signature and (optionally) pin.
2. Shard index signed and bound to the manifest; declared, indexed and published shard sets are identical.
3. Every shard passes full single-election verification, pinned to the manifest hash in the index.
4. Every shard is bound as above.
5. The published national result equals the sum of verified shard results: winners, seats by party and votes by party.

Any missing, extra, unbound or unverifiable shard fails the national election.
