# Election record format — `chunaviq-record/2`

The public election record is a directory with two files. It contains no voter identifiers, no authentication data, no IP addresses and no fine-grained timestamps.

## `entries.jsonl`

One entry per line, each line the **canonical JSON** of the entry:

* `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
* integers larger than a counter (group elements, scalars) are lowercase hex strings with no `0x` prefix and no leading zeros (`"0"` for zero)
* a line that is not byte-identical to the canonical form of its own parse is invalid

```json
{"body": {...}, "seq": 0, "time_bucket": "2026-11-02T01", "type": "manifest"}
```

| Field | Meaning |
|---|---|
| `seq` | 0-based position; must equal the line number |
| `type` | `manifest`, `lifecycle`, `trustee_commitment`, `trustee_ack`, `joint_key`, `ballot`, `registration_summary`, `registration_list`, `finalization`, `shuffle`, `flag_shares`, `tag_shares`, `aggregate`, `decryption_shares`, `result` |
| `time_bucket` | UTC hour (`YYYY-MM-DDTHH`) the board recorded the entry; hour resolution limits timing correlation |
| `body` | type-specific content |

### Signed bodies

Every body except `ballot` is signed: `body.signer` is the role name and `body.signature` is a hex Ed25519 signature over `"chunaviq/v1/signed-body\0" ‖ canonical_json(body without "signature")`. Role keys are declared in the manifest (`keys.officer`, `keys.board`, `keys.eligibility`, `trustees.members[].public_key`).

The manifest declares its own officer key, so a record is only as authentic as the channel the manifest hash came from. Verifiers should obtain the manifest hash out-of-band and pass `--expect-manifest-hash`.

### Body schemas (abridged)

Order and meaning: `spec/protocol.md` §9.

* **manifest** — `{manifest, manifest_hash}`; `manifest_hash = SHA-256(canonical_json(manifest))`. The manifest holds `spec_version` (`chunaviq-record/2`), election id, title, notice, voting rule, group name, window (`opens_at`, `closes_at`), constituencies (`id`, `name`, `eligible_voters`, `options[{id,name,party}]`, last option `NOTA`), trustees (`threshold`, `members[{index, role, public_key}]`), keys (`officer`, `board`, `eligibility`), `mixing {min_mixers, batch_size}`, `revoting {max_ballots_per_tag}`, software (`name`, `version`, `source_digest`), and in a federation `federation {national_election_id, national_manifest_hash, shard_id}`.
* **lifecycle** — `{election_id, state}`; `CLOSED` adds `ballots_accepted`, `rejections_by_reason`, optional `early_close_reason`.
* **trustee_commitment** — `{commitment: {index, commitments[k], proofs[k]{h,v}}}`, signed by `trustee-i`.
* **trustee_ack** — `{index, verified_all_shares: true, hsm_attestation_key}`; the attestation key signs that HSM's audit log.
* **joint_key** — `{joint_public_key}`.
* **ballot** (unsigned) — `{tracking_code, ballot}`; `ballot = {election_id, constituency, tag{ciphertext{alpha,beta}, proof{c, s[2]}}, selections[{option_id, ciphertext, proof{a0,b0,a1,b1,c0,c1,v0,v1}}], limit_proof{a,b,v}}`. `tracking_code = SHA-256(canonical_json(ballot))`. The plaintext tag `T` and its link proof are never in the record.
* **registration_summary** — `{election_id, chunk_size, constituencies: {id: {eligible, registered, voted_in_person, reregistrations, valid_tags, commitments_sha256, valid_tags_sha256}}}`, signed by `eligibility`. A list digest is `SHA-256(item_1 ‖ "\n" ‖ item_2 ‖ "\n" …)` over the sorted list.
* **registration_list** — `{constituency, list: "commitments" | "valid_tags", index, items[≤ chunk_size]}`; items sorted and distinct across chunks. Participation commitment = `SHA-256("chunaviq/v1/participation\0" ‖ election_id ‖ 0 ‖ voter_id ‖ 0 ‖ salt)`; the voter holds the salt, so they can find their own commitment.
* **finalization** — `{items[{seq, tracking_code, flag{alpha,beta}, masked[{alpha,beta}], proof{c[2], s[2][1+m]}}]}`, signed by `board`; one item per ballot, in record order, ≤ 128 per entry.
* **shuffle** — `{constituency, batch, mixer, rows[[tag_ct, flag_ct]], proof{commitments, chain, c, s1, s2, s3, s4, shat, sprime}}`, signed by `trustee-<mixer>`; the input of the first shuffle is the batch's `(ballot.tag.ciphertext, finalization.flag)` rows in record order, each later shuffle takes the previous output.
* **flag_shares** — `{constituency, batch, index, shares[{share, proof{a,b,v}}]}`: one share per row of the final mix output.
* **tag_shares** — `{constituency, batch, index, rows[], shares[…]}`: shares only for the rows whose flag decrypted to 1.
* **aggregate** — `{constituency, ballot_count, final_count, aggregates[{option_id, ciphertext}]}`: product of masked votes.
* **decryption_shares** — `{constituency, index, shares[{option_id, share, proof{a,b,v}}]}`.
* **result** — `{constituency, quorum[], ballot_count, final_count, counts[{option_id, votes}], winner, tied[], nota_exceeds_winner}`.

## `checkpoints.jsonl`

Signed tree heads by the `board` role, in increasing `tree_size`:

```json
{"consistency_proof": ["<hex>", ...], "election_id": "...", "prev_tree_size": 1204,
 "root": "<hex>", "signature": "<hex>", "signer": "board", "time_bucket": "...", "tree_size": 2208}
```

* Leaf hash = `SHA-256(0x00 ‖ line bytes)`; node hash = `SHA-256(0x01 ‖ left ‖ right)`; tree shape per RFC 6962.
* `consistency_proof` proves the tree at `tree_size` extends the tree at `prev_tree_size` (RFC 9162 §2.1.4).
* The final checkpoint must cover every entry.

## Voter receipt

```json
{"tracking_code": "...", "seq": 812, "entry_sha256": "...", "tree_size": 6803, "root": "...", "inclusion_path": ["<hex>", ...]}
```

Checked by `chunaviq_verify.verify_receipt(record, receipt)`: the entry at `seq` is a ballot with that tracking code, the checkpoint with that size and root is validly signed, and the inclusion path verifies (RFC 9162 §2.1.3). A receipt proves a ballot is recorded, not that it is the voter's last; "it counted" is the voter's designated-verifier proof (`protocol.md` §7.2), which is deliberately not transferable.
