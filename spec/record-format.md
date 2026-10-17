# Election record format — `evlab-record/1`

The public election record is a directory with two files. It contains no voter identifiers, no authentication data, no IP addresses and no fine-grained timestamps.

## `entries.jsonl`

One entry per line, each line the **canonical JSON** of the entry:

* `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
* integers larger than a counter (group elements, scalars, RSA values) are lowercase hex strings with no `0x` prefix and no leading zeros (`"0"` for zero)
* a line that is not byte-identical to the canonical form of its own parse is invalid

```json
{"body": {...}, "seq": 0, "time_bucket": "2026-11-02T01", "type": "manifest"}
```

| Field | Meaning |
|---|---|
| `seq` | 0-based position; must equal the line number |
| `type` | `manifest`, `lifecycle`, `trustee_commitment`, `trustee_ack`, `joint_key`, `issuer_keys`, `ballot`, `participation_summary`, `aggregate`, `decryption_shares`, `result` |
| `time_bucket` | UTC hour (`YYYY-MM-DDTHH`) the board recorded the entry; hour resolution limits timing correlation |
| `body` | type-specific content |

### Signed bodies

Every body except `ballot` is signed: `body.signer` is the role name and `body.signature` is a hex Ed25519 signature over `"evlab/v1/signed-body\0" ‖ canonical_json(body without "signature")`. Role keys are declared in the manifest (`keys.officer`, `keys.board`, `keys.eligibility`, `trustees.members[].public_key`).

The manifest declares its own officer key, so a record is only as authentic as the channel the manifest hash came from. Verifiers should obtain the manifest hash out-of-band and pass `--expect-manifest-hash`.

### Body schemas (abridged)

* **manifest** — `{manifest, manifest_hash}`; `manifest_hash = SHA-256(canonical_json(manifest))`. The manifest holds election id, title, notice, voting rule, group name, window (`opens_at`, `closes_at`, ISO-8601 UTC), constituencies (`id`, `name`, `eligible_voters`, `options[{id,name,party}]`, last option `NOTA`), trustees (`threshold`, `members[{index, role, public_key}]`), keys, software (`name`, `version`, `source_digest`).
* **lifecycle** — `{election_id, state}`; `CLOSED` adds `ballots_accepted`, `rejections_by_reason`, optional `early_close_reason`.
* **trustee_commitment** — `{commitment: {index, commitments[k], proofs[k]{h,v}}}`.
* **trustee_ack** — `{index, verified_all_shares: true}`.
* **joint_key** — `{joint_public_key}`.
* **issuer_keys** — `{election_id, issuer_keys: {constituency: {n, e}}}`.
* **ballot** — `{tracking_code, ballot}`; `tracking_code = SHA-256(canonical_json(ballot))`; ballot schema in `spec/protocol.md` §6. Exact schema at every nesting level.
* **participation_summary** — `{election_id, constituencies: {id: {eligible, credentials_issued, commitments[sorted]}}}`; commitment = `SHA-256("evlab/v1/participation\0" ‖ election_id ‖ 0 ‖ voter_id ‖ 0 ‖ salt)`; the voter holds the salt, the authority keeps it privately.
* **aggregate** — `{constituency, ballot_count, aggregates[{option_id, ciphertext}]}`.
* **decryption_shares** — `{constituency, index, shares[{option_id, share, proof{a,b,v}}]}`.
* **result** — `{constituency, quorum[], ballot_count, counts[{option_id, votes}], winner, tied[], nota_exceeds_winner}`.

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

Checked by `evlab_verify.verify_receipt(record, receipt)`: the entry at `seq` is a ballot with that tracking code, the checkpoint with that size and root is validly signed, and the inclusion path verifies (RFC 9162 §2.1.3).
