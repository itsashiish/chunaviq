# Protocol specification — ChunavIQ v2 (`chunaviq-record/2`)

Status: **research draft, not independently reviewed.** Normative for the code in `src/chunaviq` and the independent verifiers in `src/chunaviq_verify` (Python) and `web/src/engine/verifier.ts` (TypeScript). Where this document and the code disagree, the code has a bug or this document does; both are findings.

v2 replaces v1's one-shot blind-signed credential with a **registered voting tag** so a voter can **vote again**: only the last ballot under a currently valid registration counts, and nobody can tell which ballot that was. This is the defence against coercion and vote buying (`docs/coercion.md`).

## 1. Goals and non-goals

| Property | Meaning here | Mechanism |
|---|---|---|
| Eligibility | Only voters on the roll can cast a counted ballot | Identity check (Aadhaar OTP/face, or PAN + roll-mobile OTP + face) registers one tag per voter; only registered tags are accepted; counted tags must be in the published valid-tag list |
| One voter, one counted vote | At most one counted ballot per voter | One valid tag per voter; finalization keeps the last ballot per tag; the mixed, decrypted counted tags are distinct |
| Revoting | The voter can replace their ballot in private | Ballots under the same tag supersede earlier ones; re-registration and polling-day override revoke the old tag |
| Coercion resistance (bounded) | A coercer cannot tell whether a watched ballot counted | Encrypted last-ballot flags, verifiable mixing, designated-verifier "it counted" proof the voter can fake |
| Ballot secrecy | No single party learns how anyone voted | Threshold ElGamal; tags encrypted; flags and tags decrypted only after mixing; votes decrypted only as totals |
| Cast-as-intended (partial) | Voter can catch a device that encrypts the wrong choice | Benaloh cast-or-challenge |
| Recorded-as-cast | Voter can confirm their ballot is in the record | Tracking code + Merkle inclusion proof against a signed checkpoint |
| Counted-as-recorded | Anyone can confirm the result follows from the record | ZK proofs at every step: finalization OR-proofs, shuffle proofs, decryption proofs |
| Tamper evidence | Altering, deleting, inserting or reordering entries is detectable | Append-only RFC 6962 log with signed, consistent checkpoints |

**Non-goals / residual risk:** a coercer who takes the voter's device *for the whole voting period and polling day*; a coercer holding `t` can see from the public valid-tag list that the voter re-registered or voted in person (not that they merely revoted); the ballot box and eligibility authority together can learn *who voted when* (never how); a compromised device that also evades Benaloh challenges; network-level anonymity; network-layer floods (need a CDN/anycast scrubbing layer). See `docs/threat-model.md`.

## 2. Group

Schnorr group: primes `p` (2048-bit) and `q` (256-bit) with `q | p − 1`, generator `g` of the order-`q` subgroup `G_q`, derived deterministically from the public seed `"chunaviq election group v1 / research use / 2048-256"` (`crypto/primes.py::derive_group`, re-implemented in `chunaviq_verify/vmath.py::rederive`):

1. `q` = smallest probable prime ≥ `SHAKE256("chunaviq/v1/group-derivation\0" ‖ seed ‖ "\0q")` truncated to 256 bits, top and bottom bits set.
2. `r` even, from `SHAKE256(… "\0r")`, incremented by 2 until `p = q·r + 1` is a 2048-bit prime.
3. `g = h^r mod p` for the smallest `h ≥ 2` with `g ≠ 1`.

Membership `x ∈ G_q` ⟺ `1 ≤ x < p` and `x^q ≡ 1 (mod p)`; required for every adversary-supplied value later raised to a challenge. `TEST-INSECURE-512-160` exists for tests; verifiers refuse it unless `--allow-insecure-test-group`.

**Independent generators** for the shuffle proof: `h_j = (SHAKE256("chunaviq/v1/shuffle-generator\0" ‖ j ‖ "\0" ‖ ctr))^r mod p`, first `ctr` giving `h_j ∉ {0,1}`. Nobody knows a discrete-log relation between them.

## 3. Hashing (Fiat–Shamir)

`H(domain, items…) = SHA-256("chunaviq/v1/" ‖ domain ‖ 0x00 ‖ enc([items…])) mod q`, with `enc` the injective type-length-value encoding: integer `"i" ‖ len32 ‖ big-endian`, string `"s" ‖ len32 ‖ UTF-8`, bytes `"b" ‖ len32 ‖ raw`, list `"l" ‖ count32 ‖ enc(item)…`.

Domains: `schnorr`, `selection-0or1`, `contest-limit`, `decryption-share`, `ballot-tag`, `tag-link`, `finalize`, `dv-final`, `shuffle-u-seed`, `shuffle-u`, `shuffle-c`.

### Generic sigma proofs (`crypto/sigma.py`)

A statement is a list of equations `Y = Π_b B_b^{w_{i_b}}` over witnesses `w`. Prover picks `k_i ← Z_q`, commits `A = Π B^{k}`, challenge `c = H(domain, context, [statements], [A])`, responses `s_i = k_i + c·w_i`. Verifier checks `Π B^{s} = A · Y^c`. **OR-proofs** (Cramer–Damgård–Schoenmakers): the prover simulates every branch but the true one; challenges sum to the hash.

## 4. Key ceremony (k-of-n Feldman VSS, inside HSMs)

ONE national key for the whole election, so each trustee holds ONE share (see `docs/key-ceremony.md`). The ceremony runs inside each trustee's HSM applet (`custody.py::TrusteeApplet`):

1. Each applet draws `a_{i,0..k−1}`, publishes `C_{i,j} = g^{a_{i,j}}` with Schnorr proofs, context `[ceremony_hash, "trustee-coefficient", i, j]`.
2. Shares `f_i(l)` travel HSM to HSM encrypted to the recipient's X25519 transport key (HKDF-SHA256 → AES-256-GCM); never in plaintext outside an HSM.
3. Each applet checks `g^{f_i(l)} = Π_j C_{i,j}^{l^j}`, sets `s_l = Σ_i f_i(l)`, destroys coefficients, and signs `trustee_ack` with its HSM attestation key.

`K = Π_i C_{i,0}`; public share `K_l = g^{s_l}` is computable by anyone. In a federation the ceremony is bound to the national manifest hash and copied into every shard record.

## 5. Registration (eligibility authority)

1. **Identity.** One of: Aadhaar + OTP to the Aadhaar mobile; Aadhaar + face match against the UIDAI photo; PAN (name + DOB match) **plus** OTP to the mobile on the electoral roll **plus** face match to the roll photograph — PAN alone only proves knowledge of a number. All synthetic here (`election/identity.py`). Identifiers are stored as HMAC hashes; 5 failures lock the voter.
2. **Tag.** The device draws `t ← Z_q`, sends `T = g^t` with a Schnorr proof bound to `[election_id, "register", constituency, session]`. `T` must be fresh (`TAG_REUSED`).
3. **Re-registration** (lost or seized phone) replaces the voter's tag; the old tag is revoked silently. At most 5 re-registrations per voter (`TOO_MANY_REGISTRATIONS`); none after voting in person (`VOTED_IN_PERSON`).
4. **Polling-day override.** A voter who votes in person at a polling station has their online tag revoked; any online ballot then does not count.
5. Revocations are **not** published during voting (revoked tags are still accepted), so a coercer cannot test whether "their" tag was revoked.

The authority stores `voter_id → T`, a participation commitment `SHA-256("chunaviq/v1/participation\0" ‖ eid ‖ 0 ‖ voter_id ‖ 0 ‖ salt)` and the generation; the ballot box knows only the set of registered `T`.

## 6. Ballot

For options `[o_1 … o_m, NOTA]`, choice `o*`, tag secret `t`:

* **Tag ciphertext** `(α_T, β_T) = (g^{ρ}, T·K^{ρ})`.
* **Selections**: `(α_o, β_o) = (g^{r_o}, g^{[o=o*]} K^{r_o})`, each with a CDS 0/1 proof, context `[mhash, "selection", cons, o, α_T]`.
* **Limit proof**: Chaum–Pedersen that `Π(α_o, β_o)` encrypts `g^1`, context `[mhash, "contest-limit", cons, α_T]`.
* **Tag proof**: sigma proof of knowledge of `(ρ, t)` with `α_T = g^ρ`, `β_T = g^t K^ρ`, context `[mhash, "ballot-tag", cons, body_digest]`, `body_digest = SHA-256(canonical(selections, limit_proof))`. Binding to the body stops anyone re-using another voter's tag ciphertext on a different vote.

`tracking_code = SHA-256(canonical_json(ballot))`.

### Submission

`{ballot, tag: T, link}` where `link` proves `(α_T, β_T / T)` encrypts zero (witness `ρ`), context `[mhash, "tag-link", tracking_code]`. **`T` and `link` go only to the ballot box and are never published**: the public sees an encrypted tag.

### Acceptance (ballot box; re-checked by the verifiers except private parts)

1. Exact JSON schema (`MALFORMED`); election and constituency (`WRONG_ELECTION`, `UNKNOWN_CONSTITUENCY`); option list (`WRONG_BALLOT_STYLE`).
2. Every element in `G_q` (`INVALID_CIPHERTEXT`); proofs valid (`BAD_SELECTION_PROOF`, `BAD_LIMIT_PROOF`, `BAD_TAG_PROOF`); link valid (`BAD_TAG_LINK`, private).
3. `T` registered (`UNREGISTERED_TAG`); state `OPEN` and clock in window (`ELECTION_NOT_OPEN`, `OUTSIDE_VOTING_WINDOW`).
4. At most `max_ballots_per_tag` (30) ballots per tag (`TOO_MANY_REVOTES`).
5. No `α` already on the board (`DUPLICATE_CIPHERTEXT`). An identical retry under the **same** tag returns the original receipt (idempotent); the same ballot under a different tag is a copy and is refused.

Steps 3–5 and the board append happen in one `IMMEDIATE` SQLite transaction (group commit for batches).

### Benaloh challenge

Before casting, the voter may spoil a prepared ballot: the device reveals the choice and all randomness; anyone re-encrypts and compares. A fresh ballot is then prepared.

## 7. After close

### 7.1 Registration publication

The eligibility authority publishes a signed `registration_summary` per constituency (`eligible`, `registered`, `voted_in_person`, `reregistrations`, `valid_tags`, and SHA-256 digests of the two sorted lists) and the lists in signed chunks (`registration_list`): sorted participation commitments, and sorted **valid tags** (registered and not overridden in person). Checks: `registered ≤ eligible`, `valid_tags = registered − voted_in_person`, lists sorted, distinct, complete, digests match.

### 7.2 Finalization (ballot box)

For each ballot, in record order, the box sets `f = 1` iff it is the last ballot under its tag **and** that tag is still valid, else `f = 0`, and publishes:

* flag `F = Enc(g^f; u)`;
* masked votes `M_o = f ? (α_o g^{w_o}, β_o K^{w_o}) : (g^{w_o}, K^{w_o})` — a re-encryption of the vote, or an encryption of zero;
* an OR-proof (domain `finalize`, context `[mhash, "finalize", cons, tracking_code]`): **[F encrypts 0 and every M_o encrypts 0] OR [F encrypts 1 and every M_o re-encrypts (α_o, β_o)]**.

The homomorphic product of `M_o` over all ballots encrypts exactly the counted votes. Items go in signed `finalization` entries of up to 128.

**"It counted" proof for the voter** (designated verifier, domain `dv-final`): the box proves **[F encrypts 1] OR [I know t with T = g^t]**. The voter knows `t`, so they could have made it themselves: it convinces them and nobody else. The voter's phone can produce an identical-looking "proof" for any ballot to show a coercer.

### 7.3 Mixing (trustees)

Rows `(Enc(T), F)` per constituency are split into batches (`mixing.batch_size`, 2048 default). Each batch is re-encrypted and permuted in turn by ≥ `min_mixers` (3) distinct trustees, each publishing a `shuffle` entry with a **Terelius–Wikström** proof of a correct shuffle (commitment to the permutation matrix with the independent generators, chained commitments, challenge vector `u` from `shuffle-u-seed`/`shuffle-u`, challenge `shuffle-c`). One honest mixer hides which input became which output.

### 7.4 Decrypting flags and counted tags

On the final mix output of each batch: ≥ k trustees publish `flag_shares` (Chaum–Pedersen decryption shares, context `[mhash, "mix-flag", cons, batch, i]`); rows with `f = 1` are identified; ≥ k trustees publish `tag_shares` for those rows only (context `[mhash, "mix-tag", …]`). The verifier checks the decrypted counted tags are **distinct** and every one is in the published **valid-tag list**. Nothing links a counted tag to a ballot.

### 7.5 Tally

Officer publishes `aggregate` = per-option product of the masked votes `M_o` with `ballot_count` and `final_count`; ≥ k trustees publish `decryption_shares` (context `[mhash, "decrypt-aggregate", cons, o]`); `g^{t_o}` recovered by Lagrange interpolation and `t_o` by baby-step giant-step. `Σ t_o = final_count` = number of counted tags. Individual ballots are never decrypted.

Every trustee decryption runs inside the HSM applet only with: the officer-signed `CLOSED` entry, 2-of-3 operator approvals, 2-of-3 observer attestations that the ciphertexts are what the purpose says, a fresh nonce and within the decryption budget.

### Decision rule

First-past-the-post; NOTA counted, cannot win; a tie is published with `winner = null` for the Returning Officer to decide by lot (s.65 RP Act 1951).

## 8. Lifecycle

`DRAFT → KEY_CEREMONY → READY → OPEN → CLOSED → TALLIED → PUBLISHED`, each a signed `lifecycle` entry; no other transition. Early close needs a recorded reason (verifier warning).

## 9. Required record sequence

```
manifest                                   (spec_version chunaviq-record/2)
lifecycle KEY_CEREMONY
trustee_commitment × n, trustee_ack × n, joint_key
lifecycle READY
lifecycle OPEN
ballot × B                                 (includes revotes)
lifecycle CLOSED
registration_summary
registration_list × …                      (commitments, valid_tags; per constituency, chunked)
finalization × ⌈B / 128⌉                   (one item per ballot, record order)
for each constituency (manifest order):
    for each batch:
        shuffle × (≥ min_mixers)
        flag_shares × (≥ k)
        tag_shares × (≥ k)
    aggregate
    decryption_shares × (≥ k)
    result
lifecycle TALLIED
lifecycle PUBLISHED
```

Any deviation fails verification.

## 10. Denial of service (sequencer, `service/sequencer.py`)

Cheapest check first: per-client token bucket (`RATE_LIMITED`), global load shedding (`OVERLOADED`, 503 with `Retry-After`), body size and exact schema, idempotent replay (no proof work), registered-tag check, per-tag minimum interval (2 s, `TAG_RATE_LIMITED`), and only then the proofs, in a process pool, appended with group commit. The HTTP layer caps headers, bodies and connections and drops slow or idle clients. See `docs/dos-and-rehearsal.md`.
