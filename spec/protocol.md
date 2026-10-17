# Protocol specification — evlab v1

Status: **research draft, not independently reviewed.** Normative for the code in `src/evlab` and the independent verifier in `src/evlab_verify`. Where this document and the code disagree, the code has a bug or this document does; both are findings.

## 1. Goals and non-goals

| Property | Meaning here | Mechanism |
|---|---|---|
| Eligibility | Only voters on the roll can cast a counted ballot | Authenticated blind-signed credential, one per voter |
| One voter, one vote | At most one counted ballot per credential, one credential per voter | DB uniqueness at issuance; token uniqueness at the ballot box; verifier re-checks |
| Ballot secrecy | No single party can learn how a voter voted | Threshold ElGamal (k-of-n trustees) + unlinkable credentials |
| Cast-as-intended (partial) | Voter can detect a device that encrypts the wrong choice | Benaloh cast-or-challenge |
| Recorded-as-cast | Voter can confirm their ballot is in the record | Tracking code + Merkle inclusion proof against a signed checkpoint |
| Counted-as-recorded | Anyone can confirm the result follows from the record | Homomorphic aggregation + ZK proofs of correct decryption |
| Tamper evidence | Altering, deleting, inserting or reordering record entries is detectable | Append-only RFC 6962 log with signed, consistent checkpoints |

**Non-goals (not provided, documented as residual risk):** coercion resistance, receipt-freeness against a voter who reveals their device secrets, protection against a compromised voter device that also suppresses the Benaloh challenge, network-level anonymity, availability under denial of service. See `docs/threat-model.md`.

## 2. Group

Schnorr group: primes `p` (2048-bit) and `q` (256-bit) with `q | p − 1`, generator `g` of the order-`q` subgroup `G_q`.

Parameters are derived deterministically from the public seed `"evlab election group v1 / research use / 2048-256"` (`src/evlab/crypto/primes.py::derive_group`, re-implemented in `src/evlab_verify/vmath.py::rederive`):

1. `q` = smallest probable prime ≥ `SHAKE256("evlab/v1/group-derivation\0" ‖ seed ‖ "\0q")` truncated to 256 bits, top and bottom bits set.
2. `r` = even integer starting at `lo + (SHAKE256(… "\0r") mod (hi − lo))`, where `[lo, hi]` makes `p = q·r + 1` exactly 2048 bits; incremented by 2 until `p` is prime.
3. `g = h^r mod p` for the smallest `h ≥ 2` with `g ≠ 1`.

**Membership check** `x ∈ G_q` ⟺ `1 ≤ x < p` and `x^q ≡ 1 (mod p)`. Required for every value an adversary supplies that is later exponentiated by a challenge (ciphertext components, public shares, decryption shares). Proof *commitments* only need `1 ≤ x < p`, because each verification equation fixes them to a product of subgroup elements.

A second group `TEST-INSECURE-512-160` exists for fast tests. The verifier refuses it unless `--allow-insecure-test-group` is passed.

## 3. Hashing (Fiat–Shamir)

`H(domain, items…) = SHA-256("evlab/v1/" ‖ domain ‖ 0x00 ‖ enc([items…])) mod q`

`enc` is a type-length-value encoding: integer → `"i" ‖ len32 ‖ big-endian bytes` (zero is one `0x00` byte); string → `"s" ‖ len32 ‖ UTF-8`; list → `"l" ‖ count32 ‖ enc(item)…`. It is injective (property-tested).

Domains: `schnorr`, `selection-0or1`, `contest-limit`, `decryption-share`.

## 4. Key ceremony (k-of-n, Feldman VSS)

For each trustee `i ∈ {1..n}`:

1. Choose `a_{i,0..k−1} ← Z_q`. Publish `C_{i,j} = g^{a_{i,j}}` with a Schnorr proof for each `j`, challenge context `[manifest_hash, "trustee-coefficient", str(i), str(j)]`. Entry `trustee_commitment`, signed by `trustee-i`.
2. Send `f_i(l) = Σ_j a_{i,j} l^j` privately to each trustee `l`.
3. Trustee `l` checks `g^{f_i(l)} = Π_j C_{i,j}^{l^j}` for every `i`, sets `s_l = Σ_i f_i(l)`, destroys its coefficients, and publishes a signed `trustee_ack`.

Joint key `K = Π_i C_{i,0}`. Public share `K_l = Π_i Π_j C_{i,j}^{l^j} = g^{s_l}`, computable by anyone. Any `k` trustees can decrypt; any `k − 1` learn nothing about `s`.

## 5. Credentials (RSA-FDH blind signatures)

One RSA key (≥ 3072-bit, e = 65537) per constituency, held by the eligibility authority and published in the signed `issuer_keys` entry.

* Message: `M = election_id ‖ 0x00 ‖ constituency ‖ 0x00 ‖ token` (token: 32 random bytes chosen by the voter's device).
* `FDH(M) = MGF1-SHA256("evlab/v1/credential-fdh\0" ‖ M, len(n) − 1 bytes)`.
* Device sends `m' = FDH(M)·ρ^e mod n`; authority authenticates the voter, atomically records "issued" for that voter, returns `m'^d mod n`; device unblinds.
* Valid credential: `σ^e ≡ FDH(M) (mod n)`.

The authority learns who received a credential, not which token. RFC 9474 (RSABSSA) is the standardised alternative for any deployment.

## 6. Ballot

For a constituency with options `[o_1 … o_m, NOTA]` and choice `o*`:

* For each option `o`: `m_o = [o = o*]`, `r_o ← Z_q`, `(α_o, β_o) = (g^{r_o}, g^{m_o} K^{r_o})`, plus a CDS proof that `m_o ∈ {0,1}` with context `[manifest_hash, "selection", constituency, o, token_hex]`.
* Limit proof: with `A = Π α_o`, `B = Π β_o`, `R = Σ r_o`, a Chaum–Pedersen proof that `log_g A = log_K (B / g)` (exactly one selection), context `[manifest_hash, "contest-limit", constituency, token_hex]`.

Binding every proof to the token stops a ballot (or part of one) being copied under another credential.

### Ballot acceptance (ballot box; re-checked by the verifier)

1. Exact JSON schema at every level; no extra or missing fields (`MALFORMED`). *A free-form field would let a voter mark a ballot for a vote buyer.*
2. Election id matches; constituency exists.
3. Credential signature valid under that constituency's issuer key (`BAD_CREDENTIAL`).
4. Option ids equal the manifest's list, in order (`WRONG_BALLOT_STYLE`).
5. Every `α, β ∈ G_q` (`INVALID_CIPHERTEXT`); every 0/1 proof valid (`BAD_SELECTION_PROOF`); limit proof valid (`BAD_LIMIT_PROOF`).
6. Lifecycle state is `OPEN` and the clock is inside the manifest window (`ELECTION_NOT_OPEN`, `OUTSIDE_VOTING_WINDOW`).
7. Token never used before (`CREDENTIAL_ALREADY_USED`); no `α` already on the board (`DUPLICATE_CIPHERTEXT`).

Steps 6–7 and the board append happen in one critical section inside an `IMMEDIATE` SQLite transaction.

### Benaloh challenge

Before casting, a voter may *spoil* a prepared ballot: the device reveals the choice and all `r_o`; anyone can re-encrypt and compare. The spoiled ballot is discarded and a fresh one (new nonces) prepared. A cheating device that cannot predict which ballots will be challenged is caught with probability equal to the challenge rate.

## 7. Tally

After `CLOSED` and the participation summary:

1. Officer publishes, per constituency and option, `(A_o, B_o) = Π (α_o, β_o)` over accepted ballots (`aggregate`).
2. Each of ≥ k trustees publishes `M_{l,o} = A_o^{s_l}` with a Chaum–Pedersen proof `log_g K_l = log_{A_o} M_{l,o}`, context `[manifest_hash, "decrypt-aggregate", constituency, o]` (`decryption_shares`, signed by the trustee).
3. `g^{t_o} = B_o / Π_l M_{l,o}^{λ_l}` with Lagrange coefficients at 0; `t_o` found by bounded search up to the ballot count.
4. Officer publishes counts and the decision (`result`).

Individual ballots are never decrypted.

### Decision rule

First-past-the-post: the contesting candidate with the most votes wins. NOTA is counted and published but cannot win (the rule used for ECI-conducted elections; some State Election Commissions apply different NOTA rules to local-body polls). A tie for first place is published as a tie with `winner = null`: under s.65 of the Representation of the People Act, 1951 the Returning Officer decides by lot, a witnessed human act that software must not perform.

## 8. Lifecycle

`DRAFT → KEY_CEREMONY → READY → OPEN → CLOSED → TALLIED → PUBLISHED`, one step at a time, each a `lifecycle` entry signed by the officer. The board refuses any other transition. Opening before `opens_at`, or closing before `closes_at` without a recorded `early_close_reason`, is refused; an early close is surfaced by the verifier as a warning.

## 9. Required record sequence

```
manifest
lifecycle KEY_CEREMONY
trustee_commitment × n   (trustee 1..n)
trustee_ack × n
joint_key
issuer_keys
lifecycle READY
lifecycle OPEN
ballot × B
lifecycle CLOSED
participation_summary
for each constituency (manifest order):
    aggregate
    decryption_shares × (≥ k)
    result
lifecycle TALLIED
lifecycle PUBLISHED
```

Any deviation fails verification.
