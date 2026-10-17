# Key ceremony and HSM key custody

## One national key, one share per trustee — not 543

A national election has 543 constituencies. A per-constituency key would give each trustee 543 shares to guard, with no gain: the same five trustees would hold all of them, so stealing one trustee's HSM would expose all 543 anyway. v2 therefore runs **one key ceremony for the national election**; every constituency encrypts under that key and **each trustee's HSM holds exactly one share**.

Separation between constituencies comes from *what* the HSM agrees to decrypt, not from separate keys: every decryption request names its ciphertexts (per-option totals of one constituency, or the rows of one verified mix batch) and needs observers to attest to them. If the Commission still wanted per-constituency keys, the applet would store a map `ceremony → share` and apply the same policy per entry; storage is not the constraint (543 shares × 32 bytes).

## Where the code runs

`custody.TrusteeApplet` is the code that runs **inside** each trustee's HSM. A decryption share is `α^{s_i}` with a Chaum–Pedersen proof, which needs custom arithmetic with the secret share; standard PKCS#11 cannot do it without exporting the share. HSMs that run signed custom code inside the security boundary can:

| Vendor | Mechanism |
|---|---|
| Thales Luna | Functionality Modules (FM SDK) |
| Entrust nShield | CodeSafe |
| Utimaco | CryptoServer SDK |

In tests, `seal`/`unseal` emulate the HSM's protected storage so the whole flow runs anywhere. In a deployment the applet is ported to the vendor SDK, its binary hash is published, and the HSM attests to it.

## Ceremony

| Step | Inside the HSM | Published |
|---|---|---|
| 1. Begin | Bind to the national manifest hash; generate attestation (Ed25519) and transport (X25519) keys | Trustee's attestation key in `trustee_ack` |
| 2. Commit | Draw degree-(k−1) polynomial | `trustee_commitment` with Schnorr proofs |
| 3. Distribute | Encrypt each share to the recipient HSM's transport key (HKDF-SHA256 → AES-256-GCM) | Nothing (ciphertexts are useless outside the recipient HSM) |
| 4. Verify & combine | Feldman check of every incoming share; refuse bad ones; sum | `trustee_ack {verified_all_shares: true}` |
| 5. Destroy | Coefficients wiped | Log entry |

Witnesses: at least two observers independent of the trustees and the officer. Default n = 5, k = 3.

## Using a share

The applet produces decryption shares **only** if the request carries:

1. the election's `CLOSED` lifecycle entry, signed by a registered officer key — nothing is decrypted while voting is open;
2. approvals from **2 of 3** of this trustee's operator cards — no single insider;
3. attestations from **2 of 3** independent observers that they verified the ciphertexts are what the purpose says (`aggregate`, `mix-flag`, `mix-tag`) — so a single ballot cannot be smuggled in as a "total";
4. a fresh nonce, within the election's decryption budget.

Every operation is appended to a hash-chained log signed with the applet's attestation key. Logs are published after the election and checked against the attestation keys in the record (`test_hsm_logs_published_and_verified`).

## Backup and recovery

* Clone to a second HSM only to that HSM's transport key, with operator quorum (`export_clone`).
* Any k of n trustees suffice; losing n − k + 1 shares makes the election undecryptable, so keep clones in separate locations.
* After the election-petition period, destroy all shares under witness and publish the destruction log.

## What must never happen

* A share in plaintext outside an HSM, or on a networked general-purpose machine.
* A trustee decrypting anything other than attested totals or attested mix outputs.
* The officer, eligibility authority or ballot-box operator acting as a trustee or observer.

Tests: `tests/test_custody.py`.
