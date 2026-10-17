# Identity: Aadhaar OR PAN

A voter registers a phone by proving they are a specific entry on the electoral roll, using **either** document. Both paths end at the same roll entry, and the roll entry — not the document — gets one registration. Someone with both Aadhaar and PAN cannot register twice.

| Method | Real-world service it stands for | What it proves | Extra checks here |
|---|---|---|---|
| Aadhaar + OTP | UIDAI authentication via a licensed AUA/KUA, OTP to the Aadhaar-registered mobile | Control of the Aadhaar mobile | — |
| Aadhaar + face | UIDAI face authentication | The person is the Aadhaar holder | Liveness is assumed from the capture app |
| PAN | Income Tax Department / Protean Online PAN Verification | Only that a PAN exists with that name and date of birth — **no OTP, no biometric** | **OTP to the mobile on the electoral roll AND face match against the roll photograph** |

PAN alone would let anyone who knows a person's PAN, name and birth date (all printed on the card and widely shared for KYC) register as them, so the PAN path adds two independent factors held by the Election Commission. Demo attack *"Register as someone using only their PAN"* shows the refusal.

## Linking documents to the roll

* **Aadhaar.** Electors may give their Aadhaar number for roll linkage under s.23(5) of the RP Act 1950 (Form 6B). This is voluntary, so Aadhaar cannot be the only route. The authority stores a UID token, never the number.
* **PAN.** No roll linkage exists today; a real deployment would need a statutory basis and a data-sharing arrangement with the Income Tax Department (see the website's *Law* page).
* **Neither.** The voter votes at the polling station as now.

## Controls

* 5 failed attempts lock the voter (`LOCKED`); OTPs expire after 3 attempts.
* Identity references stored as keyed HMACs; raw numbers never stored or logged.
* The registration proof (Schnorr PoK of `t`) is bound to the authenticated session, so a captured proof cannot be replayed into another session.
* Re-registration (new phone) needs the same identity check and is limited to 5; it is refused after voting in person.

## Synthetic only

`election/identity.py` implements `SyntheticUIDAI`, `SyntheticPANService` and a synthetic SMS network and camera. Identifiers look like `syn-uid-0000042`, `syn-pan-0000042`, `syn-mob-0000042` — formats no real system issues. `tools/scan_pii.py` fails CI on anything shaped like a real Aadhaar, PAN, EPIC or Indian mobile number. Never connect this code to UIDAI, the Income Tax Department or any real service.

## Residual risk

SIM swap on the Aadhaar-OTP path; face spoofing without strong liveness; a compromised identity provider; and the eligibility authority registering abstainers (R2, `threat-model.md`).
