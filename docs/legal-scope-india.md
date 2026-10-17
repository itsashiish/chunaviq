# Legal and regulatory scope — India

**Not legal advice.** This page records the assumptions the project works under and the boundaries it keeps. Anything beyond research use needs review by qualified Indian counsel and, for any real election, the competent election authority. Statutes are cited for orientation; check current text and amendments before relying on them.

## 1. What this project is

An open-source **research prototype** that runs **synthetic elections only**: artificial voters, candidates, parties and results. It does not connect to, test against, or imitate any real electoral roll, election authority system, or voting service. Every record it produces carries a notice that it has no legal effect.

## 2. Who conducts elections in India

| Election | Authority | Constitutional basis |
|---|---|---|
| Lok Sabha, State Legislative Assemblies/Councils, President, Vice-President | Election Commission of India (ECI) | Article 324 |
| Panchayats | State Election Commissions | Article 243K |
| Municipalities | State Election Commissions | Article 243ZA |

Only these bodies, acting under the applicable statutes and rules, can authorise a voting method for a real election. A GitHub repository, a passing test suite, a security audit or a pilot run by this project confers no such authority.

## 3. Statutes and rules this design must respect

| Instrument | Relevance to the design |
|---|---|
| **Representation of the People Act, 1951** | s.61A permits voting machines as prescribed by rules — remote online voting is not among the prescribed methods for ECI elections. s.128 makes breach of the secrecy of voting by officials an offence, which is why the design gives no single official (officer, eligibility authority, board operator, or any single trustee) the ability to link a voter to a vote. s.65 decides ties by lot, which is why the software reports ties without resolving them. s.62 limits a person to voting once and in one constituency; v2 allows revoting, so a law would have to define that only the last online ballot under a valid registration counts and that an in-person vote cancels it (see the website's *Law* page). |
| **Conduct of Election Rules, 1961** | Prescribe EVM/VVPAT voting and postal-ballot procedures, including the Electronically Transmitted Postal Ballot System (ETPBS) for service voters, which transmits a blank ballot electronically but requires the marked ballot to be **returned by post**. ETPBS is not a precedent for online ballot return. |
| **NOTA** | Introduced following *PUCL v. Union of India* (Supreme Court, 2013). The prototype includes NOTA on every ballot; NOTA is counted but cannot win (ECI rule). Some State Election Commissions apply different NOTA consequences in local-body polls; the decision rule is a configuration point for that reason. |
| **Bharatiya Nyaya Sanhita, 2023 — Chapter IX (ss.169–177)** | Election offences: bribery (s.170), undue influence (s.171), personation (s.172) and their punishments. Remote voting weakens the physical safeguards against undue influence and vote-buying. v2 bounds this with revoting, a polling-day override and a fakeable "it counted" proof (`docs/coercion.md`); new offences for demanding to watch an online vote or buying a voting phone would still be needed. |
| **Digital Personal Data Protection Act, 2023** and **DPDP Rules, 2025** | The Rules were notified on 13 November 2025 with obligations phased in through May 2027. A real deployment would process electors' personal data and would need lawful basis, notice, security safeguards and breach intimation. The prototype avoids the question entirely by processing **no real personal data**. |
| **Information Technology Act, 2000** | Unauthorised access to computer systems is an offence and a civil wrong. Security testing in this project is confined to systems contributors own and run locally; **never** probe ECI, SEC, C-DAC or any other real election infrastructure. Report suspected vulnerabilities in real systems to the system owner or CERT-In, not to this repository. |
| **Aadhaar Act, 2016** and the **Aadhaar Authentication for Good Governance Rules, 2020** (amended 31 January 2025) | Aadhaar authentication may only be performed by authorised entities for approved purposes. The prototype **simulates** UIDAI OTP and face authentication with a synthetic service (`docs/identity.md`); it never uses, generates or accepts real Aadhaar numbers, and synthetic references (`syn-uid-…`) avoid the Aadhaar (12-digit), EPIC (3 letters + 7 digits) and PAN (5 letters + 4 digits + 1 letter) formats. |
| **RP Act 1950, s.23(5) (Form 6B)** | Aadhaar–roll linkage is voluntary (ECI to the Supreme Court, 2023), so Aadhaar cannot be the only way to register; v2 also accepts PAN, and the polling station always remains. |
| **Income-tax Act, 2025** (in force 1 April 2026; existing PANs remain valid) | PAN verification only matches a name and date of birth. The prototype **simulates** it and adds a roll-mobile OTP and a face match; a real use would need an express legal basis. |

## 4. The law that would be needed

The website's **Law** page (`#/law`, source `web/src/pages/Law.tsx`) sets out, provision by provision, what would have to change before a system like this could be used: a manner of voting under s.59 and a power like s.61A for certified remote systems; a definition of the counted vote under s.62 that allows revoting and the in-person override; s.128 secrecy duties for every operator; a new Part in the Conduct of Election Rules; an express basis for Aadhaar and PAN verification; DPDP treatment; protected-system status under the IT Act; new BNS offences; and a statutory right for candidates and observers to re-verify the record.

## 5. Recent context

* ECI elections use EVMs with VVPAT. Its published remote-voting work has concerned accessibility for domestic migrants via a multi-constituency **remote EVM** operated at supervised polling stations, not internet voting.
* In June 2025 the **Bihar State Election Commission** piloted mobile-app e-voting (an app developed by C-DAC) for municipal by-elections, for a registered subset of voters such as elderly, disabled and migrant electors. This was a State Election Commission pilot for local bodies under state law, not an ECI change, and its design has not, to this project's knowledge, been published for independent end-to-end verification. It illustrates why this project focuses on producing **public, independently checkable evidence**.

## 6. Data rules for this repository (mandatory)

1. Synthetic data only. No real electoral rolls, EPIC numbers, Aadhaar numbers, PAN numbers, names, addresses, phone numbers, photographs or biometrics — not in code, fixtures, issues, pull requests, logs or screenshots.
2. No production credentials or keys. Generated keys live in memory or in local temp directories and are never committed.
3. No scraping of ECI/SEC electoral-roll portals, including "for test data".
4. Real parties, candidates and constituencies are not used. Fixtures use `Synthetic Party A`, `Synthetic Constituency 1`, etc.
5. Published outputs carry the synthetic-election notice.

CI enforces rule 1 partly (`tools/scan_pii.py` fails on Aadhaar-, PAN-, EPIC- and Indian-mobile-shaped strings); reviewers enforce the rest.

## 7. Deployment boundaries

| Tier | Allowed | Gate to the next tier |
|---|---|---|
| **1. Research (current)** | Local simulations, synthetic elections, public code review, verifier experiments, academic publication | Independent cryptographic protocol review; independent implementation of the verifier; closure of all critical findings |
| **2. Controlled evaluation** | Isolated test environments, mock elections with consenting participants and no binding outcome (e.g. a student society straw poll), red-team exercises, accessibility studies | Written authorisation from a competent election authority for a specific pilot; DPDP compliance assessment; legal opinion; certification route agreed with the authority |
| **3. Official use** | Only as and when the competent authority adopts a method under the applicable statute and rules, with its own certification, operational controls and contingency plan | — |

**This repository stays in tier 1.** Moving to tier 2 or 3 requires a separate decision by people with authority to make it; it is not something a code change can do.
