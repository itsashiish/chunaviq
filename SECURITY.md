# Security policy

## Scope

This is a **research prototype** that runs synthetic elections. It is not deployed anywhere and must not be used for any binding election. We still treat flaws seriously, because the point of the project is to produce trustworthy evidence about what such a system can and cannot guarantee.

In scope: anything that would let someone break **eligibility** (vote without a credential, vote twice), **ballot secrecy** (link a voter to a vote with fewer than the assumed colluders), **verifiability** (make the independent verifier accept a wrong result or a tampered record), or **integrity of the build** (CI, releases, dependencies).

Out of scope: the residual risks already documented in `docs/threat-model.md` (coercion, malicious voter devices, denial of service, ≥ k colluding trustees), unless you show a way to make them worse than documented.

## Reporting

Use **GitHub private vulnerability reporting** (Security tab → "Report a vulnerability"). Do not open a public issue or pull request for an exploitable flaw.

Please include: affected commit, the invariant you broke (`spec/invariants.md`), and a minimal reproduction using **synthetic data only** — ideally a failing pytest.

We aim to acknowledge within 5 working days, agree a fix and disclosure date within 30 days, and credit reporters who want credit in `audits/`.

## Real election systems

**Never test against real election infrastructure** (ECI, State Election Commissions, C-DAC or vendor systems). Unauthorised access is an offence under the Information Technology Act, 2000. If you believe you have found a flaw in a real system, report it to the system owner or to CERT-In (https://www.cert-in.org.in), not here.
