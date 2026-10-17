# Audits and evidence

| Item | What it is |
|---|---|
| [`2026-10-17-self-assessment.md`](2026-10-17-self-assessment.md) | Internal findings (fixed and open), capacity numbers |
| [`scale-10k/`](scale-10k/) | Evidence from a 10,000-eligible-voter synthetic election (v0.1.0 run; regenerate for v2 with `make scale`) |
| `rehearsal-<profile>-<date>/` | Dress rehearsals: an election over HTTP under seven attack kinds. `summary.json`, `verify.json`, `report.md`, `server-metrics.csv` (every second) and `requests.csv.gz` (every request). How to run and publish one: [`docs/dos-and-rehearsal.md`](../docs/dos-and-rehearsal.md) |

`scale-10k/` holds the run summary, the verifier's JSON report, the observer report, the simulation ground truth, the signed checkpoints and the signed manifest entry. The full record is not committed; regenerate it with `chunaviq simulate` or the `scale` workflow. A regenerated record will have **different** keys, ciphertexts and roots (all randomness is fresh) but must verify the same way.

Independent audit reports, when they exist, go here as `YYYY-MM-DD-<auditor>.md` with a remediation table that links each finding to the commit that fixed it.
