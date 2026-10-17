# Audits and evidence

| Item | What it is |
|---|---|
| [`2026-10-17-self-assessment.md`](2026-10-17-self-assessment.md) | Internal findings (fixed and open), capacity numbers |
| [`scale-10k/`](scale-10k/) | Evidence from a 10,000-eligible-voter synthetic election |

`scale-10k/` holds the run summary, the verifier's JSON report, the observer report, the simulation ground truth, the signed checkpoints and the signed manifest entry. The full record (128 MB) is not committed; regenerate it with `chunaviq simulate` or the `scale` workflow. A regenerated record will have **different** keys, ciphertexts and roots (all randomness is fresh) but must verify the same way.

Independent audit reports, when they exist, go here as `YYYY-MM-DD-<auditor>.md` with a remediation table that links each finding to the commit that fixed it.
