# Paper

*ChunavIQ: An Open, End-to-End Verifiable Remote-Voting Prototype for India's Legal and Identity Constraints, with Deniable Revoting, Hardware-Held Trustee Keys and Adversarial Dress Rehearsals* — Ashish Ramtekkar, 2026. Preprint.

| File | |
|---|---|
| [`ChunavIQ-paper.pdf`](ChunavIQ-paper.pdf) | The paper (Springer LNCS format, 14 pages) |
| `main.tex`, `references.bib` | LaTeX source (`llncs` class, `splncs04` bibliography style) |

Build: `latexmk -pdf main.tex` (needs TeX Live with the `llncs` class, e.g. Debian/Ubuntu `texlive-publishers`).

Every number in the paper comes from files in this repository: unit costs and the national model from `docs/scale/capacity.md`, rehearsals from `audits/rehearsal-*`.
