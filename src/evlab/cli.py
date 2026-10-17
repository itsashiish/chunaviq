"""evlab command line.

evlab simulate OUT [--voters N ...]   run a full synthetic election
evlab verify RECORD [...]             delegate to the independent verifier
evlab report REPORT.json OUT.html     render the observer report
evlab check-group                     re-derive the group from its public seed
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="evlab")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("simulate", help="run a complete synthetic election")
    s.add_argument("out", type=Path)
    s.add_argument("--voters", type=int, default=10_000)
    s.add_argument("--constituencies", type=int, default=5)
    s.add_argument("--candidates", type=int, default=4, help="contesting candidates per constituency (NOTA added)")
    s.add_argument("--turnout", type=float, default=0.68)
    s.add_argument("--trustees", type=int, default=5)
    s.add_argument("--threshold", type=int, default=3)
    s.add_argument("--unavailable-trustees", type=int, default=1)
    s.add_argument("--workers", type=int, default=None)
    s.add_argument("--seed", type=int, default=2026)
    s.add_argument("--rsa-bits", type=int, default=3072)
    s.add_argument("--no-attacks", action="store_true")
    s.add_argument("--test-group", action="store_true", help="use the INSECURE 512-bit test group (fast; tests only)")

    v = sub.add_parser("verify", help="independently verify a record (evlab_verify)")
    v.add_argument("rest", nargs=argparse.REMAINDER)

    r = sub.add_parser("report", help="render an observer HTML report from a verifier JSON report")
    r.add_argument("report_json", type=Path)
    r.add_argument("out_html", type=Path)

    sub.add_parser("check-group", help="re-derive approved groups from their seeds and compare")

    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    if a.cmd == "simulate":
        from .election.simulate import SimConfig, run

        cfg = SimConfig(
            voters=a.voters,
            constituencies=a.constituencies,
            candidates_per_constituency=a.candidates,
            turnout=a.turnout,
            trustees=a.trustees,
            threshold=a.threshold,
            unavailable_trustees=a.unavailable_trustees,
            seed=a.seed,
            rsa_bits=a.rsa_bits,
            inject_attacks=not a.no_attacks,
            group="TEST-INSECURE-512-160" if a.test_group else "EVLAB-2048-256-V1",
        )
        if a.workers:
            cfg.workers = a.workers
        summary = run(a.out, cfg)
        print(json.dumps({k: summary[k] for k in ("ballots_accepted", "credentials_issued", "attacks", "results", "timings")}, indent=2, sort_keys=True))
        failed = [k for k, v in summary["attacks"].items() if v.startswith("ACCEPTED")]
        return 1 if failed else 0

    if a.cmd == "verify":
        from evlab_verify.__main__ import main as vmain

        return vmain(a.rest)

    if a.cmd == "report":
        from .report import write_report

        write_report(a.report_json, a.out_html)
        return 0

    if a.cmd == "check-group":
        from .crypto import params
        from .crypto.primes import derive_group

        ok = True
        for name, (seed, pb, qb) in params.GROUP_SEEDS.items():
            from .crypto.group import get_group

            g = get_group(name)
            same = derive_group(seed, pb, qb) == (g.p, g.q, g.g)
            ok &= same
            print(f"{name}: {'matches seed derivation' if same else 'MISMATCH'}")
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
