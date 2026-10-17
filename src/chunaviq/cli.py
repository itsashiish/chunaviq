"""chunaviq command line.

chunaviq simulate OUT [--voters N ...]   run a full synthetic election
chunaviq verify RECORD [...]             delegate to the independent verifier
chunaviq report REPORT.json OUT.html     render the observer report
chunaviq check-group                     re-derive the group from its public seed
chunaviq federate / verify-federation    national election as constituency shards
chunaviq capacity                        measure unit costs, model national capacity
chunaviq serve --election DIR            hardened ballot-intake server (one constituency)
chunaviq rehearse smoke|shard-peak       dress rehearsal over HTTP under attack, with full outputs
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="chunaviq")
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
    s.add_argument("--no-attacks", action="store_true")
    s.add_argument("--test-group", action="store_true", help="use the INSECURE 512-bit test group (fast; tests only)")

    v = sub.add_parser("verify", help="independently verify a record (chunaviq_verify)")
    v.add_argument("rest", nargs=argparse.REMAINDER)

    r = sub.add_parser("report", help="render an observer HTML report from a verifier JSON report")
    r.add_argument("report_json", type=Path)
    r.add_argument("out_html", type=Path)

    sub.add_parser("check-group", help="re-derive approved groups from their seeds and compare")

    f = sub.add_parser("federate", help="run a national election as one shard per constituency")
    f.add_argument("out", type=Path)
    f.add_argument("--shards", type=int, default=24)
    f.add_argument("--voters-per-shard", type=int, default=300)
    f.add_argument("--workers", type=int, default=None)
    f.add_argument("--seed", type=int, default=2026)

    vf = sub.add_parser("verify-federation", help="independently verify a federated national election")
    vf.add_argument("rest", nargs=argparse.REMAINDER)

    sub.add_parser("capacity", help="benchmark unit costs and model national-scale capacity")

    sv = sub.add_parser("serve", help="run the hardened ballot-intake server for one constituency")
    sv.add_argument("rest", nargs=argparse.REMAINDER)

    rh = sub.add_parser("rehearse", help="dress rehearsal: an election over HTTP under attack, end to end, with full outputs")
    rh.add_argument("profile", choices=["smoke", "mini-peak", "shard-peak"])
    rh.add_argument("--out", type=Path, default=None)
    rh.add_argument("--seconds", type=int, default=None, help="load duration (default: profile's)")
    rh.add_argument("--rate", type=float, default=None, help="honest ballots/s (default: profile's, or as close to the design rate as this machine allows)")
    rh.add_argument("--workers", type=int, default=None, help="server verification processes")

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
            inject_attacks=not a.no_attacks,
            group="TEST-INSECURE-512-160" if a.test_group else "CHUNAVIQ-2048-256-V1",
        )
        if a.workers:
            cfg.workers = a.workers
        summary = run(a.out, cfg)
        print(
            json.dumps(
                {k: summary[k] for k in ("ballots_accepted", "registered", "finalization", "coercion", "attacks", "results", "timings")},
                indent=2,
                sort_keys=True,
            )
        )
        failed = [k for k, v in summary["attacks"].items() if v.startswith("ACCEPTED")]
        return 1 if failed else 0

    if a.cmd == "verify":
        from chunaviq_verify.__main__ import main as vmain

        return vmain(a.rest)

    if a.cmd == "federate":
        from .election.federation import FedConfig, run_federation

        fc = FedConfig(shards=a.shards, voters_per_shard=a.voters_per_shard, seed=a.seed)
        if a.workers:
            fc.workers = a.workers
        print(json.dumps(run_federation(a.out, fc), indent=2, sort_keys=True))
        return 0

    if a.cmd == "verify-federation":
        from chunaviq_verify.federation import main as fmain

        return fmain(a.rest)

    if a.cmd == "capacity":
        from .capacity import main as cmain

        return cmain()

    if a.cmd == "serve":
        from .service.sequencer import main as smain

        return smain(a.rest)

    if a.cmd == "rehearse":
        import datetime as _dt

        from .service.rehearsal import run as rrun

        out = a.out or Path("rehearsal") / f"{a.profile}-{_dt.datetime.now(_dt.UTC).strftime('%Y%m%dT%H%M%SZ')}"
        summary = rrun(a.profile, out, seconds=a.seconds, rate=a.rate, workers=a.workers)
        print((out / "report.md").read_text())
        print(f"Outputs in {out}")
        return 0 if summary["verification"]["status"] == "VERIFIED" and summary["every_receipt_is_on_the_board"] else 1

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
