"""python -m chunaviq_verify RECORD_DIR [options]  -- exit code 0 only if VERIFIED."""

from __future__ import annotations

import argparse
import json
import sys

from .verifier import verify_record


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="chunaviq-verify", description="Independently verify an chunaviq election record.")
    ap.add_argument("record", help="directory containing entries.jsonl and checkpoints.jsonl")
    ap.add_argument("--expect-manifest-hash", help="manifest hash obtained out-of-band from the authority")
    ap.add_argument("--expect-source-digest", help="source digest of the audited software release")
    ap.add_argument("--allow-insecure-test-group", action="store_true", help="accept TEST-ONLY groups (tests only)")
    ap.add_argument("--json", metavar="OUT", help="write the full JSON report here")
    ap.add_argument("--workers", type=int, default=None)
    a = ap.parse_args(argv)
    rep = verify_record(
        a.record,
        expect_manifest_hash=a.expect_manifest_hash,
        expect_source_digest=a.expect_source_digest,
        allow_insecure_group=a.allow_insecure_test_group,
        workers=a.workers,
    )
    d = rep.to_dict()
    for c in d["checks"]:
        print(f"[{c['status']:4}] {c['id']:34} {c['title']}" + (f"\n         {c['detail']}" if c["detail"] and c["status"] != "PASS" else ""))
    print(f"\n{d['status']}  ({d['failures']} failures, {d['warnings']} warnings)")
    if a.json:
        with open(a.json, "w") as f:
            json.dump(d, f, indent=2, sort_keys=True)
    return 0 if rep.verified else 1


if __name__ == "__main__":
    sys.exit(main())
