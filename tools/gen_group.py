#!/usr/bin/env python3
"""Re-derive the approved election groups from their public seeds.

    python tools/gen_group.py --check     compare with src/evlab/crypto/params.py
    python tools/gen_group.py --print     print derived parameters

Derivation is specified in spec/protocol.md section 2. Anyone can run this to
confirm the published parameters contain no hidden structure.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from evlab.crypto import params  # noqa: E402
from evlab.crypto.primes import derive_group  # noqa: E402

EXPECTED = {
    "EVLAB-2048-256-V1": (params.P_2048, params.Q_2048, params.G_2048),
    "TEST-INSECURE-512-160": (params.P_TEST, params.Q_TEST, params.G_TEST),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--print", action="store_true")
    a = ap.parse_args()
    ok = True
    for name, (seed, pb, qb) in params.GROUP_SEEDS.items():
        p, q, g = derive_group(seed, pb, qb)
        if a.print:
            print(f"{name}\n  seed {seed!r}\n  p {p:x}\n  q {q:x}\n  g {g:x}")
        same = (p, q, g) == EXPECTED[name]
        ok &= same
        print(f"{name}: {'OK' if same else 'MISMATCH'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
