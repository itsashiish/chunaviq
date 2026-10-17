#!/usr/bin/env python3
"""Fail if anything shaped like a real Indian identity number is committed.

Patterns: Aadhaar-like (12 digits, first digit 2-9, optional spaces),
EPIC-like (3 capital letters + 7 digits), Indian mobile-like (+91 / 10 digits
starting 6-9). Synthetic IDs in this project use `syn-v-NNNNNNN` instead.
Usage: python tools/scan_pii.py [paths...]  (defaults to tracked files)
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PATTERNS = {
    "aadhaar-like": re.compile(r"(?<![\w-])[2-9]\d{3}[ ]?\d{4}[ ]?\d{4}(?![\w-])"),
    "epic-like": re.compile(r"(?<![A-Za-z0-9])[A-Z]{3}\d{7}(?![A-Za-z0-9])"),
    "mobile-like": re.compile(r"(?<![\w-])(?:\+91[ -]?)?[6-9]\d{9}(?![\w-])"),
}
SKIP_SUFFIXES = {".png", ".jpg", ".pdf", ".zip", ".gz", ".db"}
SKIP_FILES = {"src/evlab/crypto/params.py", "src/evlab_verify/groups.py", "requirements/dev.txt", "requirements/runtime.txt"}


def files(args: list[str]) -> list[Path]:
    if args:
        return [Path(a) for a in args]
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout  # noqa: S603,S607
    return [Path(x) for x in out.splitlines()]


def main(argv: list[str]) -> int:
    hits = 0
    for f in files(argv):
        if f.suffix in SKIP_SUFFIXES or f.as_posix() in SKIP_FILES or not f.is_file():
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for name, rx in PATTERNS.items():
                if rx.search(line):
                    print(f"{f}:{n}: {name}: {line.strip()[:100]}")
                    hits += 1
    if hits:
        print(f"\n{hits} possible real-identity values found. This repository must contain synthetic data only.")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
