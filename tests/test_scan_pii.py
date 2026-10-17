"""The synthetic-data guard flags identity-shaped values but not decimal numbers."""

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location("scan_pii", Path(__file__).parents[1] / "tools" / "scan_pii.py")
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


def _hits(line: str) -> set[str]:
    return {name for name, rx in scan.PATTERNS.items() if rx.search(line)}


def test_identity_shaped_values_are_flagged():
    # Built from pieces so this file never contains an identity-shaped literal itself.
    twelve, ten = "2345" + "67890123", "98765" + "43210"
    assert _hits(f"id {twelve[:4]} {twelve[4:8]} {twelve[8:]}") == {"aadhaar-like"}
    assert _hits(f"id {twelve}.") == {"aadhaar-like"}  # sentence-ending full stop
    assert _hits(f"call +91 {ten}") == {"mobile-like"}
    assert _hits("card " + "ABC" + "1234567") == {"epic-like"}
    assert _hits("pan " + "ABCDE" + "1234" + "F") == {"pan-like"}
    assert _hits("syn-pan-0000042 syn-uid-0000042") == set()


def test_decimal_numbers_are_not_flagged():
    assert _hits('"fixed": 2228.333333333334,') == set()
    assert _hits('"design_per_s": 29761.904761904763') == set()
    assert _hits("ratio " + "98765" + "43210.5") == set()
