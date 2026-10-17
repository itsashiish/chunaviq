from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, settings

sys.path.insert(0, str(Path(__file__).parent))

settings.register_profile("ci", max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
settings.register_profile("deep", max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))

from harness import Election  # noqa: E402


@pytest.fixture
def election(tmp_path):
    return Election(tmp_path)


@pytest.fixture(scope="session")
def finished(tmp_path_factory):
    """A complete small election with a published record (secure group), exercising
    every protocol-v2 path: a revote, a re-registration, a polling-day override."""
    from collections import Counter

    e = Election(tmp_path_factory.mktemp("finished"), voters_per=(8, 7))
    final: dict[int, int] = {}
    for i in range(len(e.roll) - 3):  # three abstain
        e.vote(i, i % 4)
        final[i] = i % 4
    e.vote(0, 3)  # changed their mind: only this one counts
    final[0] = 3
    d1 = e.devices[1]
    d1.register(e.elig, "aadhaar-face")  # new phone: the old tag (and its ballot) stops counting
    e.cast(d1, e.options[d1.voter.constituency][2])
    final[1] = 2
    e.in_person.append(2)  # voted online, then at the polling station: online ballot cancelled
    del final[2]
    expected: dict[str, Counter] = {}
    for i, ci in final.items():
        v = e.roll[i]
        expected.setdefault(v.constituency, Counter())[e.options[v.constituency][ci]] += 1
    e.expected = {c: {o: expected.get(c, Counter())[o] for o in e.options[c]} for c in e.options}
    e.results = e.close_and_tally()
    return e
