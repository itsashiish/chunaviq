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
    """A complete small election with a published record (secure group)."""
    e = Election(tmp_path_factory.mktemp("finished"), voters_per=(8, 7))
    for i in range(len(e.roll) - 3):  # three abstain
        e.vote(i, i % 4)
    e.results = e.close_and_tally()
    return e
