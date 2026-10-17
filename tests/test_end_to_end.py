"""Full synthetic elections via the simulation harness, and verifier independence."""

import ast
import json
import os
from pathlib import Path

import pytest

from chunaviq.crypto import params
from chunaviq.election.simulate import SimConfig, run
from chunaviq.report import render
from chunaviq_verify import verify_record
from chunaviq_verify.groups import APPROVED_GROUPS
from chunaviq_verify.vmath import rederive

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def sim(tmp_path_factory):
    out = tmp_path_factory.mktemp("sim") / "run"
    summary = run(out, SimConfig(voters=150, constituencies=3, rsa_bits=2048, workers=2, seed=11))
    return out, summary


def test_every_injected_attack_is_rejected(sim):
    _, s = sim
    assert len(s["attacks"]) >= 9
    assert not any(v.startswith("ACCEPTED") for v in s["attacks"].values()), s["attacks"]
    assert s["attacks"]["replay_identical_ballot"].startswith("idempotent")


def test_simulation_record_verifies_and_matches_ground_truth(sim):
    out, s = sim
    rep = verify_record(out / "record", expect_manifest_hash=s["manifest_hash"])
    assert rep.verified, [c for c in rep.checks if c.status == "FAIL"]
    oracle = json.loads((out / "oracle.json").read_text())
    assert {c: r["counts"] for c, r in rep.results.items()} == oracle


def test_reconciliation_and_audits(sim):
    _, s = sim
    assert s["reconciliation"]["consistent"]
    assert s["ballots_accepted"] == s["credentials_issued"]
    assert s["benaloh_audits"].get("failed", 0) == 0


def test_observer_report_renders(sim):
    out, _ = sim
    html = render(verify_record(out / "record").to_dict())
    assert "VERIFIED" in html and "Synthetic research data" in html and "<script" not in html


def test_tally_survives_unavailable_trustee(sim):
    _, s = sim
    assert s["config"]["unavailable_trustees"] == 1 and s["results"]


# ------------------------------------------------------------------ independence
def test_verifier_shares_no_code_with_election_package():
    for f in (ROOT / "src" / "chunaviq_verify").rglob("*.py"):
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.split(".")[0] == "chunaviq", f"{f.name} imports {node.module}"
            if isinstance(node, ast.Import):
                assert all(a.name.split(".")[0] != "chunaviq" for a in node.names), f.name


def test_verifier_group_constants_match_election_constants():
    a = APPROVED_GROUPS["CHUNAVIQ-2048-256-V1"]
    assert (a["p"], a["q"], a["g"]) == (params.P_2048, params.Q_2048, params.G_2048)
    b = APPROVED_GROUPS["TEST-INSECURE-512-160"]
    assert (b["p"], b["q"], b["g"]) == (params.P_TEST, params.Q_TEST, params.G_TEST)


@pytest.mark.parametrize("name", list(APPROVED_GROUPS))
def test_groups_rederive_from_public_seed_independently(name):
    g = APPROVED_GROUPS[name]
    assert rederive(*g["seed"]) == (g["p"], g["q"], g["g"])


# ------------------------------------------------------------------ scale (slow)
@pytest.mark.slow
def test_scale_10000_voters(tmp_path):
    voters = int(os.environ.get("CHUNAVIQ_SCALE_VOTERS", "10000"))
    s = run(tmp_path / "scale", SimConfig(voters=voters))
    assert s["eligible_voters"] == voters
    assert not any(v.startswith("ACCEPTED") for v in s["attacks"].values())
    rep = verify_record(tmp_path / "scale" / "record", expect_manifest_hash=s["manifest_hash"])
    assert rep.verified
    oracle = json.loads((tmp_path / "scale" / "oracle.json").read_text())
    assert {c: r["counts"] for c, r in rep.results.items()} == oracle
