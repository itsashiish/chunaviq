"""Adversarial tests on the published record.

Two attacker models:
  * outsider  -- edits the record but cannot sign anything
  * insider   -- additionally holds the board operator key (and, where stated,
                 the officer key) and re-signs everything after tampering

The verifier must reject both. Insider tampering must be caught by the
cryptography that no single role can forge (tag proofs, ZK proofs, shuffle
proofs, trustee signatures, threshold decryption).
"""

import json
import shutil

import pytest

from chunaviq.crypto.elgamal import Ciphertext
from chunaviq.crypto.encoding import to_hex
from chunaviq_verify import verify_record
from harness import Election, copy_record, load_entries, resign_checkpoints, write_entries


def failed(rep) -> set[str]:
    return {c.id for c in rep.checks if c.status == "FAIL"}


@pytest.fixture
def rec(finished, tmp_path):
    return copy_record(finished.record, tmp_path / "rec")


def first(entries, t):
    return next(e for e in entries if e["type"] == t)


def test_untampered_record_verifies(finished):
    rep = verify_record(finished.record, expect_manifest_hash=finished.mhash)
    assert rep.verified, failed(rep)
    assert all(c.status == "PASS" for c in rep.checks)


def test_counts_match_ground_truth(finished):
    """Revote counted once, re-registered voter's new ballot counted, polling-day voter's online ballot not counted."""
    rep = verify_record(finished.record)
    assert {c: r["counts"] for c, r in rep.results.items()} == finished.expected
    assert sum(sum(v.values()) for v in finished.expected.values()) == len(finished.roll) - 4
    cast = sum(r["ballots_cast"] for r in rep.results.values())
    assert cast == len(finished.roll) - 3 + 2  # one revote + one re-registered vote


# ------------------------------------------------------------------ outsider
def test_outsider_alters_a_ballot(rec):
    es = load_entries(rec)
    b = first(es, "ballot")["body"]["ballot"]
    b["selections"][0]["ciphertext"]["beta"] = to_hex(int(b["selections"][0]["ciphertext"]["beta"], 16) ^ 1)
    write_entries(rec, es)
    assert "board.checkpoints" in failed(verify_record(rec))


def test_outsider_deletes_a_ballot(rec):
    es = load_entries(rec)
    idx = next(i for i, e in enumerate(es) if e["type"] == "ballot")
    del es[idx]
    for i, e in enumerate(es):
        e["seq"] = i
    write_entries(rec, es)
    assert not verify_record(rec).verified


def test_outsider_truncates_record(rec):
    lines = (rec / "entries.jsonl").read_bytes().split(b"\n")
    (rec / "entries.jsonl").write_bytes(b"\n".join(lines[:-3]) + b"\n")
    rep = verify_record(rec)
    assert not rep.verified


def test_outsider_forks_checkpoint_history(rec):
    cps = [json.loads(x) for x in (rec / "checkpoints.jsonl").read_bytes().split(b"\n") if x]
    cps[-1]["consistency_proof"] = list(reversed(cps[-1]["consistency_proof"]))
    (rec / "checkpoints.jsonl").write_text("\n".join(json.dumps(c, sort_keys=True, separators=(",", ":")) for c in cps) + "\n")
    assert "board.checkpoints" in failed(verify_record(rec))


def test_wrong_pinned_manifest_hash(finished):
    assert "manifest.pinned" in failed(verify_record(finished.record, expect_manifest_hash="00" * 32))


def test_missing_checkpoints_file_fails(rec):
    (rec / "checkpoints.jsonl").write_text("")
    assert not verify_record(rec).verified


# ------------------------------------------------------------------ insider (board key)
def test_insider_alters_ballot_and_resigns(finished, rec):
    es = load_entries(rec)
    s0 = first(es, "ballot")["body"]["ballot"]["selections"][0]
    ct = Ciphertext.from_dict(s0["ciphertext"])
    s0["ciphertext"] = Ciphertext(ct.alpha, ct.beta * finished.grp.g % finished.grp.p).to_dict()
    write_entries(rec, es)
    resign_checkpoints(rec, finished.operator)
    f = failed(verify_record(rec))
    assert "board.checkpoints" not in f and "ballots.valid" in f


def test_insider_stuffs_a_ballot_without_tag_proof(finished, rec):
    """The ballot box knows voters' tags; it still cannot make a ballot for one."""
    es = load_entries(rec)
    idx = next(i for i, e in enumerate(es) if e["type"] == "ballot")
    forged = json.loads(json.dumps(es[idx]))
    tag = forged["body"]["ballot"]["tag"]["ciphertext"]
    tag["beta"] = to_hex(int(tag["beta"], 16) * finished.grp.g % finished.grp.p)
    es.insert(idx + 1, forged)
    for i, e in enumerate(es):
        e["seq"] = i
    write_entries(rec, es)
    resign_checkpoints(rec, finished.operator)
    f = failed(verify_record(rec))
    assert {"ballots.valid", "ballots.no_copies"} <= f


def test_insider_duplicates_a_ballot(finished, rec):
    es = load_entries(rec)
    idx = next(i for i, e in enumerate(es) if e["type"] == "ballot")
    es.insert(idx + 1, json.loads(json.dumps(es[idx])))
    for i, e in enumerate(es):
        e["seq"] = i
    write_entries(rec, es)
    resign_checkpoints(rec, finished.operator)
    f = failed(verify_record(rec))
    assert "ballots.no_copies" in f


def test_insider_drops_a_ballot_and_resigns(finished, rec):
    es = load_entries(rec)
    idx = next(i for i, e in enumerate(es) if e["type"] == "ballot")
    del es[idx]
    for i, e in enumerate(es):
        e["seq"] = i
    write_entries(rec, es)
    resign_checkpoints(rec, finished.operator)
    f = failed(verify_record(rec))
    assert "lifecycle.close_count" in f or "record.structure" in f or "finalization.complete" in f


def test_insider_with_officer_key_changes_result(finished, rec):
    """Even an insider holding the officer AND board keys cannot change a count:
    the counts must equal the threshold decryption of the ballot aggregates."""
    es = load_entries(rec)
    res = first(es, "result")["body"]
    res = {k: v for k, v in res.items() if k not in ("signer", "signature")}
    res["counts"][0]["votes"] += 1
    res["counts"][1]["votes"] -= 1
    first(es, "result")["body"] = finished.officer.sign_body(res)
    write_entries(rec, es)
    resign_checkpoints(rec, finished.operator)
    f = failed(verify_record(rec))
    assert "tally.results" in f and "board.checkpoints" not in f


def test_insider_with_officer_key_swaps_winner_flag(finished, rec):
    es = load_entries(rec)
    entry = first(es, "result")
    res = {k: v for k, v in entry["body"].items() if k not in ("signer", "signature")}
    res["winner"] = "NOTA"
    entry["body"] = finished.officer.sign_body(res)
    write_entries(rec, es)
    resign_checkpoints(rec, finished.operator)
    assert "tally.results" in failed(verify_record(rec))


def test_tampered_decryption_share(finished, rec):
    es = load_entries(rec)
    sh = first(es, "decryption_shares")["body"]["shares"][0]
    sh["share"] = to_hex(int(sh["share"], 16) * finished.grp.g % finished.grp.p)
    write_entries(rec, es)
    resign_checkpoints(rec, finished.operator)
    f = failed(verify_record(rec))
    assert "record.structure" in f or "tally.decryption" in f  # trustee signature breaks first


def test_ballot_injected_after_close(finished, rec):
    es = load_entries(rec)
    ballot = json.loads(json.dumps(first(es, "ballot")))
    close_idx = next(i for i, e in enumerate(es) if e["type"] == "lifecycle" and e["body"]["state"] == "CLOSED")
    es.insert(close_idx + 1, ballot)
    for i, e in enumerate(es):
        e["seq"] = i
    write_entries(rec, es)
    resign_checkpoints(rec, finished.operator)
    assert "record.structure" in failed(verify_record(rec))


def test_missing_publication_step(finished, rec):
    es = load_entries(rec)[:-1]  # drop PUBLISHED
    write_entries(rec, es)
    resign_checkpoints(rec, finished.operator)
    assert "record.structure" in failed(verify_record(rec))


def test_manifest_swapped_after_open(finished, rec):
    es = load_entries(rec)
    m = es[0]["body"]
    man = json.loads(json.dumps(m["manifest"]))
    man["constituencies"][0]["options"][0]["name"] = "Different Candidate"
    es[0]["body"] = dict(m, manifest=man)
    write_entries(rec, es)
    resign_checkpoints(rec, finished.operator)
    f = failed(verify_record(rec))
    assert {"manifest.hash", "manifest.signature"} <= f


def test_insecure_group_refused_unless_flagged(tmp_path):
    e = Election(tmp_path, group="TEST-INSECURE-512-160", voters_per=(3, 3))
    for i in range(6):
        e.vote(i)
    e.close_and_tally()
    assert "group.approved" in failed(verify_record(e.record))
    assert verify_record(e.record, allow_insecure_group=True).verified


# ------------------------------------------------------------------ protocol v2: finalization and mixing
def test_insider_flips_finalization_after_mixing(finished, rec):
    """With the board key, re-sign a finalization item claiming a superseded ballot
    counts. The flag no longer matches its proof, and the shuffles no longer start
    from the published flags."""
    es = load_entries(rec)
    fin = first(es, "finalization")["body"]
    item = fin["items"][0]
    item["flag"]["beta"] = to_hex(int(item["flag"]["beta"], 16) * finished.grp.g % finished.grp.p)
    body = {k: v for k, v in fin.items() if k not in ("signer", "signature")}
    first(es, "finalization")["body"] = finished.operator.sign_body(body)
    write_entries(rec, es)
    resign_checkpoints(rec, finished.operator)
    f = failed(verify_record(rec))
    assert {"finalization.proofs", "mixing.shuffles"} <= f


def test_mixer_replaces_a_row(finished, rec):
    """A mixer swaps one output row for a copy of another (dropping one vote, doubling another)."""
    es = load_entries(rec)
    sh = first(es, "shuffle")
    rows = sh["body"]["rows"]
    rows[0] = json.loads(json.dumps(rows[1]))
    write_entries(rec, es)
    resign_checkpoints(rec, finished.operator)
    f = failed(verify_record(rec))
    assert "record.structure" in f or "mixing.shuffles" in f  # the mixer's signature breaks first


def _corrupt_box(tmp_path, mark):
    """An election whose ballot box (and officer, who skips his own check) cheats at finalization."""
    e = Election(tmp_path, voters_per=(4,), candidates=2, trustees=3, threshold=2)
    for i in range(4):
        e.vote(i, i % 3)
    e.vote(0, 2)  # revote
    d = e.devices[1]
    d.register(e.elig, "aadhaar-otp")  # re-registration: tag 1 revoked
    e.cast(d, "C1")
    orig = e.box.final_seqs

    def cheat(valid):
        finals, stats = orig(valid)
        return mark(e, finals), stats

    e.box.final_seqs = cheat
    e.admin.strict = False
    e.close_and_tally()
    return e


def test_ballot_box_counts_two_ballots_of_one_voter(tmp_path):
    e = _corrupt_box(tmp_path, lambda e, finals: finals | {min(s for s in range(e.board.size) if e.board.entry(s)["type"] == "ballot")})
    assert "mixing.counted_tags" in failed(verify_record(e.record))


def test_ballot_box_counts_a_revoked_tag(tmp_path):
    def include_revoked(e, finals):
        seqs = [s for s in range(e.board.size) if e.board.entry(s)["type"] == "ballot"]
        return finals | {seqs[1]}  # voter 1's first ballot, cast with the tag they later replaced

    e = _corrupt_box(tmp_path, include_revoked)
    assert "mixing.counted_tags" in failed(verify_record(e.record))


def test_source_digest_pin(finished, tmp_path):
    assert "manifest.software" in failed(verify_record(finished.record, expect_source_digest="0" * 64))
    shutil.rmtree(tmp_path, ignore_errors=True)
