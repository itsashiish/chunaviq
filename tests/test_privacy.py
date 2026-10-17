"""Identity must not leak into the ballot path, the public record, or logs."""

import json
import logging
import sqlite3

from evlab.crypto.threshold import Trustee
from harness import Election, load_entries


def _all_text(record):
    return (record / "entries.jsonl").read_text() + (record / "checkpoints.jsonl").read_text()


def test_public_record_contains_no_voter_identifiers(finished):
    text = _all_text(finished.record)
    assert "syn-v-" not in text
    for v in finished.roll:
        assert v.voter_id not in text and v.auth_secret.hex() not in text


def test_ballot_box_database_holds_no_identity(finished):
    con = sqlite3.connect(finished.tmp / "private" / "box.db")
    cols = {r[1] for t in ("used_tokens", "alphas") for r in con.execute(f"PRAGMA table_info({t})")}
    assert cols == {"token", "seq", "alpha"}
    blob = (finished.tmp / "private" / "box.db").read_bytes()
    assert b"syn-v-" not in blob


def test_eligibility_database_never_sees_tokens_signatures_or_ballots(finished):
    con = sqlite3.connect(finished.tmp / "private" / "elig.db")
    dump = "\n".join(con.iterdump())
    for e in load_entries(finished.record):
        if e["type"] == "ballot":
            b = e["body"]["ballot"]
            assert b["credential"]["token"] not in dump
            assert b["credential"]["signature"] not in dump
            assert e["body"]["tracking_code"] not in dump


def test_record_timestamps_are_hour_granular(finished):
    for e in load_entries(finished.record):
        assert len(e["time_bucket"]) == len("2026-11-02T01")
        assert "time" not in json.dumps(e["body"]).replace("time_bucket", "")


def test_participation_commitments_are_not_in_issuance_order(finished):
    summ = [e for e in load_entries(finished.record) if e["type"] == "participation_summary"][0]["body"]
    for c in summ["constituencies"].values():
        assert c["commitments"] == sorted(c["commitments"])


def test_logs_carry_no_identity(tmp_path, caplog):
    caplog.set_level(logging.DEBUG, logger="evlab")
    e = Election(tmp_path)
    d = e.credentialed(0)
    e.box.submit(d.prepare("C1").ballot)
    try:
        e.box.submit(d.prepare("C1").ballot)
    except Exception:  # noqa: BLE001
        pass
    try:
        e.credentialed(0)
    except Exception:  # noqa: BLE001
        pass
    text = caplog.text
    assert caplog.records and "syn-v-" not in text and d.token.hex() not in text


def test_trustees_decrypt_only_aggregates(tmp_path, monkeypatch):
    calls = []
    orig = Trustee.decryption_share

    def spy(self, ct, ctx):
        calls.append(ctx)
        return orig(self, ct, ctx)

    monkeypatch.setattr(Trustee, "decryption_share", spy)
    e = Election(tmp_path, voters_per=(4, 4))
    for i in range(8):
        e.vote(i, i % 4)
    e.close_and_tally()
    k = e.manifest["trustees"]["threshold"]
    options_total = sum(len(c["options"]) for c in e.manifest["constituencies"])
    assert len(calls) == k * options_total  # never per ballot
    assert all(c[1] == "decrypt-aggregate" for c in calls)
