"""Identity must not leak into the ballot path, the public record, or logs; the
public record must not reveal which ballots are revotes of one another."""

import json
import logging
import sqlite3

from chunaviq.crypto.encoding import to_hex
from chunaviq.custody import TrusteeApplet
from harness import Election, load_entries


def _all_text(record):
    return (record / "entries.jsonl").read_text() + (record / "checkpoints.jsonl").read_text()


def test_public_record_contains_no_voter_identifiers(finished):
    text = _all_text(finished.record)
    for marker in ("syn-v-", "syn-uid-", "syn-pan-", "syn-mob-", "Synthetic Person"):
        assert marker not in text
    for v in finished.roll:
        assert v.face.hex() not in text


def test_public_record_does_not_link_revotes(finished):
    """Ballots show only an encrypted tag; no tag value appears next to any ballot."""
    tags = {to_hex(d.T) for d in finished.devices.values()}
    for e in load_entries(finished.record):
        if e["type"] in ("ballot", "finalization", "shuffle", "flag_shares"):
            blob = json.dumps(e["body"])
            assert not any(t in blob for t in tags)


def test_ballot_box_database_holds_no_identity(finished):
    con = sqlite3.connect(finished.tmp / "private" / "box.db")
    cols = {r[1] for t in ("ballots", "alphas", "finals") for r in con.execute(f"PRAGMA table_info({t})")}
    assert cols == {"seq", "tc", "tag", "cons", "alpha", "u", "flag_alpha", "flag_beta"}
    blob = (finished.tmp / "private" / "box.db").read_bytes()
    for marker in (b"syn-v-", b"syn-uid-", b"syn-pan-", b"syn-mob-"):
        assert marker not in blob


def test_eligibility_database_stores_no_raw_identity_numbers(finished):
    """Aadhaar and PAN references are kept only as keyed hashes."""
    con = sqlite3.connect(finished.tmp / "private" / "elig.db")
    dump = "\n".join(con.iterdump())
    assert "syn-uid-" not in dump and "syn-pan-" not in dump


def test_eligibility_database_never_sees_ballots(finished):
    con = sqlite3.connect(finished.tmp / "private" / "elig.db")
    dump = "\n".join(con.iterdump())
    for e in load_entries(finished.record):
        if e["type"] == "ballot":
            assert e["body"]["tracking_code"] not in dump
            assert e["body"]["ballot"]["tag"]["ciphertext"]["alpha"] not in dump


def test_record_timestamps_are_hour_granular(finished):
    for e in load_entries(finished.record):
        assert len(e["time_bucket"]) == len("2026-11-02T01")
        assert "time" not in json.dumps(e["body"]).replace("time_bucket", "")


def test_registration_lists_are_sorted_not_in_registration_order(finished):
    chunks = [e["body"] for e in load_entries(finished.record) if e["type"] == "registration_list"]
    assert chunks
    for c in chunks:
        assert c["items"] == sorted(c["items"])


def test_logs_carry_no_identity(tmp_path, caplog):
    caplog.set_level(logging.DEBUG, logger="chunaviq")
    e = Election(tmp_path)
    d = e.registered(0)
    e.cast(d, "C1")
    bad = e.sub(d, "C1")
    bad["tag"] = to_hex(e.registered(1).T)
    try:
        e.box.submit(bad)
    except Exception:  # noqa: BLE001
        pass
    d.register(e.elig, "aadhaar-otp")
    text = caplog.text
    assert caplog.records and "syn-v-" not in text and "syn-uid-" not in text and to_hex(d.T) not in text


def test_trustees_never_decrypt_an_individual_vote(tmp_path, monkeypatch):
    """HSMs are asked for: per-option totals, mixed (anonymous) flags, and mixed tags
    of counted rows. Never a ballot's vote ciphertext, never a ballot's own tag."""
    seen = []
    orig = TrusteeApplet.decrypt

    def spy(self, request, approvals, attestations):
        seen.append((request["purpose"], [it["ciphertext"]["alpha"] for it in request["items"]]))
        return orig(self, request, approvals, attestations)

    monkeypatch.setattr(TrusteeApplet, "decrypt", spy)
    e = Election(tmp_path, voters_per=(4, 4))
    for i in range(8):
        e.vote(i, i % 4)
    e.close_and_tally()
    assert {p for p, _ in seen} == {"aggregate", "mix-flag", "mix-tag"}
    ballot_alphas = set()
    for ent in load_entries(e.record):
        if ent["type"] == "ballot":
            b = ent["body"]["ballot"]
            ballot_alphas.add(b["tag"]["ciphertext"]["alpha"])
            ballot_alphas.update(s["ciphertext"]["alpha"] for s in b["selections"])
    assert not any(a in ballot_alphas for _, alphas in seen for a in alphas)
    k = e.manifest["trustees"]["threshold"]
    options_total = sum(len(c["options"]) for c in e.manifest["constituencies"])
    assert sum(len(a) for p, a in seen if p == "aggregate") == k * options_total
