"""Independent verifier for an chunaviq election record.

    python -m chunaviq_verify RECORD_DIR [--expect-manifest-hash H] [--json OUT]

Reads only the public record (entries.jsonl, checkpoints.jsonl). Produces a
list of named checks; the record is VERIFIED only if every check passes.
Missing evidence is a failure, never a skip.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import multiprocessing as mp
import os
import sqlite3
import tempfile
from collections import Counter, deque
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass, field
from math import isqrt
from pathlib import Path

from .groups import APPROVED_GROUPS
from .vmath import (
    G,
    StreamingRoots,
    challenge,
    cjson,
    consistency_ok,
    cp_ok,
    ed_ok,
    hx,
    inclusion_ok,
    leaf,
    powmod,
    rsa_fdh_ok,
    schnorr_ok,
    zero_or_one_ok,
)

PASS, FAIL, WARN = "PASS", "FAIL", "WARN"
NOTA = "NOTA"


@dataclass
class Check:
    id: str
    title: str
    status: str
    detail: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    results: dict = field(default_factory=dict)
    facts: dict = field(default_factory=dict)

    def add(self, cid: str, title: str, ok: bool | None, detail: str = "") -> bool:
        status = PASS if ok else (WARN if ok is None else FAIL)
        self.checks.append(Check(cid, title, status, detail))
        return bool(ok)

    @property
    def verified(self) -> bool:
        return bool(self.checks) and all(c.status != FAIL for c in self.checks)

    def to_dict(self) -> dict:
        return {
            "status": "VERIFIED" if self.verified else "NOT VERIFIED",
            "failures": sum(c.status == FAIL for c in self.checks),
            "warnings": sum(c.status == WARN for c in self.checks),
            "checks": [asdict(c) for c in self.checks],
            "results": self.results,
            "facts": self.facts,
        }


class StructureError(Exception):
    pass


# --------------------------------------------------------------------- ballots
_B: dict = {}


def _binit(ctx: dict) -> None:
    _B.clear()
    _B.update(ctx)
    _B["G"] = G(ctx["p"], ctx["q"], ctx["g"])


def _check_ballot(b: dict) -> str | None:
    """Mirror of the ballot rules in spec/protocol.md section 5 (re-implemented)."""
    Gq, K, mh, eid = _B["G"], _B["K"], _B["mhash"], _B["election_id"]
    try:
        if set(b) != {"election_id", "constituency", "credential", "selections", "limit_proof"}:
            return "MALFORMED"
        if b["election_id"] != eid:
            return "WRONG_ELECTION"
        cons = b["constituency"]
        if cons not in _B["options"]:
            return "UNKNOWN_CONSTITUENCY"
        tok = b["credential"]["token"]
        if set(b["credential"]) != {"token", "signature"} or not isinstance(tok, str) or len(tok) != 64 or bytes.fromhex(tok).hex() != tok:
            return "MALFORMED"
        n, e = _B["issuers"][cons]
        msg = eid.encode() + b"\x00" + cons.encode() + b"\x00" + bytes.fromhex(tok)
        if not rsa_fdh_ok(n, e, msg, hx(b["credential"]["signature"])):
            return "BAD_CREDENTIAL"
        sels = b["selections"]
        if [s.get("option_id") for s in sels] != _B["options"][cons]:
            return "WRONG_BALLOT_STYLE"
        A, B = 1, 1
        for s in sels:
            if (
                set(s) != {"option_id", "ciphertext", "proof"}
                or set(s["ciphertext"]) != {"alpha", "beta"}
                or set(s["proof"]) != {"a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1"}
            ):
                return "MALFORMED"
            al, be = hx(s["ciphertext"]["alpha"]), hx(s["ciphertext"]["beta"])
            if not zero_or_one_ok(Gq, K, al, be, s["proof"], [mh, "selection", cons, s["option_id"], tok]):
                return "BAD_SELECTION_PROOF"
            A, B = A * al % Gq.p, B * be % Gq.p
        lp = b["limit_proof"]
        if set(lp) != {"a", "b", "v"}:
            return "MALFORMED"
        Y = B * pow(Gq.g, -1, Gq.p) % Gq.p
        if not cp_ok(Gq, K, A, Y, hx(lp["a"]), hx(lp["b"]), hx(lp["v"]), "contest-limit", [mh, "contest-limit", cons, tok]):
            return "BAD_LIMIT_PROOF"
        return None
    except (KeyError, TypeError, ValueError, AttributeError):
        return "MALFORMED"


# --------------------------------------------------------------------- helpers
def _hour(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H").replace(tzinfo=dt.UTC)


def _ts(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def _lagrange0(q: int, idx: list[int], i: int) -> int:
    num = den = 1
    for m in idx:
        if m != i:
            num, den = num * m % q, den * (m - i) % q
    return num * pow(den, -1, q) % q


def _decide(counts: dict[str, int]) -> dict:
    c = {k: v for k, v in counts.items() if k != NOTA}
    top = max(c.values()) if c else 0
    lead = sorted(k for k, v in c.items() if v == top)
    return {"winner": lead[0] if len(lead) == 1 else None, "tied": lead if len(lead) > 1 else [], "nota_exceeds_winner": counts.get(NOTA, 0) > top}


# --------------------------------------------------------------------- verifier
def verify_record(
    record_dir: str | Path,
    *,
    expect_manifest_hash: str | None = None,
    allow_insecure_group: bool = False,
    expect_source_digest: str | None = None,
    workers: int | None = None,
) -> Report:
    rep = Report()
    try:
        _verify(Path(record_dir), rep, expect_manifest_hash, allow_insecure_group, expect_source_digest, workers)
    except StructureError as e:
        rep.add("record.structure", "Record follows the required entry sequence", False, str(e))
    except (KeyError, TypeError, ValueError, IndexError, json.JSONDecodeError) as e:
        rep.add("record.parse", "Record is well-formed", False, f"{type(e).__name__}: {e}")
    return rep


def _verify(d: Path, rep: Report, pin: str | None, allow_insecure: bool, pin_src: str | None, workers: int | None) -> None:
    # ---------------------------------------------------------------- 1. stream pass 1: canonical form + Merkle roots
    # Constant memory: entries are read line by line; only the Merkle frontier
    # (O(log n) hashes) and the roots at checkpoint sizes are kept.
    cps = [json.loads(x) for x in (d / "checkpoints.jsonl").read_bytes().split(b"\n") if x]
    roots_stream = StreamingRoots({cp.get("tree_size", -1) for cp in cps})
    first: dict | None = None
    count = 0
    with open(d / "entries.jsonl", "rb") as fh:
        for i, raw in enumerate(fh):
            ln = raw[:-1] if raw.endswith(b"\n") else raw
            e = json.loads(ln)
            if cjson(e) != ln or e.get("seq") != i:
                rep.add("record.canonical", "Entries are canonical and contiguously numbered", False, f"entry {i}")
                return
            if i == 0:
                first = e
            roots_stream.add(leaf(ln))
            count += 1
    roots = roots_stream.roots
    rep.add("record.canonical", "Entries are canonical and contiguously numbered", True, f"{count} entries")
    rep.facts["entries"] = count

    # ---------------------------------------------------------------- 2. manifest
    if first is None or first["type"] != "manifest":
        raise StructureError("first entry must be the manifest")
    mb = first["body"]
    man = mb["manifest"]
    mh = hashlib.sha256(cjson(man)).hexdigest()
    keys = man["keys"]
    rep.add("manifest.hash", "Manifest hash matches manifest content", mh == mb["manifest_hash"], mh)
    rep.add("manifest.signature", "Manifest signed by the election officer key it declares", ed_ok(mb, keys["officer"], "officer"))
    if pin:
        rep.add("manifest.pinned", "Manifest hash equals the independently obtained value", pin == mh, f"expected {pin}")
    else:
        rep.add(
            "manifest.pinned",
            "Manifest hash pinned to an out-of-band value",
            None,
            "Not pinned: the record is self-consistent, but its authenticity rests on how you obtained it. "
            "Obtain the manifest hash from the authority through a separate channel and pass --expect-manifest-hash.",
        )
    if pin_src:
        rep.add("manifest.software", "Software digest equals the audited release", man["software"]["source_digest"] == pin_src)
    eid = man["election_id"]
    rep.facts.update(election_id=eid, title=man["title"], manifest_hash=mh, notice=man["notice"], window=man["window"], software=man["software"])

    gname = man["group"]
    if gname not in APPROVED_GROUPS:
        rep.add("group.approved", "Election group is an approved parameter set", False, gname)
        return
    gp = APPROVED_GROUPS[gname]
    secure_ok = gp["secure"] or allow_insecure
    rep.add(
        "group.approved",
        "Election group is an approved parameter set",
        secure_ok if gp["secure"] else (None if allow_insecure else False),
        gname + ("" if gp["secure"] else " is a TEST-ONLY insecure group"),
    )
    if not secure_ok:
        return
    Gq = G(gp["p"], gp["q"], gp["g"])
    rep.add("group.sanity", "Group generator has order q", Gq.g != 1 and powmod(Gq.g, Gq.q, Gq.p) == 1 and (Gq.p - 1) % Gq.q == 0)

    # ---------------------------------------------------------------- 3. checkpoints
    ok, why, prev = bool(cps), "", None
    for cp in cps:
        size = cp["tree_size"]
        if not ed_ok(cp, keys["board"], "board") or cp["election_id"] != eid:
            ok, why = False, f"bad signature at size {size}"
            break
        if size not in roots or roots[size].hex() != cp["root"]:
            ok, why = False, f"root mismatch at size {size} (entries altered, removed or inserted)"
            break
        if prev is not None:
            if size <= prev["tree_size"] or cp["prev_tree_size"] != prev["tree_size"]:
                ok, why = False, f"checkpoint sequence broken at size {size}"
                break
            if not consistency_ok(
                prev["tree_size"], size, bytes.fromhex(prev["root"]), bytes.fromhex(cp["root"]), [bytes.fromhex(h) for h in cp["consistency_proof"]]
            ):
                ok, why = False, f"consistency proof invalid {prev['tree_size']}->{size}"
                break
        prev = cp
    rep.add("board.checkpoints", "Every signed checkpoint matches the entries and extends its predecessor", ok, why or f"{len(cps)} checkpoints")
    rep.add(
        "board.sealed",
        "Final signed checkpoint covers every entry",
        bool(cps) and cps[-1]["tree_size"] == count,
        f"final size {cps[-1]['tree_size'] if cps else 0} of {count}",
    )
    rep.facts["final_root"] = cps[-1]["root"] if cps else None

    # ---------------------------------------------------------------- 4. structure walk
    it = _stream_entries(d / "entries.jsonl", skip=1)

    def nxt(expected_type: str, state: str | None = None) -> dict:
        try:
            e = next(it)
        except StopIteration:
            raise StructureError(f"record ends early; expected {expected_type}{' ' + state if state else ''}") from None
        if e["type"] != expected_type or (state and e["body"].get("state") != state):
            raise StructureError(f"entry {e['seq']}: expected {expected_type}{' ' + state if state else ''}, got {e['type']}")
        return e

    def lifecycle(state: str) -> dict:
        e = nxt("lifecycle", state)
        if not (ed_ok(e["body"], keys["officer"], "officer") and e["body"]["election_id"] == eid):
            raise StructureError(f"lifecycle {state} not signed by officer")
        return e

    lifecycle("KEY_CEREMONY")
    members = man["trustees"]["members"]
    k = man["trustees"]["threshold"]
    n = len(members)
    comms: dict[int, list[int]] = {}
    pok_ok = True
    for mem in members:
        e = nxt("trustee_commitment")
        b = e["body"]
        if not ed_ok(b, mem["public_key"], mem["role"]) or b["commitment"]["index"] != mem["index"]:
            raise StructureError(f"commitment of {mem['role']} missing, out of order or wrongly signed")
        Cs = [hx(c) for c in b["commitment"]["commitments"]]
        prs = b["commitment"]["proofs"]
        if len(Cs) != k or len(prs) != k:
            pok_ok = False
        for j, (C, pr) in enumerate(zip(Cs, prs, strict=False)):  # length mismatch already recorded above
            if not schnorr_ok(Gq, C, hx(pr["h"]), hx(pr["v"]), [mh, "trustee-coefficient", str(mem["index"]), str(j)]):
                pok_ok = False
        comms[mem["index"]] = Cs
    rep.add("ceremony.commitments", f"All {n} trustees committed to degree-{k - 1} polynomials with valid proofs of knowledge", pok_ok)
    acks = True
    for mem in members:
        b = nxt("trustee_ack")["body"]
        acks &= ed_ok(b, mem["public_key"], mem["role"]) and b["index"] == mem["index"] and b["verified_all_shares"] is True
    rep.add("ceremony.acks", "Every trustee signed that all shares it received verified", acks)
    jk = nxt("joint_key")["body"]
    K = 1
    for i in comms:
        K = K * comms[i][0] % Gq.p
    rep.add(
        "ceremony.joint_key",
        "Published joint key = product of trustees' constant commitments",
        ed_ok(jk, keys["officer"], "officer") and hx(jk["joint_public_key"]) == K and Gq.member(K) and K != 1,
    )

    def pub_share(i: int) -> int:
        acc = 1
        for Cs in comms.values():
            xj = 1
            for C in Cs:
                acc = acc * Gq.e(C, xj) % Gq.p
                xj = xj * i % Gq.q
        return acc

    ik = nxt("issuer_keys")["body"]
    cons_ids = [c["id"] for c in man["constituencies"]]
    issuers = {c: (hx(v["n"]), hx(v["e"])) for c, v in ik["issuer_keys"].items()}
    good = ed_ok(ik, keys["eligibility"], "eligibility") and sorted(issuers) == sorted(cons_ids) and all(e == 65537 for _, e in issuers.values())
    rep.add("credentials.issuer_keys", "Credential issuer keys signed by the eligibility authority, one per constituency", good)
    weak = [c for c, (nn, _) in issuers.items() if nn.bit_length() < 3072]
    if weak:
        rep.add(
            "credentials.key_size",
            "Issuer RSA moduli are at least 3072 bits",
            None if all(issuers[c][0].bit_length() >= 2048 for c in weak) else False,
            f"{len(weak)} below 3072 bits",
        )
    lifecycle("READY")
    open_e = lifecycle("OPEN")

    # ---------------------------------------------------------------- 5. ballots (streamed in bounded chunks)
    options = {c["id"]: [o["id"] for o in c["options"]] for c in man["constituencies"]}
    ctx = {"p": Gq.p, "q": Gq.q, "g": Gq.g, "K": K, "mhash": mh, "election_id": eid, "options": options, "issuers": issuers}
    w0, w1 = _ts(man["window"]["opens_at"]), _ts(man["window"]["closes_at"])
    h0, h1 = _hour(_hour_floor(w0)), _hour(_hour_floor(w1))
    workers = workers or os.cpu_count() or 1
    tally = _BallotTally(ctx, workers if count > 400 else 1)
    in_win = True
    chunk: list[tuple[int, dict]] = []
    try:
        while True:
            try:
                e = next(it)
            except StopIteration:
                raise StructureError("record ends before CLOSED") from None
            if e["type"] == "ballot":
                in_win &= h0 <= _hour(e["time_bucket"]) <= h1
                chunk.append((e["seq"], e["body"]))
                if len(chunk) >= _CHUNK:
                    tally.submit(chunk)
                    chunk = []
                continue
            if e["type"] != "lifecycle" or e["body"].get("state") != "CLOSED":
                raise StructureError(f"entry {e['seq']}: only ballots may appear between OPEN and CLOSED (got {e['type']})")
            if not ed_ok(e["body"], keys["officer"], "officer"):
                raise StructureError("CLOSED not signed by officer")
            close_e = e
            break
        if chunk:
            tally.submit(chunk)
        tally.finish()
    finally:
        tally.close()
    n_all = sum(tally.count.values())
    bad = sorted(tally.bad)
    detail = f"{n_all} checked" + (f"; invalid (seq, reason): {bad[:5]}" if bad else "")
    rep.add("ballots.valid", "Every ballot carries a valid credential, ciphertexts and proofs (exactly one selection)", not bad, detail)
    rep.add("ballots.one_per_credential", "No credential used twice", tally.dup_tokens == 0, f"{tally.dup_tokens} reused")
    rep.add("ballots.no_copies", "No ciphertext appears twice (ballot-copying defence)", tally.dup_alphas == 0)
    rep.add("ballots.tracking_codes", "Tracking codes equal the hash of each ballot", tally.bad_tracking == 0)
    rep.add("ballots.window", "Ballots were recorded inside the published voting window (hour resolution)", in_win)
    rep.add("lifecycle.open_time", "Election opened no earlier than the published opening hour", _hour(open_e["time_bucket"]) >= _hour(_hour_floor(w0)))
    cb = close_e["body"]
    rep.add(
        "lifecycle.close_count",
        "CLOSED entry states the number of ballots actually recorded",
        cb.get("ballots_accepted") == n_all,
        f"{cb.get('ballots_accepted')} vs {n_all}",
    )
    if "early_close_reason" in cb:
        rep.add("lifecycle.early_close", "Polls closed at the published time", None, f"EARLY CLOSE: {cb['early_close_reason']}")
    rep.facts["rejections_by_reason"] = cb.get("rejections_by_reason", {})

    # ---------------------------------------------------------------- 6. participation
    ps = nxt("participation_summary")["body"]
    per_cons_ballots = tally.count
    pok, notes = ed_ok(ps, keys["eligibility"], "eligibility"), []
    for c in man["constituencies"]:
        s = ps["constituencies"].get(c["id"])
        if s is None:
            pok = False
            notes.append(f"{c['id']}: missing")
            continue
        cm = s["commitments"]
        conds = [
            s["eligible"] == c["eligible_voters"],
            s["credentials_issued"] <= s["eligible"],
            per_cons_ballots[c["id"]] <= s["credentials_issued"],
            len(cm) == s["credentials_issued"],
            len(set(cm)) == len(cm),
            cm == sorted(cm),
        ]
        if not all(conds):
            pok = False
            notes.append(f"{c['id']}: {conds}")
        rep.results.setdefault(c["id"], {}).update(eligible=s["eligible"], credentials_issued=s["credentials_issued"])
    rep.add("reconciliation.participation", "ballots <= credentials issued <= eligible voters, per constituency", pok, "; ".join(notes))

    # ---------------------------------------------------------------- 7. tally
    tally_ok, dec_ok, res_ok, tnotes = True, True, True, []
    shares_cache = {m["index"]: pub_share(m["index"]) for m in members}
    roles = {m["index"]: m for m in members}
    for c in man["constituencies"]:
        cid, opts = c["id"], options[c["id"]]
        mine_n = tally.count.get(cid, 0)
        ag = nxt("aggregate")["body"]
        if ag["constituency"] != cid or not ed_ok(ag, keys["officer"], "officer"):
            raise StructureError(f"aggregate for {cid} missing or unsigned")
        acc = tally.agg.get(cid) or [[1, 1] for _ in opts]
        aggs = {oid: (acc[j][0], acc[j][1]) for j, oid in enumerate(opts)}
        posted = {x["option_id"]: (hx(x["ciphertext"]["alpha"]), hx(x["ciphertext"]["beta"])) for x in ag["aggregates"]}
        if posted != aggs or ag["ballot_count"] != mine_n:
            tally_ok = False
            tnotes.append(f"{cid}: aggregate mismatch")
        got: dict[str, dict[int, int]] = {oid: {} for oid in opts}
        providers = []
        while True:
            e = next(it, None)
            if e is None:
                raise StructureError(f"record ends inside tally of {cid}")
            if e["type"] == "decryption_shares":
                b = e["body"]
                i = b["index"]
                if b["constituency"] != cid or i not in roles or i in providers or not ed_ok(b, roles[i]["public_key"], roles[i]["role"]):
                    raise StructureError(f"bad decryption share entry {e['seq']}")
                providers.append(i)
                for x in b["shares"]:
                    oid = x["option_id"]
                    M = hx(x["share"])
                    pr = x["proof"]
                    if oid not in aggs or not cp_ok(
                        Gq, aggs[oid][0], shares_cache[i], M, hx(pr["a"]), hx(pr["b"]), hx(pr["v"]), "decryption-share", [mh, "decrypt-aggregate", cid, oid]
                    ):
                        dec_ok = False
                        tnotes.append(f"{cid}/{oid}: invalid share from trustee {i}")
                    got[oid][i] = M
                continue
            if e["type"] != "result":
                raise StructureError(f"entry {e['seq']}: expected decryption_shares or result")
            res = e["body"]
            break
        if len(providers) < k:
            dec_ok = False
            tnotes.append(f"{cid}: only {len(providers)} shares, threshold {k}")
        if not ed_ok(res, keys["officer"], "officer") or res["constituency"] != cid or sorted(res["quorum"]) != sorted(providers):
            raise StructureError(f"result for {cid} unsigned or quorum mismatch")
        counts = {}
        for oid in opts:
            if any(i not in got[oid] for i in providers):
                dec_ok = False
                continue
            A, B = aggs[oid]
            s = 1
            for i in providers:
                s = s * Gq.e(got[oid][i], _lagrange0(Gq.q, providers, i)) % Gq.p
            gm = B * pow(s, -1, Gq.p) % Gq.p
            counts[oid] = _bsgs(Gq, gm, mine_n)
        posted_counts = {x["option_id"]: x["votes"] for x in res["counts"]}
        if any(v is None for v in counts.values()) or counts != posted_counts or sum(posted_counts.values()) != mine_n:
            res_ok = False
            tnotes.append(f"{cid}: decrypted {counts} != published {posted_counts}")
        dec = _decide(posted_counts)
        if {kk: res.get(kk) for kk in dec} != dec or res["ballot_count"] != mine_n:
            res_ok = False
            tnotes.append(f"{cid}: winner/tie flags do not follow the published rule")
        rep.results.setdefault(cid, {}).update(
            name=c["name"], counts=posted_counts, ballots=mine_n, quorum=providers, options={o["id"]: o["name"] for o in c["options"]}, **dec
        )
    rep.add("tally.aggregates", "Encrypted per-option totals equal the product of all accepted ballots", tally_ok, "; ".join(tnotes))
    rep.add("tally.decryption", f"At least {k} trustees decrypted each total with valid proofs", dec_ok)
    rep.add("tally.results", "Published counts equal the verified decryption and follow the FPTP/NOTA rule", res_ok)
    lifecycle("TALLIED")
    lifecycle("PUBLISHED")
    if next(it, None) is not None:
        raise StructureError("entries after PUBLISHED")
    rep.add("record.structure", "Record follows the required entry sequence", True)


# --------------------------------------------------------------------- streaming helpers
_CHUNK = 512


def _stream_entries(path: Path, skip: int = 0):
    """Parsed entries straight from disk, one at a time."""
    with open(path, "rb") as fh:
        for i, raw in enumerate(fh):
            if i >= skip:
                yield json.loads(raw)


def _check_chunk(items: list[tuple[int, dict]]) -> dict:
    """Worker: verify ballots, tracking codes, partial aggregates and dedup fingerprints for one chunk."""
    p, options = _B["G"].p, _B["options"]
    bad, bad_tc, agg, count, toks, alphas = [], 0, {}, Counter(), [], []
    for seq, body in items:
        b = body.get("ballot") if isinstance(body, dict) else None
        code = _check_ballot(b) if isinstance(b, dict) else "MALFORMED"
        if code:
            bad.append((seq, code))
        try:
            if body["tracking_code"] != hashlib.sha256(cjson(b)).hexdigest():
                bad_tc += 1
            cons = b["constituency"]
            count[cons] += 1
            toks.append(hashlib.sha256(b["credential"]["token"].encode()).digest()[:16])
            sels = b["selections"]
            alphas.extend(hashlib.sha256(s["ciphertext"]["alpha"].encode()).digest()[:16] for s in sels)
            if cons in options and len(sels) == len(options[cons]):
                acc = agg.setdefault(cons, [[1, 1] for _ in sels])
                for j, s in enumerate(sels):
                    acc[j][0] = acc[j][0] * hx(s["ciphertext"]["alpha"]) % p
                    acc[j][1] = acc[j][1] * hx(s["ciphertext"]["beta"]) % p
        except (KeyError, TypeError, ValueError, AttributeError):
            bad_tc += 1
    return {"bad": bad, "bad_tc": bad_tc, "agg": agg, "count": dict(count), "toks": toks, "alphas": alphas}


class _BallotTally:
    """Runs chunk checks (in a bounded process pool when workers > 1), merges partial
    aggregates, and detects duplicate credentials/ciphertexts with an on-disk index,
    so memory stays flat however many ballots the record holds."""

    def __init__(self, ctx: dict, workers: int) -> None:
        self.ctx, self.p = ctx, ctx["p"]
        self.bad: list[tuple[int, str]] = []
        self.bad_tracking = 0
        self.dup_tokens = 0
        self.dup_alphas = 0
        self.agg: dict[str, list[list[int]]] = {}
        self.count: Counter[str] = Counter()
        self._tmp = tempfile.TemporaryDirectory(prefix="chunaviq-verify-")
        self._db = sqlite3.connect(os.path.join(self._tmp.name, "dedup.db"))
        self._db.executescript(
            "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;"
            "CREATE TABLE tok(fp BLOB PRIMARY KEY) WITHOUT ROWID; CREATE TABLE alp(fp BLOB PRIMARY KEY) WITHOUT ROWID;"
        )
        self._pool: ProcessPoolExecutor | None = None
        self._pending: deque = deque()
        self._max_pending = 2 * workers
        if workers > 1:
            self._pool = ProcessPoolExecutor(max_workers=workers, mp_context=mp.get_context("spawn"), initializer=_binit, initargs=(ctx,))
        else:
            _binit(ctx)

    def submit(self, chunk: list[tuple[int, dict]]) -> None:
        if self._pool is None:
            self._merge(_check_chunk(chunk))
            return
        self._pending.append(self._pool.submit(_check_chunk, chunk))
        while len(self._pending) >= self._max_pending:
            self._merge(self._pending.popleft().result())

    def finish(self) -> None:
        while self._pending:
            self._merge(self._pending.popleft().result())

    def _merge(self, r: dict) -> None:
        self.bad.extend(r["bad"])
        self.bad_tracking += r["bad_tc"]
        self.count.update(r["count"])
        for cons, acc in r["agg"].items():
            mine = self.agg.setdefault(cons, [[1, 1] for _ in acc])
            for j, (a, b) in enumerate(acc):
                mine[j][0] = mine[j][0] * a % self.p
                mine[j][1] = mine[j][1] * b % self.p
        before = self._db.total_changes
        self._db.executemany("INSERT OR IGNORE INTO tok VALUES (?)", [(x,) for x in r["toks"]])
        self.dup_tokens += len(r["toks"]) - (self._db.total_changes - before)
        before = self._db.total_changes
        self._db.executemany("INSERT OR IGNORE INTO alp VALUES (?)", [(x,) for x in r["alphas"]])
        self.dup_alphas += len(r["alphas"]) - (self._db.total_changes - before)

    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(cancel_futures=True)
        self._db.close()
        self._tmp.cleanup()


def _bsgs(Gq: G, target: int, bound: int) -> int | None:
    """Smallest m in [0, bound] with g^m = target, by baby-step giant-step; None if absent."""
    n = isqrt(bound) + 1
    table: dict[int, int] = {}
    acc = 1
    for j in range(n):
        table.setdefault(acc, j)
        acc = acc * Gq.g % Gq.p
    step = pow(acc, -1, Gq.p)
    cur = target
    for i in range(n + 1):
        if cur in table:
            m = i * n + table[cur]
            return m if m <= bound else None
        cur = cur * step % Gq.p
    return None


def _hour_floor(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H")


def verify_receipt(record_dir: str | Path, receipt: dict) -> bool:
    """A voter's check that their tracking code is in the signed record."""
    d = Path(record_dir)
    lines = [x for x in (d / "entries.jsonl").read_bytes().split(b"\n") if x]
    seq = receipt["seq"]
    if seq >= len(lines):
        return False
    entry = json.loads(lines[seq])
    if entry["type"] != "ballot" or entry["body"]["tracking_code"] != receipt["tracking_code"]:
        return False
    man = json.loads(lines[0])["body"]["manifest"]
    for x in (d / "checkpoints.jsonl").read_bytes().split(b"\n"):
        if not x:
            continue
        cp = json.loads(x)
        if cp["tree_size"] == receipt["tree_size"] and cp["root"] == receipt["root"] and ed_ok(cp, man["keys"]["board"], "board"):
            return inclusion_ok(leaf(lines[seq]), seq, cp["tree_size"], [bytes.fromhex(h) for h in receipt["inclusion_path"]], bytes.fromhex(cp["root"]))
    return False


__all__ = ["verify_record", "verify_receipt", "Report", "Check", "challenge"]
