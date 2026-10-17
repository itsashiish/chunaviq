"""Independent verifier for a ChunavIQ election record (protocol v2).

    python -m chunaviq_verify RECORD_DIR [--expect-manifest-hash H] [--json OUT]

Reads only the public record (entries.jsonl, checkpoints.jsonl). Produces a
list of named checks; the record is VERIFIED only if every check passes.
Missing evidence is a failure, never a skip.

Memory stays flat however large the record: entries are streamed; per-ballot
data needed later (tag and flag ciphertexts) goes to a temporary on-disk
index; proof checking runs in bounded chunks, in parallel when workers > 1.
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
from .vmath import G, StreamingRoots, challenge, cjson, consistency_ok, cp_ok, ed_ok, hx, inclusion_ok, leaf, powmod, schnorr_ok, zero_or_one_ok
from .vsigma import finalize_branches, shuffle_ok, sigma_ok, tag_eqs

PASS, FAIL, WARN = "PASS", "FAIL", "WARN"
NOTA = "NOTA"
SPEC = "chunaviq-record/2"


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


# ===================================================================== workers
_B: dict = {}


def _binit(ctx: dict) -> None:
    _B.clear()
    _B.update(ctx)
    _B["G"] = G(ctx["p"], ctx["q"], ctx["g"])


def _ct(d: dict) -> tuple[int, int]:
    if set(d) != {"alpha", "beta"}:
        raise ValueError("ciphertext schema")
    return hx(d["alpha"]), hx(d["beta"])


def _check_ballot(b: dict) -> str | None:
    """Mirror of the ballot rules in spec/protocol.md section 6 (re-implemented)."""
    Gq, K, mh, eid = _B["G"], _B["K"], _B["mhash"], _B["election_id"]
    try:
        if set(b) != {"election_id", "constituency", "tag", "selections", "limit_proof"}:
            return "MALFORMED"
        if b["election_id"] != eid:
            return "WRONG_ELECTION"
        cons = b["constituency"]
        if cons not in _B["options"]:
            return "UNKNOWN_CONSTITUENCY"
        tag = b["tag"]
        if set(tag) != {"ciphertext", "proof"}:
            return "MALFORMED"
        ta, tb = _ct(tag["ciphertext"])
        if not (Gq.member(ta) and Gq.member(tb)):
            return "INVALID_CIPHERTEXT"
        tah = tag["ciphertext"]["alpha"]
        sels = b["selections"]
        if [s.get("option_id") for s in sels] != _B["options"][cons]:
            return "WRONG_BALLOT_STYLE"
        A, B = 1, 1
        for s in sels:
            if set(s) != {"option_id", "ciphertext", "proof"} or set(s["proof"]) != {"a0", "b0", "a1", "b1", "c0", "c1", "v0", "v1"}:
                return "MALFORMED"
            al, be = _ct(s["ciphertext"])
            if not zero_or_one_ok(Gq, K, al, be, s["proof"], [mh, "selection", cons, s["option_id"], tah]):
                return "BAD_SELECTION_PROOF"
            A, B = A * al % Gq.p, B * be % Gq.p
        lp = b["limit_proof"]
        if set(lp) != {"a", "b", "v"}:
            return "MALFORMED"
        Y = B * pow(Gq.g, -1, Gq.p) % Gq.p
        if not cp_ok(Gq, K, A, Y, hx(lp["a"]), hx(lp["b"]), hx(lp["v"]), "contest-limit", [mh, "contest-limit", cons, tah]):
            return "BAD_LIMIT_PROOF"
        digest = hashlib.sha256(cjson({"selections": sels, "limit_proof": lp})).hexdigest()
        if not sigma_ok(Gq, tag_eqs(Gq, K, ta, tb), 2, tag["proof"], "ballot-tag", [mh, "ballot-tag", cons, digest]):
            return "BAD_TAG_PROOF"
        return None
    except (KeyError, TypeError, ValueError, AttributeError):
        return "MALFORMED"


def _ballot_chunk(items: list[tuple[int, dict]]) -> dict:
    bad, bad_tc, count, alphas, rows = [], 0, Counter(), [], []
    for seq, body in items:
        b = body.get("ballot") if isinstance(body, dict) else None
        code = _check_ballot(b) if isinstance(b, dict) else "MALFORMED"
        if code:
            bad.append((seq, code))
        try:
            if body["tracking_code"] != hashlib.sha256(cjson(b)).hexdigest():
                bad_tc += 1
            count[b["constituency"]] += 1
            tct = b["tag"]["ciphertext"]
            alphas.append(hashlib.sha256(tct["alpha"].encode()).digest()[:16])
            alphas.extend(hashlib.sha256(s["ciphertext"]["alpha"].encode()).digest()[:16] for s in b["selections"])
            rows.append((seq, b["constituency"], body["tracking_code"], tct["alpha"], tct["beta"]))
        except (KeyError, TypeError, ValueError, AttributeError):
            bad_tc += 1
    return {"bad": bad, "bad_tc": bad_tc, "count": dict(count), "alphas": alphas, "rows": rows}


def _final_chunk(items: list[tuple[int, str, str, list, dict]]) -> dict:
    """Finalization items, each paired with its ballot's votes: check the OR-proof,
    accumulate masked totals per constituency."""
    Gq, K, mh = _B["G"], _B["K"], _B["mhash"]
    p = Gq.p
    bad, agg, flags = [], {}, []
    for seq, cons, tc, votes, it in items:
        try:
            if (
                set(it) != {"seq", "tracking_code", "flag", "masked", "proof"}
                or it["seq"] != seq
                or it["tracking_code"] != tc
                or len(it["masked"]) != len(votes)
            ):
                bad.append(seq)
                continue
            fa, fb = _ct(it["flag"])
            masked = [_ct(m) for m in it["masked"]]
            if not all(Gq.member(x) for x in (fa, fb, *(v for m in masked for v in m))):
                bad.append(seq)
                continue
            if not _sigma_or(Gq, finalize_branches(Gq, K, (fa, fb), votes, masked), it["proof"], [mh, "finalize", cons, tc]):
                bad.append(seq)
                continue
            acc = agg.setdefault(cons, [[1, 1] for _ in masked])
            for j, (ma, mb) in enumerate(masked):
                acc[j][0] = acc[j][0] * ma % p
                acc[j][1] = acc[j][1] * mb % p
            flags.append((seq, it["flag"]["alpha"], it["flag"]["beta"]))
        except (KeyError, TypeError, ValueError, AttributeError):
            bad.append(seq)
    return {"bad": bad, "agg": agg, "flags": flags}


def _sigma_or(Gq, branches, proof, ctx) -> bool:
    from .vsigma import sigma_or_ok

    return sigma_or_ok(Gq, branches, proof, "finalize", ctx)


def _lagrange0(q: int, idx: list[int], i: int) -> int:
    num = den = 1
    for m in idx:
        if m != i:
            num, den = num * m % q, den * (m - i) % q
    return num * pow(den, -1, q) % q


def _combine(Gq: G, beta: int, shares: dict[int, int]) -> int:
    idx = sorted(shares)
    s = 1
    for i in idx:
        s = s * Gq.e(shares[i], _lagrange0(Gq.q, idx, i)) % Gq.p
    return beta * pow(s, -1, Gq.p) % Gq.p


def _mix_batch(job: tuple) -> dict:
    """Verify one mixing batch: the shuffle chain, every flag share, every tag share.
    Returns flags, decrypted final tags (hex) and problems found."""
    cons, batch, rows, shuffles, flag_entries, tag_entries = job
    Gq, K, mh, pubs, k = _B["G"], _B["K"], _B["mhash"], _B["pubs"], _B["k"]
    problems: list[str] = []
    cur = rows
    mixers = []
    for sb in shuffles:
        try:
            out = [[_ct(c) for c in r] for r in sb["rows"]]
        except (KeyError, TypeError, ValueError):
            problems.append(f"{cons}/{batch}: malformed shuffle output")
            return {"problems": problems, "flags": [], "tags": [], "mixers": mixers}
        if not shuffle_ok(Gq, K, cur, out, sb["proof"], [mh, "mix", cons, str(batch), str(sb["mixer"])]):
            problems.append(f"{cons}/{batch}: shuffle by trustee {sb['mixer']} does not verify")
        mixers.append(sb["mixer"])
        cur = out
    # flags
    fshares: dict[int, list[int]] = {}
    for fb in flag_entries:
        i = fb["index"]
        if len(fb["shares"]) != len(cur):
            problems.append(f"{cons}/{batch}: trustee {i} flag share count")
            continue
        vals = []
        for r, x in enumerate(fb["shares"]):
            M = hx(x["share"])
            pr = x["proof"]
            if not cp_ok(Gq, cur[r][1][0], pubs[i], M, hx(pr["a"]), hx(pr["b"]), hx(pr["v"]), "decryption-share", [mh, "mix-flag", cons, str(batch), str(r)]):
                problems.append(f"{cons}/{batch}: invalid flag share from trustee {i} row {r}")
            vals.append(M)
        fshares[i] = vals
    if len(fshares) < k:
        problems.append(f"{cons}/{batch}: only {len(fshares)} flag decryptions, threshold {k}")
        return {"problems": problems, "flags": [], "tags": [], "mixers": mixers}
    flags = []
    for r in range(len(cur)):
        gf = _combine(Gq, cur[r][1][1], {i: v[r] for i, v in fshares.items()})
        if gf not in (1, Gq.g):
            problems.append(f"{cons}/{batch}: row {r} flag is not 0 or 1")
        flags.append(1 if gf == Gq.g else 0)
    want = [r for r, f in enumerate(flags) if f]
    tshares: dict[int, list[int]] = {}
    for tb in tag_entries:
        i = tb["index"]
        if tb["rows"] != want or len(tb["shares"]) != len(want):
            problems.append(f"{cons}/{batch}: trustee {i} decrypted tags of rows other than the counted ones")
            continue
        vals = []
        for r, x in zip(want, tb["shares"], strict=True):
            M = hx(x["share"])
            pr = x["proof"]
            if not cp_ok(Gq, cur[r][0][0], pubs[i], M, hx(pr["a"]), hx(pr["b"]), hx(pr["v"]), "decryption-share", [mh, "mix-tag", cons, str(batch), str(r)]):
                problems.append(f"{cons}/{batch}: invalid tag share from trustee {i} row {r}")
            vals.append(M)
        tshares[i] = vals
    if want and len(tshares) < k:
        problems.append(f"{cons}/{batch}: only {len(tshares)} tag decryptions, threshold {k}")
        return {"problems": problems, "flags": flags, "tags": [], "mixers": mixers}
    tags = [format(_combine(Gq, cur[r][0][1], {i: v[j] for i, v in tshares.items()}), "x") for j, r in enumerate(want)]
    return {"problems": problems, "flags": flags, "tags": tags, "mixers": mixers}


class _Pool:
    """Bounded parallel map with ordered results (or inline when workers <= 1)."""

    def __init__(self, ctx: dict, workers: int) -> None:
        self.ctx, self.workers = dict(ctx), workers
        self._pool = self._start() if workers > 1 else None
        if self._pool is None:
            _binit(self.ctx)
        self._pending: deque = deque()
        self._max = 2 * workers

    def _start(self) -> ProcessPoolExecutor:
        return ProcessPoolExecutor(max_workers=self.workers, mp_context=mp.get_context("spawn"), initializer=_binit, initargs=(self.ctx,))

    def submit(self, fn, arg, sink) -> None:
        if self._pool is None:
            sink(fn(arg))
            return
        self._pending.append((self._pool.submit(fn, arg), sink))
        while len(self._pending) >= self._max:
            f, s = self._pending.popleft()
            s(f.result())

    def drain(self) -> None:
        while self._pending:
            f, s = self._pending.popleft()
            s(f.result())

    def close(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(cancel_futures=True)

    def update(self, **kw) -> None:
        """Add context for the next phase (restarts workers; only between phases)."""
        self.drain()
        self.ctx.update(kw)
        if self._pool is None:
            _binit(self.ctx)
        else:
            self._pool.shutdown()
            self._pool = self._start()


# ===================================================================== helpers
_CHUNK = 256


def _hour(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H").replace(tzinfo=dt.UTC)


def _ts(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def _hour_floor(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H")


def _decide(counts: dict[str, int]) -> dict:
    c = {k: v for k, v in counts.items() if k != NOTA}
    top = max(c.values()) if c else 0
    lead = sorted(k for k, v in c.items() if v == top)
    return {"winner": lead[0] if len(lead) == 1 else None, "tied": lead if len(lead) > 1 else [], "nota_exceeds_winner": counts.get(NOTA, 0) > top}


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


def _stream_entries(path: Path, skip: int = 0, only: str | None = None):
    needle = None if only is None else b'"type":"' + only.encode() + b'"'
    with open(path, "rb") as fh:
        for i, raw in enumerate(fh):
            if i < skip or (needle is not None and needle not in raw):
                continue
            e = json.loads(raw)
            if only is None or e["type"] == only:
                yield e


class _Peek:
    def __init__(self, it) -> None:
        self._it, self._buf = it, []

    def peek(self):
        if not self._buf:
            self._buf.append(next(self._it, None))
        return self._buf[0]

    def __next__(self):
        if self._buf:
            x = self._buf.pop()
            if x is None:
                raise StopIteration
            return x
        return next(self._it)

    def __iter__(self):
        return self


# ===================================================================== verifier
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
    # ------------------------------------------------------------ 1. canonical form + Merkle roots (streamed)
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

    # ------------------------------------------------------------ 2. manifest
    if first is None or first["type"] != "manifest":
        raise StructureError("first entry must be the manifest")
    mb = first["body"]
    man = mb["manifest"]
    mh = hashlib.sha256(cjson(man)).hexdigest()
    keys = man["keys"]
    rep.add("manifest.spec", "Record uses protocol v2 (revoting, mixing)", man.get("spec_version") == SPEC, str(man.get("spec_version")))
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
    mix = man["mixing"]
    rep.facts.update(election_id=eid, title=man["title"], manifest_hash=mh, notice=man["notice"], window=man["window"], software=man["software"], mixing=mix)

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

    # ------------------------------------------------------------ 3. checkpoints
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

    # ------------------------------------------------------------ 4. structure walk: ceremony
    it = _Peek(_stream_entries(d / "entries.jsonl", skip=1))

    def nxt(expected_type: str, state: str | None = None) -> dict:
        e = it.peek()
        if e is None:
            raise StructureError(f"record ends early; expected {expected_type}{' ' + state if state else ''}")
        if e["type"] != expected_type or (state and e["body"].get("state") != state):
            raise StructureError(f"entry {e['seq']}: expected {expected_type}{' ' + state if state else ''}, got {e['type']}")
        return next(it)

    def lifecycle(state: str) -> dict:
        e = nxt("lifecycle", state)
        if not (ed_ok(e["body"], keys["officer"], "officer") and e["body"]["election_id"] == eid):
            raise StructureError(f"lifecycle {state} not signed by officer")
        return e

    lifecycle("KEY_CEREMONY")
    members = man["trustees"]["members"]
    roles = {m["index"]: m for m in members}
    k = man["trustees"]["threshold"]
    n = len(members)
    # In a federated election the ceremony is national: proofs are bound to the national manifest hash.
    cer_ctx = man["federation"]["national_manifest_hash"] if "federation" in man else mh
    comms: dict[int, list[int]] = {}
    pok_ok = True
    for mem in members:
        b = nxt("trustee_commitment")["body"]
        if not ed_ok(b, mem["public_key"], mem["role"]) or b["commitment"]["index"] != mem["index"]:
            raise StructureError(f"commitment of {mem['role']} missing, out of order or wrongly signed")
        Cs = [hx(c) for c in b["commitment"]["commitments"]]
        prs = b["commitment"]["proofs"]
        if len(Cs) != k or len(prs) != k:
            pok_ok = False
        for j, (C, pr) in enumerate(zip(Cs, prs, strict=False)):
            if not schnorr_ok(Gq, C, hx(pr["h"]), hx(pr["v"]), [cer_ctx, "trustee-coefficient", str(mem["index"]), str(j)]):
                pok_ok = False
        comms[mem["index"]] = Cs
    rep.add("ceremony.commitments", f"All {n} trustees committed to degree-{k - 1} polynomials with valid proofs of knowledge", pok_ok)
    acks, hsm_keys = True, {}
    for mem in members:
        b = nxt("trustee_ack")["body"]
        acks &= ed_ok(b, mem["public_key"], mem["role"]) and b["index"] == mem["index"] and b["verified_all_shares"] is True
        hsm_keys[mem["index"]] = b.get("hsm_attestation_key")
    rep.add("ceremony.acks", "Every trustee signed that all shares it received verified", acks)
    rep.facts["hsm_attestation_keys"] = hsm_keys
    jk = nxt("joint_key")["body"]
    K = 1
    for i in comms:
        K = K * comms[i][0] % Gq.p
    rep.add(
        "ceremony.joint_key",
        "Published joint key = product of trustees' constant commitments",
        ed_ok(jk, keys["officer"], "officer") and hx(jk["joint_public_key"]) == K and Gq.member(K) and K != 1,
    )
    rep.facts["joint_key"] = format(K, "x")

    def pub_share(i: int) -> int:
        acc = 1
        for Cs in comms.values():
            xj = 1
            for C in Cs:
                acc = acc * Gq.e(C, xj) % Gq.p
                xj = xj * i % Gq.q
        return acc

    lifecycle("READY")
    open_e = lifecycle("OPEN")

    # ------------------------------------------------------------ 5. ballots
    options = {c["id"]: [o["id"] for o in c["options"]] for c in man["constituencies"]}
    ctx = {"p": Gq.p, "q": Gq.q, "g": Gq.g, "K": K, "mhash": mh, "election_id": eid, "options": options, "k": k, "pubs": {}}
    workers = workers or os.cpu_count() or 1
    pool = _Pool(ctx, workers if count > 400 else 1)
    tmp = tempfile.TemporaryDirectory(prefix="chunaviq-verify-")
    db = sqlite3.connect(os.path.join(tmp.name, "index.db"))
    db.executescript(
        "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;"
        "CREATE TABLE alp(fp BLOB PRIMARY KEY) WITHOUT ROWID;"
        "CREATE TABLE rows(seq INTEGER PRIMARY KEY, cons TEXT, tc TEXT, ta TEXT, tb TEXT, fa TEXT, fb TEXT);"
        "CREATE INDEX rows_cons ON rows(cons, seq);"
        "CREATE TABLE valid(cons TEXT, tag TEXT, PRIMARY KEY(cons, tag)) WITHOUT ROWID;"
        "CREATE TABLE counted(cons TEXT, tag TEXT, PRIMARY KEY(cons, tag)) WITHOUT ROWID;"
    )
    try:
        _verify_body(d, rep, it, nxt, lifecycle, man, mh, eid, keys, Gq, K, k, roles, options, pool, db, open_e, pub_share, mix, workers if count > 400 else 1)
    finally:
        pool.close()
        db.close()
        tmp.cleanup()


def _verify_body(d, rep, it, nxt, lifecycle, man, mh, eid, keys, Gq, K, k, roles, options, pool, db, open_e, pub_share, mix, workers) -> None:
    st = {"bad": [], "bad_tc": 0, "dup": 0, "count": Counter()}
    w0, w1 = _ts(man["window"]["opens_at"]), _ts(man["window"]["closes_at"])
    h0, h1 = _hour(_hour_floor(w0)), _hour(_hour_floor(w1))

    def sink_ballots(r: dict) -> None:
        st["bad"].extend(r["bad"])
        st["bad_tc"] += r["bad_tc"]
        st["count"].update(r["count"])
        before = db.total_changes
        db.executemany("INSERT OR IGNORE INTO alp VALUES (?)", [(x,) for x in r["alphas"]])
        st["dup"] += len(r["alphas"]) - (db.total_changes - before)
        db.executemany("INSERT INTO rows(seq, cons, tc, ta, tb) VALUES(?,?,?,?,?)", r["rows"])

    in_win = True
    chunk: list = []
    while True:
        e = it.peek()
        if e is None:
            raise StructureError("record ends before CLOSED")
        if e["type"] != "ballot":
            break
        e = next(it)
        in_win &= h0 <= _hour(e["time_bucket"]) <= h1
        chunk.append((e["seq"], e["body"]))
        if len(chunk) >= _CHUNK:
            pool.submit(_ballot_chunk, chunk, sink_ballots)
            chunk = []
    if chunk:
        pool.submit(_ballot_chunk, chunk, sink_ballots)
    pool.drain()
    close_e = lifecycle("CLOSED")
    n_all = sum(st["count"].values())
    bad = sorted(st["bad"])
    rep.add(
        "ballots.valid",
        "Every ballot has valid ciphertexts, a tag proof and selection/limit proofs (exactly one selection)",
        not bad,
        f"{n_all} checked" + (f"; invalid (seq, reason): {bad[:5]}" if bad else ""),
    )
    rep.add("ballots.no_copies", "No ciphertext appears twice (ballot-copying defence)", st["dup"] == 0, f"{st['dup']} repeated")
    rep.add("ballots.tracking_codes", "Tracking codes equal the hash of each ballot", st["bad_tc"] == 0)
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
    rep.facts["ballots_cast"] = n_all

    # ------------------------------------------------------------ 6. registrations (summary, then sorted lists in chunks)
    rs = nxt("registration_summary")["body"]
    rok, notes = ed_ok(rs, keys["eligibility"], "eligibility"), []
    for c in man["constituencies"]:
        s = rs["constituencies"].get(c["id"])
        if s is None:
            rok = False
            notes.append(f"{c['id']}: missing")
            continue
        conds = {
            "eligible matches manifest": s["eligible"] == c["eligible_voters"],
            "registered <= eligible": s["registered"] <= s["eligible"],
            "valid tags = registered - voted in person": s["valid_tags"] == s["registered"] - s["voted_in_person"],
        }
        if not all(conds.values()):
            rok = False
            notes.append(f"{c['id']}: " + ", ".join(kk for kk, v in conds.items() if not v))
        rep.results.setdefault(c["id"], {}).update(
            eligible=s["eligible"], registered=s["registered"], voted_in_person=s["voted_in_person"], reregistrations=s["reregistrations"]
        )
    lists: dict[tuple[str, str], dict] = {}
    while it.peek() is not None and it.peek()["type"] == "registration_list":
        b = next(it)["body"]
        key = (b.get("constituency"), b.get("list"))
        st_ = lists.setdefault(key, {"n": 0, "next": 0, "last": None, "ok": True, "h": hashlib.sha256()})
        if not ed_ok(b, keys["eligibility"], "eligibility") or key[1] not in ("commitments", "valid_tags") or b["index"] != st_["next"]:
            st_["ok"] = False
        st_["next"] += 1
        for x in b["items"]:
            if not isinstance(x, str) or (st_["last"] is not None and not x > st_["last"]):
                st_["ok"] = False  # sorted and distinct
            st_["last"] = x
            st_["n"] += 1
            st_["h"].update(x.encode() + b"\n")
            if key[1] == "valid_tags":
                try:
                    v = hx(x)
                    if v == 1 or not Gq.member(v):
                        st_["ok"] = False
                except ValueError:
                    st_["ok"] = False
                db.execute("INSERT OR IGNORE INTO valid(cons, tag) VALUES(?,?)", (key[0], x))
    for c in man["constituencies"]:
        s = rs["constituencies"].get(c["id"], {})
        for kind, count, digest in (
            ("commitments", s.get("registered"), s.get("commitments_sha256")),
            ("valid_tags", s.get("valid_tags"), s.get("valid_tags_sha256")),
        ):
            st_ = lists.get((c["id"], kind), {"n": 0, "ok": True, "h": hashlib.sha256()})
            if not st_["ok"] or st_["n"] != count or st_["h"].hexdigest() != digest:
                rok = False
                notes.append(f"{c['id']}: {kind} list does not match the summary (count, order or digest)")
    rep.add(
        "registration.summary",
        "Registration summary and lists signed; registered <= eligible; one valid tag per registration not overridden in person; "
        "lists sorted, distinct, complete",
        rok,
        "; ".join(notes[:6]),
    )

    # ------------------------------------------------------------ 7. finalization
    fin = {"bad": [], "agg": {}, "n": 0}

    def sink_final(r: dict) -> None:
        fin["bad"].extend(r["bad"])
        for cons, acc in r["agg"].items():
            mine = fin["agg"].setdefault(cons, [[1, 1] for _ in acc])
            for j, (a, b) in enumerate(acc):
                mine[j][0] = mine[j][0] * a % Gq.p
                mine[j][1] = mine[j][1] * b % Gq.p
        db.executemany("UPDATE rows SET fa=?, fb=? WHERE seq=?", [(a, b, s) for s, a, b in r["flags"]])

    sigs_ok = True
    ballots = _stream_entries(d / "entries.jsonl", only="ballot")
    chunk = []
    while it.peek() is not None and it.peek()["type"] == "finalization":
        e = next(it)
        sigs_ok &= ed_ok(e["body"], keys["board"], "board")
        for item in e["body"]["items"]:
            be = next(ballots, None)
            if be is None:
                fin["bad"].append(item.get("seq"))
                continue
            b = be["body"]["ballot"]
            try:
                votes = [_ct(s["ciphertext"]) for s in b["selections"]]
            except (KeyError, TypeError, ValueError):
                votes = []
            chunk.append((be["seq"], b["constituency"], be["body"]["tracking_code"], votes, item))
            fin["n"] += 1
            if len(chunk) >= _CHUNK // 4:
                pool.submit(_final_chunk, chunk, sink_final)
                chunk = []
    if chunk:
        pool.submit(_final_chunk, chunk, sink_final)
    pool.drain()
    missing = next(ballots, None) is not None
    rep.add(
        "finalization.complete",
        "Every ballot has exactly one finalization item, in record order, signed by the ballot box",
        sigs_ok and not missing and fin["n"] == n_all,
        f"{fin['n']} items for {n_all} ballots",
    )
    rep.add(
        "finalization.proofs",
        "Each finalization proves: [flag 1 and masked vote = the ballot re-encrypted] or [flag 0 and masked vote = zero]",
        not fin["bad"],
        f"invalid at seq {sorted(x for x in fin['bad'] if x is not None)[:5]}" if fin["bad"] else "",
    )

    # ------------------------------------------------------------ 8. mixing, counted tags, tally
    pubs = {i: pub_share(i) for i in roles}
    pool.update(pubs=pubs)
    mix_ok, tag_ok, dec_ok, tally_ok, res_ok = True, True, True, True, True
    notes_mix, notes_tally = [], []
    min_m, bsz = mix["min_mixers"], mix["batch_size"]
    for c in man["constituencies"]:
        cid, opts = c["id"], options[c["id"]]
        n_c = db.execute("SELECT COUNT(*) FROM rows WHERE cons=?", (cid,)).fetchone()[0]
        results: dict[int, dict] = {}
        n_batches = (n_c + bsz - 1) // bsz
        counted_n, dup_or_invalid = 0, 0

        def take(r: dict, cid: str = cid) -> None:
            nonlocal counted_n, dup_or_invalid
            for t in r["tags"]:
                counted_n += 1
                before = db.total_changes
                db.execute("INSERT OR IGNORE INTO counted(cons, tag) VALUES(?,?)", (cid, t))
                if db.total_changes == before or db.execute("SELECT 1 FROM valid WHERE cons=? AND tag=?", (cid, t)).fetchone() is None:
                    dup_or_invalid += 1
            r["tags"] = []

        for batch in range(n_batches):
            part = db.execute("SELECT seq, ta, tb, fa, fb FROM rows WHERE cons=? ORDER BY seq LIMIT ? OFFSET ?", (cid, bsz, batch * bsz)).fetchall()
            if any(r[3] is None for r in part):
                mix_ok = False
                notes_mix.append(f"{cid}/{batch}: rows without a finalization flag")
                rows = []
            else:
                rows = [[(hx(r[1]), hx(r[2])), (hx(r[3]), hx(r[4]))] for r in part]
            shuffles, mixers = [], []
            while it.peek() is not None and it.peek()["type"] == "shuffle":
                sb = next(it)["body"]
                m = sb.get("mixer")
                if (
                    sb.get("constituency") != cid
                    or sb.get("batch") != batch
                    or m not in roles
                    or m in mixers
                    or not ed_ok(sb, roles[m]["public_key"], roles[m]["role"])
                ):
                    raise StructureError(f"shuffle entry out of place or wrongly signed ({cid}/{batch})")
                shuffles.append(sb)
                mixers.append(m)
            if len(mixers) < min_m:
                mix_ok = False
                notes_mix.append(f"{cid}/{batch}: {len(mixers)} mixers, {min_m} required")

            def shares(kind: str, cid: str = cid, batch: int = batch) -> list[dict]:
                got, idx = [], []
                while it.peek() is not None and it.peek()["type"] == kind:
                    b = next(it)["body"]
                    i = b.get("index")
                    if (
                        b.get("constituency") != cid
                        or b.get("batch") != batch
                        or i not in roles
                        or i in idx
                        or not ed_ok(b, roles[i]["public_key"], roles[i]["role"])
                    ):
                        raise StructureError(f"{kind} entry out of place or wrongly signed ({cid}/{batch})")
                    got.append(b)
                    idx.append(i)
                return got

            fl, tg = shares("flag_shares"), shares("tag_shares")
            if not rows or not shuffles:
                continue

            def sink_mix(r: dict, batch: int = batch, results: dict = results, take=take) -> None:
                take(r)
                results[batch] = r

            pool.submit(_mix_batch, (cid, batch, rows, shuffles, fl, tg), sink_mix)
        pool.drain()
        for batch in range(n_batches):
            r = results.get(batch)
            if r is None:
                mix_ok = False
                continue
            if r["problems"]:
                mix_ok = False
                notes_mix.extend(r["problems"][:3])
        if dup_or_invalid:
            tag_ok = False
            notes_tally.append(f"{cid}: {dup_or_invalid} counted tags are repeated or not registered and valid")
        n_final = counted_n
        results.clear()

        # aggregate, decryption, result
        ag = nxt("aggregate")["body"]
        if ag["constituency"] != cid or not ed_ok(ag, keys["officer"], "officer"):
            raise StructureError(f"aggregate for {cid} missing or unsigned")
        acc = fin["agg"].get(cid) or [[1, 1] for _ in opts]
        aggs = {oid: (acc[j][0], acc[j][1]) for j, oid in enumerate(opts)}
        posted = {x["option_id"]: _ct(x["ciphertext"]) for x in ag["aggregates"]}
        if posted != aggs or ag["ballot_count"] != n_c or ag["final_count"] != n_final:
            tally_ok = False
            notes_tally.append(f"{cid}: aggregate or counts do not match the record")
        got: dict[str, dict[int, int]] = {oid: {} for oid in opts}
        providers: list[int] = []
        while it.peek() is not None and it.peek()["type"] == "decryption_shares":
            b = next(it)["body"]
            i = b["index"]
            if b["constituency"] != cid or i not in roles or i in providers or not ed_ok(b, roles[i]["public_key"], roles[i]["role"]):
                raise StructureError(f"bad decryption share entry for {cid}")
            providers.append(i)
            for x in b["shares"]:
                oid = x["option_id"]
                M = hx(x["share"])
                pr = x["proof"]
                if oid not in aggs or not cp_ok(
                    Gq, aggs[oid][0], pubs[i], M, hx(pr["a"]), hx(pr["b"]), hx(pr["v"]), "decryption-share", [mh, "decrypt-aggregate", cid, oid]
                ):
                    dec_ok = False
                    notes_tally.append(f"{cid}/{oid}: invalid share from trustee {i}")
                got[oid][i] = M
        res = nxt("result")["body"]
        if len(providers) < k:
            dec_ok = False
            notes_tally.append(f"{cid}: only {len(providers)} shares, threshold {k}")
        if not ed_ok(res, keys["officer"], "officer") or res["constituency"] != cid or sorted(res["quorum"]) != sorted(providers):
            raise StructureError(f"result for {cid} unsigned or quorum mismatch")
        counts: dict[str, int | None] = {}
        for oid in opts:
            if any(i not in got[oid] for i in providers):
                dec_ok = False
                continue
            counts[oid] = _bsgs(Gq, _combine(Gq, aggs[oid][1], {i: got[oid][i] for i in providers}), n_final)
        posted_counts = {x["option_id"]: x["votes"] for x in res["counts"]}
        if any(v is None for v in counts.values()) or counts != posted_counts or sum(posted_counts.values()) != n_final:
            res_ok = False
            notes_tally.append(f"{cid}: decrypted {counts} != published {posted_counts} (or total != counted ballots {n_final})")
        dec = _decide(posted_counts)
        if {kk: res.get(kk) for kk in dec} != dec or res["ballot_count"] != n_c or res["final_count"] != n_final:
            res_ok = False
            notes_tally.append(f"{cid}: winner/tie flags or counts do not follow the published rule")
        rep.results.setdefault(cid, {}).update(
            name=c["name"],
            counts=posted_counts,
            ballots=n_final,
            ballots_cast=n_c,
            superseded_or_revoked=n_c - n_final,
            quorum=providers,
            options={o["id"]: o["name"] for o in c["options"]},
            **dec,
        )
    rep.add(
        "mixing.shuffles",
        f"Each batch was shuffled by at least {mix['min_mixers']} trustees with valid proofs, and every flag and tag decryption is proven",
        mix_ok,
        "; ".join(notes_mix[:6]),
    )
    rep.add(
        "mixing.counted_tags",
        "Counted ballots carry distinct tags, each a registered tag not overridden in person (at most one counted ballot per voter)",
        tag_ok,
        "; ".join(n for n in notes_tally if "tags" in n),
    )
    rep.add(
        "tally.aggregates",
        "Encrypted per-option totals equal the product of the finalized (masked) votes",
        tally_ok,
        "; ".join(n for n in notes_tally if "aggregate" in n),
    )
    rep.add("tally.decryption", f"At least {k} trustees decrypted each total with valid proofs", dec_ok)
    rep.add(
        "tally.results",
        "Published counts equal the verified decryption, sum to the counted ballots, and follow the FPTP/NOTA rule",
        res_ok,
        "; ".join(n for n in notes_tally if "decrypted" in n or "rule" in n),
    )
    lifecycle("TALLIED")
    lifecycle("PUBLISHED")
    if it.peek() is not None:
        raise StructureError("entries after PUBLISHED")
    rep.add("record.structure", "Record follows the required entry sequence", True)
    _check_hsm_logs(d, rep)


def _check_hsm_logs(d: Path, rep: Report) -> None:
    """Optional: trustee HSM audit logs published next to the record (<record>/../hsm)."""
    hdir = d.parent / "hsm"
    keys = rep.facts.get("hsm_attestation_keys") or {}
    if not hdir.is_dir() or not keys:
        return
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    ok, notes = True, []
    for idx, key in keys.items():
        f = hdir / f"trustee-{idx}.json"
        if not f.exists() or not key:
            continue
        data = json.loads(f.read_text())
        if data.get("attestation_key") != key:
            ok = False
            notes.append(f"trustee {idx}: log signed by a key other than the one in its ceremony acknowledgement")
            continue
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
        prev = "0" * 64
        for nn, rec in enumerate(data.get("log", [])):
            body = {kk: v for kk, v in rec.items() if kk not in ("hash", "signature")}
            if rec.get("n") != nn or rec.get("prev") != prev or hashlib.sha256(cjson(body)).hexdigest() != rec.get("hash"):
                ok = False
                notes.append(f"trustee {idx}: hash chain broken at {nn}")
                break
            try:
                pub.verify(bytes.fromhex(rec["signature"]), b"chunaviq/v1/signed-body\x00" + cjson({**body, "hash": rec["hash"]}))
            except (InvalidSignature, ValueError, KeyError):
                ok = False
                notes.append(f"trustee {idx}: bad signature at {nn}")
                break
            prev = rec["hash"]
    rep.add("custody.hsm_logs", "Published trustee HSM logs are intact, hash-chained and signed by the HSM keys declared in the ceremony", ok, "; ".join(notes))


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
