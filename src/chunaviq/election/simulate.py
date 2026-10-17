"""End-to-end synthetic election harness.

Runs every stage -- manifest, key ceremony, credential issuance, voting,
injected attacks, sealing, participation summary, threshold tally and
publication -- against synthetic voters, and writes:

  <out>/record/       the public election record (what observers verify)
  <out>/private/      eligibility and ballot-box databases (never published)
  <out>/oracle.json   simulation-only ground truth, for tests to compare
  <out>/summary.json  timings, counts and attack outcomes

Client-side encryption and server-side proof checking are spread over worker
processes; acceptance (uniqueness + board append) stays strictly sequential.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import multiprocessing as mp
import os
import random
import secrets
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .. import __version__
from ..crypto.blind import RSAPublic
from ..crypto.elgamal import Ciphertext, PublicKey
from ..crypto.encoding import canonical_json, to_hex
from ..crypto.group import get_group
from ..crypto.proofs import ChaumPedersenProof, disjunctive_prove
from ..crypto.signing import RoleKey
from .administration import Administration, TrusteeHost
from .ballot import BallotRejected, benaloh_audit, check_ballot, encrypt_ballot, selection_context
from .ballotbox import BallotBox
from .board import Board
from .client import VoterDevice
from .clock import FakeClock, iso
from .eligibility import EligibilityAuthority, EligibilityError
from .manifest import build_manifest
from .roll import make_constituencies, make_roll, split_eligible

log = logging.getLogger("chunaviq.simulate")


@dataclass
class SimConfig:
    voters: int = 10_000
    constituencies: int = 5
    candidates_per_constituency: int = 4
    turnout: float = 0.68
    trustees: int = 5
    threshold: int = 3
    unavailable_trustees: int = 1  # tally must still succeed with n - this >= k
    group: str = "CHUNAVIQ-2048-256-V1"
    rsa_bits: int = 3072
    seed: int = 2026
    benaloh_audit_rate: float = 0.02
    inject_attacks: bool = True
    workers: int = field(default_factory=lambda: os.cpu_count() or 1)
    election_id: str = "SYN-2026-GE-001"
    checkpoint_every: int = 1000
    durable: bool = True


# ------------------------------------------------------------------ worker side
_W: dict = {}


def _winit(group_name: str, K_hex: str, mhash: str, election_id: str, options: dict, issuer: dict) -> None:
    grp = get_group(group_name)
    _W.update(
        pk=PublicKey(grp, int(K_hex, 16)), mhash=mhash, election_id=election_id, options=options, issuer={c: RSAPublic.from_dict(d) for c, d in issuer.items()}
    )


def _wprepare(job: tuple) -> tuple[dict, bool | None]:
    cons, choice, token_hex, sig_hex, do_audit = job
    opts = _W["options"][cons]
    audited = None
    if do_audit:
        spoiled = encrypt_ballot(_W["pk"], _W["mhash"], _W["election_id"], cons, opts, choice, token_hex, sig_hex)
        audited = benaloh_audit(_W["pk"], spoiled, opts)
    pb = encrypt_ballot(_W["pk"], _W["mhash"], _W["election_id"], cons, opts, choice, token_hex, sig_hex)
    return pb.ballot, audited


def _wcheck(ballot: dict) -> str | None:
    try:
        check_ballot(ballot, pk=_W["pk"], mhash=_W["mhash"], election_id=_W["election_id"], options=_W["options"], issuer_keys=_W["issuer"])
        return None
    except BallotRejected as e:
        return e.code


# ------------------------------------------------------------------ attacks
def _overvote_ballot(pk: PublicKey, mhash: str, base: dict) -> dict:
    """Two selections set to 1, each with a *valid* 0/1 proof, and a forged limit
    proof. Must be rejected with BAD_LIMIT_PROOF."""
    b = json.loads(json.dumps(base))
    tok = b["credential"]["token"]
    for j in (0, 1):
        oid = b["selections"][j]["option_id"]
        r = pk.group.rand_scalar()
        ct = pk.encrypt(1, r)
        b["selections"][j]["ciphertext"] = ct.to_dict()
        b["selections"][j]["proof"] = disjunctive_prove(pk, ct, 1, r, selection_context(mhash, b["constituency"], oid, tok)).to_dict()
    lp = ChaumPedersenProof.from_dict(b["limit_proof"])
    b["limit_proof"] = ChaumPedersenProof(lp.a, lp.b, (lp.response + 1) % pk.group.q).to_dict()
    return b


def run(out: Path, cfg: SimConfig) -> dict:
    t0 = time.perf_counter()
    timings: dict[str, float] = {}
    out = Path(out)
    (out / "record").mkdir(parents=True, exist_ok=False)
    (out / "private").mkdir(parents=True, exist_ok=True)
    rng = random.Random(cfg.seed)
    grp = get_group(cfg.group)

    opens = dt.datetime(2026, 11, 2, 1, 30, tzinfo=dt.UTC)  # 07:00 IST
    closes = opens + dt.timedelta(hours=11)  # 18:00 IST
    clock = FakeClock(opens - dt.timedelta(days=2))

    officer, operator = RoleKey("officer"), RoleKey("board")
    hosts = [TrusteeHost(i + 1, grp, cfg.threshold) for i in range(cfg.trustees)]
    cons = make_constituencies(cfg.constituencies, cfg.candidates_per_constituency, split_eligible(cfg.voters, cfg.constituencies, cfg.seed), cfg.seed)
    roll = make_roll(cons)
    elig = EligibilityAuthority(out / "private" / "eligibility.db", cfg.election_id, [c.id for c in cons], clock, cfg.rsa_bits)
    elig.load_roll(roll)

    board = Board(out / "record", cfg.election_id, operator, clock, durable=cfg.durable)
    admin = Administration(board, officer, grp, hosts, clock)
    manifest = build_manifest(
        election_id=cfg.election_id,
        title="Synthetic Assembly General Election (research simulation)",
        group_name=cfg.group,
        constituencies=cons,
        opens_at=iso(opens),
        closes_at=iso(closes),
        threshold=cfg.threshold,
        trustee_keys=[h.key.public_hex for h in hosts],
        officer_key=officer.public_hex,
        board_key=operator.public_hex,
        eligibility_key=elig.key.public_hex,
        software_version=__version__,
    )
    mhash = admin.publish_manifest(manifest)

    s = time.perf_counter()
    pk = admin.key_ceremony()
    timings["key_ceremony_s"] = time.perf_counter() - s
    admin.publish_issuer_keys(elig.issuer_keys_entry())
    admin.ready()
    elig.set_accepting(True)

    clock.set(opens)
    admin.open()
    box = BallotBox(out / "private" / "ballotbox.db", board, manifest, mhash, pk, elig.issuer_keys(), clock)
    options = box.options

    # -------------------------------------------------------- credentials
    s = time.perf_counter()
    weights = {c.id: [rng.uniform(0.2, 1.0) for _ in c.candidates] for c in cons}
    devices, jobs, truth = [], [], defaultdict(Counter)
    for v in roll:
        if rng.random() >= cfg.turnout:
            continue
        dev = VoterDevice(v, cfg.election_id, mhash, pk, elig.issuer_keys()[v.constituency], options[v.constituency])
        dev.obtain_credential(elig)
        choice = rng.choices(options[v.constituency], weights[v.constituency])[0]
        truth[v.constituency][choice] += 1
        devices.append(dev)
        jobs.append((v.constituency, choice, dev.token.hex(), to_hex(dev.signature), rng.random() < cfg.benaloh_audit_rate))
    timings["credential_issuance_s"] = time.perf_counter() - s

    # -------------------------------------------------------- voting
    ctx = mp.get_context("spawn")
    init = (cfg.group, to_hex(pk.K), mhash, cfg.election_id, options, {c: k.to_dict() for c, k in elig.issuer_keys().items()})
    s = time.perf_counter()
    with ctx.Pool(cfg.workers, initializer=_winit, initargs=init) as pool:
        prepared = pool.map(_wprepare, jobs, chunksize=64)
        timings["client_encryption_s"] = time.perf_counter() - s
        s = time.perf_counter()
        verdicts = pool.map(_wcheck, [b for b, _ in prepared], chunksize=64)
        timings["server_verification_s"] = time.perf_counter() - s
    audits = Counter("passed" if a else "failed" for _, a in prepared if a is not None)

    s = time.perf_counter()
    voting_span = (closes - opens).total_seconds() - 600
    accepted = 0
    for i, ((ballot, _), code) in enumerate(zip(prepared, verdicts, strict=True)):
        clock.set(opens + dt.timedelta(seconds=voting_span * i / max(1, len(prepared))))
        if code is not None:
            box.rejections[code] += 1
            continue
        box.submit(ballot, prechecked=True)
        accepted += 1
        if accepted % cfg.checkpoint_every == 0:
            board.checkpoint()
    timings["acceptance_s"] = time.perf_counter() - s

    # -------------------------------------------------------- attacks
    attack_results: dict[str, str] = {}
    if cfg.inject_attacks and prepared:

        def attempt(name: str, fn) -> None:
            try:
                fn()
                attack_results[name] = "ACCEPTED (FAILURE)"
            except (BallotRejected, EligibilityError) as e:
                attack_results[name] = f"rejected: {e.code}"

        first = prepared[0][0]
        dev0 = devices[0]
        attempt("replay_identical_ballot", lambda: box.submit(first))
        attempt("reuse_credential_new_ballot", lambda: box.submit(dev0.prepare(options[dev0.voter.constituency][0]).ballot))
        forged = json.loads(json.dumps(first))
        forged["credential"] = {"token": secrets.token_hex(32), "signature": to_hex(secrets.randbits(cfg.rsa_bits - 8) | 1)}
        attempt("forged_credential", lambda: box.submit(forged))
        other = next((c.id for c in cons if c.id != dev0.voter.constituency), None)
        if other:
            wrong = json.loads(json.dumps(first))
            wrong["constituency"] = other
            attempt("cross_constituency_ballot", lambda: box.submit(wrong))
        attempt("overvote_two_selections", lambda: box.submit(_overvote_ballot(pk, mhash, first)))
        tampered = json.loads(json.dumps(first))
        ct = Ciphertext.from_dict(tampered["selections"][0]["ciphertext"])
        tampered["selections"][0]["ciphertext"] = Ciphertext(ct.alpha, ct.beta * grp.g % grp.p).to_dict()
        attempt("tampered_ciphertext", lambda: box.submit(tampered))
        attempt("ineligible_person_requests_credential", lambda: elig.issue_credential("syn-v-9999999", b"x" * 16, "1"))
        attempt("second_credential_same_voter", lambda: devices[1].obtain_credential(elig))

    # -------------------------------------------------------- seal + tally
    clock.set(closes)
    elig.set_accepting(False)
    late = json.loads(json.dumps(first)) if prepared else None
    if late is not None and cfg.inject_attacks:
        try:
            box.submit(late)
            attack_results["ballot_after_close"] = "ACCEPTED (FAILURE)"
        except BallotRejected as e:
            attack_results["ballot_after_close"] = f"rejected: {e.code}"
    admin.close(dict(box.rejections))
    admin.publish_participation(elig.participation_summary())
    for h in hosts[: cfg.unavailable_trustees]:
        h.available = False
    s = time.perf_counter()
    results = admin.tally()
    timings["tally_s"] = time.perf_counter() - s
    admin.publish()
    recon = box.reconcile()

    oracle = {c: {oid: truth[c].get(oid, 0) for oid in options[c]} for c in options}
    (out / "oracle.json").write_text(json.dumps(oracle, indent=2, sort_keys=True))
    timings["total_s"] = time.perf_counter() - t0
    summary = {
        "config": asdict(cfg),
        "eligible_voters": len(roll),
        "credentials_issued": len(devices),
        "ballots_accepted": accepted,
        "benaloh_audits": dict(audits),
        "attacks": attack_results,
        "rejections_by_reason": dict(box.rejections),
        "reconciliation": recon,
        "results": results,
        "record_entries": len(board.entries),
        "final_checkpoint": board.checkpoints[-1]["root"],
        "manifest_hash": mhash,
        "timings": {k: round(v, 2) for k, v in timings.items()},
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def dump_canonical(path: Path, obj: dict) -> None:
    path.write_bytes(canonical_json(obj))
