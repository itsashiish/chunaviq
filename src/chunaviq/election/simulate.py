"""End-to-end synthetic election harness (protocol v2).

Runs every stage -- manifest, key ceremony in trustee HSMs, identity
verification (Aadhaar OTP, Aadhaar face, PAN + OTP + face), tag registration,
voting, revoting, coercion followed by a private revote, re-registration,
injected attacks, close, polling-day overrides, finalization, mixing, tally
and publication -- against synthetic voters, and writes:

  <out>/record/       the public election record (what observers verify)
  <out>/private/      eligibility and ballot-box databases (never published)
  <out>/hsm/          each trustee HSM's exported audit log (published after the election)
  <out>/oracle.json   simulation-only ground truth, for tests to compare
  <out>/summary.json  timings, counts, attack outcomes and coercion checks

Voter-device encryption and server-side proof checking run in worker
processes; acceptance (uniqueness + board append) is strictly sequential.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import multiprocessing as mp
import os
import random
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .. import __version__
from ..crypto import sigma
from ..crypto.elgamal import Ciphertext, PublicKey
from ..crypto.encoding import canonical_json, from_hex, to_hex
from ..crypto.group import get_group
from ..crypto.proofs import ChaumPedersenProof, disjunctive_prove
from ..crypto.signing import RoleKey
from ..custody import CustodyPolicy, TrusteeApplet
from .administration import Administration, Observer, TrusteeHost
from .ballot import (
    BallotRejected,
    PreparedBallot,
    benaloh_audit,
    body_digest,
    check_ballot,
    check_link,
    encrypt_ballot,
    fast_pows,
    make_link,
    selection_context,
    tag_context,
)
from .ballotbox import BallotBox
from .board import Board
from .client import VoterDevice
from .clock import FakeClock, iso
from .eligibility import EligibilityAuthority, EligibilityError
from .identity import IdentityHub, live_capture
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
    min_mixers: int = 3
    mix_batch: int = 2048
    unavailable_trustees: int = 1  # tally must still succeed with n - this >= max(k, mixers)
    group: str = "CHUNAVIQ-2048-256-V1"
    seed: int = 2026
    benaloh_audit_rate: float = 0.02
    revote_rate: float = 0.05  # change of mind: a second ballot later
    coerced_rate: float = 0.02  # vote watched by a coercer, then a private revote
    reregister_rate: float = 0.01  # new phone / phone taken: re-register, vote again
    in_person_rate: float = 0.01  # voted online, then at the polling station on polling day
    inject_attacks: bool = True
    workers: int = field(default_factory=lambda: os.cpu_count() or 1)
    election_id: str = "SYN-2026-GE-001"
    checkpoint_every: int = 1000
    durable: bool = True
    batch_size: int = 256  # group commit: ballots per transaction + fsync
    # --- set by the federation runner when this election is one constituency shard
    first_constituency: int = 1
    first_voter: int = 1
    constituency_prefix: str = "SYN-AC"
    federation: dict | None = None
    officer_raw_key: bytes | None = None
    trustee_raw_keys: list[bytes] | None = None
    national: dict | None = None  # national ceremony entries + sealed HSM states (simulation only)


# ------------------------------------------------------------------ worker side
_W: dict = {}


def _winit(group_name: str, K_hex: str, mhash: str, election_id: str, options: dict) -> None:
    grp = get_group(group_name)
    _W.update(pk=PublicKey(grp, int(K_hex, 16)), mhash=mhash, election_id=election_id, options=options)


def _wprepare(job: tuple) -> tuple[dict, bool | None]:
    """Voter device: encrypt, optionally Benaloh-audit a spoiled ballot, build the submission."""
    cons, choice, t_hex, do_audit = job
    pk, opts = _W["pk"], _W["options"][cons]
    t = int(t_hex, 16)
    audited = None
    if do_audit:
        spoiled = encrypt_ballot(pk, _W["mhash"], _W["election_id"], cons, opts, choice, t)
        audited = benaloh_audit(pk, spoiled, opts)
    pb = encrypt_ballot(pk, _W["mhash"], _W["election_id"], cons, opts, choice, t)
    T = pk.group.g_pow(t)
    return {"ballot": pb.ballot, "tag": to_hex(T), "link": make_link(pk, _W["mhash"], pb, T)}, audited


def _wcheck(sub: dict) -> str:
    """Ballot box worker: all stateless checks. Returns the tag or 'REJECT:<code>'."""
    try:
        check_ballot(sub["ballot"], pk=_W["pk"], mhash=_W["mhash"], election_id=_W["election_id"], options=_W["options"])
        return to_hex(check_link(_W["pk"], _W["mhash"], sub["ballot"], sub["tag"], sub["link"]))
    except BallotRejected as e:
        return "REJECT:" + e.code


# ------------------------------------------------------------------ attacks
def _overvote(pk: PublicKey, mhash: str, sub: dict) -> dict:
    """Two selections set to 1, each with a *valid* 0/1 proof; limit proof forged."""
    s = json.loads(json.dumps(sub))
    b = s["ballot"]
    ta = b["tag"]["ciphertext"]["alpha"]
    for j in (0, 1):
        oid = b["selections"][j]["option_id"]
        r = pk.group.rand_scalar()
        ct = pk.encrypt(1, r)
        b["selections"][j]["ciphertext"] = ct.to_dict()
        b["selections"][j]["proof"] = disjunctive_prove(pk, ct, 1, r, selection_context(mhash, b["constituency"], oid, ta)).to_dict()
    lp = ChaumPedersenProof.from_dict(b["limit_proof"])
    b["limit_proof"] = ChaumPedersenProof(lp.a, lp.b, (lp.response + 1) % pk.group.q).to_dict()
    return s


def _forged_by_insider(pk: PublicKey, mhash: str, eid: str, cons: str, opts: list[str], T_hex: str) -> dict:
    """The ballot box and the eligibility authority both know T but not t. Try to cast
    a 'revote' for that voter: a well-formed ballot that encrypts T, with valid
    selection and limit proofs -- only the tag proof has to be faked."""
    from ..crypto.elgamal import add
    from ..crypto.proofs import cp_prove
    from .ballot import limit_context

    grp = pk.group
    T = from_hex(T_hex)
    r = grp.rand_scalar()
    tct = Ciphertext(grp.g_pow(r), T * pk.k_pow(r) % grp.p)
    ta = to_hex(tct.alpha)
    sels, nonces, cts = [], [], []
    for j, oid in enumerate(opts):
        m, rr = (1 if j == 0 else 0), grp.rand_scalar()
        ct = pk.encrypt(m, rr)
        sels.append(
            {"option_id": oid, "ciphertext": ct.to_dict(), "proof": disjunctive_prove(pk, ct, m, rr, selection_context(mhash, cons, oid, ta)).to_dict()}
        )
        nonces.append(rr)
        cts.append(ct)
    agg = add(grp, cts)
    lp = cp_prove(
        grp, sum(nonces) % grp.q, pk.K, agg.alpha, grp.div(agg.beta, grp.g), "contest-limit", limit_context(mhash, cons, ta), h_pow=pk.k_pow
    ).to_dict()
    st = sigma.tag_statement(grp, pk.K, tct.alpha, tct.beta)
    fake_tag_proof = sigma.prove(grp, st, [r, grp.rand_scalar()], "ballot-tag", tag_context(mhash, cons, body_digest(sels, lp)), fast_pows(pk))  # wrong t
    b = {"election_id": eid, "constituency": cons, "tag": {"ciphertext": tct.to_dict(), "proof": fake_tag_proof}, "selections": sels, "limit_proof": lp}
    from .ballot import link_context, tracking_code

    link = sigma.prove(grp, sigma.link_statement(grp, pk.K, tct.alpha, tct.beta, T), [r], "tag-link", link_context(mhash, tracking_code(b)), fast_pows(pk))
    return {"ballot": b, "tag": T_hex, "link": link}


def run(out: Path, cfg: SimConfig) -> dict:
    t0 = time.perf_counter()
    timings: dict[str, float] = {}
    out = Path(out)
    (out / "record").mkdir(parents=True, exist_ok=False)
    (out / "private").mkdir(parents=True, exist_ok=True)
    (out / "hsm").mkdir(parents=True, exist_ok=True)
    rng = random.Random(cfg.seed)
    grp = get_group(cfg.group)

    opens = dt.datetime(2026, 11, 2, 1, 30, tzinfo=dt.UTC)  # 07:00 IST, day 1
    closes = opens + dt.timedelta(days=6, hours=11)  # 18:00 IST, day 7 (a seven-day online window)
    clock = FakeClock(opens - dt.timedelta(days=2))

    officer = RoleKey("officer", cfg.officer_raw_key)
    operator = RoleKey("board")
    raw = cfg.trustee_raw_keys or [None] * cfg.trustees
    hosts = [TrusteeHost(i + 1, grp, cfg.threshold, raw_key=raw[i]) for i in range(cfg.trustees)]
    observers = [Observer() for _ in range(3)]
    cons = make_constituencies(
        cfg.constituencies,
        cfg.candidates_per_constituency,
        split_eligible(cfg.voters, cfg.constituencies, cfg.seed),
        cfg.seed,
        start=cfg.first_constituency,
        prefix=cfg.constituency_prefix,
    )
    roll = make_roll(cons, start=cfg.first_voter, seed=cfg.seed)
    hub = IdentityHub.synthetic(roll)
    elig = EligibilityAuthority(out / "private" / "eligibility.db", cfg.election_id, [c.id for c in cons], clock, grp, hub)
    elig.load_roll(roll)

    board = Board(out / "record", cfg.election_id, operator, clock, durable=cfg.durable)
    admin = Administration(board, officer, grp, hosts, clock, observers)
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
        federation=cfg.federation,
        min_mixers=cfg.min_mixers,
        mix_batch=cfg.mix_batch,
    )
    mhash = admin.publish_manifest(manifest)

    s = time.perf_counter()
    if cfg.national is None:
        budget = 4 * cfg.voters + 64 * cfg.constituencies
        for h in hosts:
            h.install(CustodyPolicy([cfg.election_id], [officer.public_hex], h.operator_keys, 2, [o.key.public_hex for o in observers], 2, budget))
        pk = admin.key_ceremony()
    else:  # federated shard: the national ceremony already happened in the trustees' HSMs
        nat = cfg.national
        from ..crypto.threshold import TrusteeCommitment

        for h, blob in zip(hosts, nat["sealed"], strict=True):
            h.applet = TrusteeApplet.unseal(bytes.fromhex(blob), bytes.fromhex(nat["kek"][h.index - 1]))
            h.operators = [RoleKey("operator", bytes.fromhex(x)) for x in nat["operators"][h.index - 1]]
        admin.observers = observers = [Observer() for _ in nat["observers"]]
        for o, x in zip(observers, nat["observers"], strict=True):
            o.key = RoleKey("observer", bytes.fromhex(x))
        pk = admin.import_ceremony([(t, b) for t, b in nat["entries"]], [TrusteeCommitment.from_dict(c) for c in nat["commitments"]])
    timings["key_ceremony_s"] = time.perf_counter() - s
    admin.ready()
    elig.set_accepting(True)

    clock.set(opens)
    admin.open()
    box = BallotBox(out / "private" / "ballotbox.db", board, manifest, mhash, pk, clock, elig.known_tag, max_per_tag=30)
    options = box.options

    # -------------------------------------------------------- identity + registration
    s = time.perf_counter()
    weights = {c.id: [rng.uniform(0.2, 1.0) for _ in c.candidates] for c in cons}
    methods = Counter()
    plans: list[tuple[VoterDevice, list[tuple[str, str, str]]]] = []  # device, [(choice, t_hex, kind)]
    truth: dict[str, Counter] = defaultdict(Counter)
    coerced, in_person_voters = [], []
    for v in roll:
        if rng.random() >= cfg.turnout:
            continue
        dev = VoterDevice(v, cfg.election_id, mhash, pk, options[v.constituency])
        x = rng.random()
        method = "pan" if (x < 0.2 and v.pan_ref) else ("aadhaar-face" if x < 0.4 else "aadhaar-otp")
        dev.register(elig, method)
        methods[method] += 1
        opts = options[v.constituency]
        own = rng.choices(opts, weights[v.constituency])[0]
        ballots: list[tuple[str, str, str]] = []
        r = rng.random()
        if r < cfg.coerced_rate:
            ballots.append((rng.choice(opts), to_hex(dev.t), "coerced"))  # cast in front of a coercer
            ballots.append((own, to_hex(dev.t), "private-revote"))
            coerced.append(dev)
        elif r < cfg.coerced_rate + cfg.revote_rate:
            ballots.append((rng.choice(opts), to_hex(dev.t), "first"))
            ballots.append((own, to_hex(dev.t), "changed-mind"))
        elif r < cfg.coerced_rate + cfg.revote_rate + cfg.reregister_rate:
            ballots.append((rng.choice(opts), to_hex(dev.t), "old-device"))
            dev.register(elig, "aadhaar-otp")  # new phone: old tag revoked
            ballots.append((own, to_hex(dev.t), "new-device"))
        else:
            ballots.append((own, to_hex(dev.t), "single"))
        plans.append((dev, ballots))
        if rng.random() < cfg.in_person_rate:
            in_person_voters.append(dev)
        else:
            truth[v.constituency][own] += 1
    timings["identity_and_registration_s"] = time.perf_counter() - s

    # -------------------------------------------------------- voting (round 1 = first ballots, round 2 = revotes)
    jobs, owners = [], []
    for dev, bl in plans:
        for rnd, (choice, t_hex, kind) in enumerate(bl):
            jobs.append((dev.voter.constituency, choice, t_hex, rng.random() < cfg.benaloh_audit_rate))
            owners.append((dev, rnd, kind))
    init = (cfg.group, to_hex(pk.K), mhash, cfg.election_id, options)
    s = time.perf_counter()
    if cfg.workers <= 1:
        _winit(*init)
        prepared = [_wprepare(j) for j in jobs]
        timings["client_encryption_s"] = time.perf_counter() - s
        s = time.perf_counter()
        verdicts = [_wcheck(sub) for sub, _ in prepared]
    else:
        with mp.get_context("spawn").Pool(cfg.workers, initializer=_winit, initargs=init) as pool:
            prepared = pool.map(_wprepare, jobs, chunksize=32)
            timings["client_encryption_s"] = time.perf_counter() - s
            s = time.perf_counter()
            verdicts = pool.map(_wcheck, [sub for sub, _ in prepared], chunksize=32)
    timings["server_verification_s"] = time.perf_counter() - s
    audits = Counter("passed" if a else "failed" for _, a in prepared if a is not None)

    s = time.perf_counter()
    rounds = [[i for i, (_, rnd, _) in enumerate(owners) if rnd == r] for r in (0, 1)]
    span = (closes - opens).total_seconds() - 3600
    accepted = 0
    since_cp = 0
    for r_i, idxs in enumerate(rounds):
        for start in range(0, len(idxs), cfg.batch_size):
            part = idxs[start : start + cfg.batch_size]
            frac = (r_i + start / max(1, len(idxs))) / 2
            clock.set(opens + dt.timedelta(seconds=span * frac))
            subs, tags = [], []
            for i in part:
                if verdicts[i].startswith("REJECT:"):
                    box.rejections[verdicts[i][7:]] += 1
                    continue
                subs.append(prepared[i][0])
                tags.append(verdicts[i])
            res = box.submit_batch(subs, prechecked_tags=tags)
            k = 0
            for i in part:
                if verdicts[i].startswith("REJECT:"):
                    continue
                if isinstance(res[k], dict):
                    owners[i][0].cast.append(res[k]["tracking_code"])
                    accepted += 1
                    since_cp += 1
                k += 1
            if since_cp >= cfg.checkpoint_every:
                board.checkpoint()
                since_cp = 0
    timings["acceptance_s"] = time.perf_counter() - s

    # -------------------------------------------------------- attacks
    attack_results: dict[str, str] = {}
    if cfg.inject_attacks and plans:

        def attempt(name: str, fn) -> None:
            try:
                fn()
                attack_results[name] = "ACCEPTED (FAILURE)"
            except (BallotRejected, EligibilityError) as e:
                attack_results[name] = f"rejected: {e.code}"

        first = prepared[0][0]
        dev0 = plans[0][0]
        c0 = dev0.voter.constituency
        before = board.count("ballot")
        replay = box.submit(first)
        attack_results["replay_identical_ballot"] = (
            "idempotent: original receipt returned, not counted again"
            if replay.get("duplicate_submission") and board.count("ballot") == before
            else "ACCEPTED (FAILURE)"
        )
        _winit(*init)
        stranger, _ = _wprepare((c0, options[c0][0], to_hex(grp.rand_scalar()), False))
        attempt("unregistered_tag", lambda: box.submit(stranger))
        mine = next((sub for sub, _ in prepared if sub["tag"] != first["tag"] and sub["ballot"]["constituency"] == c0), stranger)
        copy_votes = json.loads(json.dumps(mine))
        copy_votes["ballot"]["selections"] = first["ballot"]["selections"]
        copy_votes["ballot"]["limit_proof"] = first["ballot"]["limit_proof"]
        attempt("copy_votes_into_another_voters_ballot", lambda: box.submit(copy_votes))
        resubmit = json.loads(json.dumps(first))
        resubmit["tag"], resubmit["link"] = mine["tag"], mine["link"]
        attempt("resubmit_someone_elses_ballot_under_own_tag", lambda: box.submit(resubmit))
        attempt("insider_forges_revote_for_known_tag", lambda: box.submit(_forged_by_insider(pk, mhash, cfg.election_id, c0, options[c0], first["tag"])))
        other = next((c.id for c in cons if c.id != c0), None)
        if other:
            wrong = json.loads(json.dumps(first))
            wrong["ballot"]["constituency"] = other
            attempt("cross_constituency_ballot", lambda: box.submit(wrong))
        attempt("overvote_two_selections", lambda: box.submit(_overvote(pk, mhash, first)))
        tampered = json.loads(json.dumps(first))
        ct = Ciphertext.from_dict(tampered["ballot"]["selections"][0]["ciphertext"])
        tampered["ballot"]["selections"][0]["ciphertext"] = Ciphertext(ct.alpha, ct.beta * grp.g % grp.p).to_dict()
        attempt("tampered_ciphertext", lambda: box.submit(tampered))
        attempt("ineligible_person_aadhaar", lambda: elig.aadhaar_otp_start("syn-uid-9999999"))
        v1 = plans[min(1, len(plans) - 1)][0].voter
        attempt("impostor_face_aadhaar", lambda: elig.aadhaar_face(v1.aadhaar_ref, live_capture(v1.face, genuine=False)))
        pan_v = next((d.voter for d, _ in plans if d.voter.pan_ref), None)
        if pan_v:
            attempt("pan_with_wrong_date_of_birth", lambda: elig.pan_start(pan_v.pan_ref, pan_v.name, "1901-01-01"))

            def pan_stolen_no_phone() -> None:
                txn = elig.pan_start(pan_v.pan_ref, pan_v.name, pan_v.dob)  # attacker knows PAN + birth date ...
                elig.pan_finish(pan_v.pan_ref, txn, "000000", live_capture(pan_v.face, genuine=False))  # ... but not the phone or the face

            attempt("pan_and_dob_known_but_no_phone_or_face", pan_stolen_no_phone)

        def same_tag_twice() -> None:
            d = plans[0][0]
            session = d.authenticate(elig, "aadhaar-otp")
            from ..crypto.proofs import schnorr_prove
            from .eligibility import register_context

            proof = schnorr_prove(grp, d.t, d.T, register_context(cfg.election_id, d.voter.constituency, session))
            elig.register(session, to_hex(d.T), proof.to_dict())

        attempt("register_an_already_used_tag", same_tag_twice)

    # -------------------------------------------------------- seal, polling-day override, finalize, tally
    clock.set(closes)
    elig.set_accepting(False)
    if cfg.inject_attacks and plans:
        late = plans[0][0]
        try:
            box.submit(late.submission(late.prepare(options[late.voter.constituency][0])))
            attack_results["ballot_after_close"] = "ACCEPTED (FAILURE)"
        except BallotRejected as e:
            attack_results["ballot_after_close"] = f"rejected: {e.code}"
    admin.close(dict(box.rejections))
    clock.advance(hours=14)  # polling day at the booth: online voters who also vote in person
    revoked_in_person = sum(elig.mark_voted_in_person(d.voter.voter_id) for d in in_person_voters)
    clock.advance(hours=12)
    admin.publish_registration(elig.registration_entries(), {c: set(elig.valid_tags(c)) for c in elig.constituencies})
    s = time.perf_counter()
    fstats = box.finalize(admin.valid_tags, workers=cfg.workers, group_name=cfg.group)
    timings["finalization_s"] = time.perf_counter() - s

    # voters check privately that their latest ballot is the one that counts
    sample = [d for d, _ in plans if d not in in_person_voters][:25]
    dv_ok = 0
    for d in sample:
        proof = box.dv_proof(d.cast[-1]) if d.cast else None
        dv_ok += bool(proof and d.check_counted(proof["flag"], proof["proof"]))
    coercion = {
        "coerced_voters": len(coerced),
        "coerced_ballot_has_counted_proof": sum(box.dv_proof(d.cast[0]) is not None for d in coerced if d.cast),
        "voters_checked_latest_counts": f"{dv_ok}/{len(sample)}",
    }
    if coerced:
        d = coerced[0]
        fin = next(it for e in board.iter_entries("finalization") for it in e["body"]["items"] if it["tracking_code"] == d.cast[0])
        coercion["voter_can_fake_proof_for_coercer"] = d.check_counted(fin["flag"], d.fake_counted_proof(fin["flag"], d.cast[0]), tracking=d.cast[0])

    for h in hosts[: cfg.unavailable_trustees]:
        h.available = False
    s = time.perf_counter()
    results = admin.tally(workers=cfg.workers)
    timings["mix_and_tally_s"] = time.perf_counter() - s
    admin.publish()
    recon = box.reconcile()
    for h in hosts:
        assert h.applet is not None
        (out / "hsm" / f"trustee-{h.index}.json").write_text(
            json.dumps({"attestation_key": h.applet.attestation_key(), "log": h.applet.audit_log()}, indent=1, sort_keys=True)
        )

    oracle = {c: {oid: truth[c].get(oid, 0) for oid in options[c]} for c in options}
    (out / "oracle.json").write_text(json.dumps(oracle, indent=2, sort_keys=True))
    timings["total_s"] = time.perf_counter() - t0
    summary = {
        "config": {k: v for k, v in asdict(cfg).items() if k not in ("trustee_raw_keys", "officer_raw_key", "national")},  # never persist keys
        "eligible_voters": len(roll),
        "registered": len(plans),
        "identity_methods": dict(methods),
        "ballots_accepted": accepted,
        "finalization": fstats,
        "voted_in_person_after_online": revoked_in_person,
        "coercion": coercion,
        "benaloh_audits": dict(audits),
        "attacks": attack_results,
        "rejections_by_reason": dict(box.rejections),
        "reconciliation": recon,
        "results": results,
        "record_entries": board.size,
        "final_checkpoint": board.checkpoints[-1]["root"],
        "manifest_hash": mhash,
        "timings": {k: round(v, 2) for k, v in timings.items()},
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def dump_canonical(path: Path, obj: dict) -> None:
    path.write_bytes(canonical_json(obj))


__all__ = ["SimConfig", "run", "PreparedBallot"]
