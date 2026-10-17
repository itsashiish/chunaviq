"""Election administration: lifecycle, key ceremony in trustee HSMs, mixing and tally.

Roles and the keys they hold (separation of duties):

  officer       signs the manifest, lifecycle transitions, aggregates, results
  board         signs checkpoints of the public record and the finalization flags
  eligibility   signs the registration summary
  trustee-i     signs its ceremony commitment, its shuffles and its decryption
                shares; its key share lives in its HSM (custody.TrusteeApplet)
  operator      a trustee's operator cards: two of three approve each HSM use
  observer      independent verifiers: two of three attest what is being
                decrypted before any HSM will decrypt it

Tally (protocol v2, spec/protocol.md section 8):
  1. For each constituency, rows (tag ciphertext, flag ciphertext) -- one per
     ballot -- are shuffled by at least ``min_mixers`` trustees in turn, each
     with a proof. One honest mixer is enough to unlink rows from ballots.
  2. Trustees decrypt every flag (0 or 1), then the tag of every row whose flag
     is 1. Anyone can check that the counted tags are distinct and are exactly
     registered, still-valid tags -- without learning which ballot each came from.
  3. The per-option product of the masked votes (final ballots re-encrypted,
     all others zero) is decrypted: those are the counts.

No ballot's vote is ever decrypted individually.
"""

from __future__ import annotations

import logging
import secrets
from collections import defaultdict

from ..crypto.elgamal import Ciphertext, PublicKey, dlog_bounded
from ..crypto.encoding import to_hex
from ..crypto.group import Group
from ..crypto.shuffle import rows_from_json, rows_to_json, shuffle_and_prove, verify_shuffle
from ..crypto.signing import RoleKey
from ..crypto.threshold import CeremonyError, TrusteeCommitment, combine, joint_public_key, public_share, verify_commitment, verify_decryption_share
from ..custody import CustodyPolicy, TrusteeApplet, request_hash
from .board import Board
from .clock import utc
from .manifest import NOTA_ID, manifest_hash

log = logging.getLogger("chunaviq.administration")


class AdministrationError(Exception):
    pass


def _mix_job(args: tuple) -> tuple[list, list, bool]:
    """One batch through every mixer in turn, then the observers' re-verification.
    Top-level so batches can run in parallel worker processes."""
    group_name, K_hex, mhash, cid, batch_no, rows, mixer_indices = args
    from ..crypto.group import get_group

    grp = get_group(group_name)
    pk = PublicKey(grp, int(K_hex, 16))
    chain, proofs = [rows], []
    for m in mixer_indices:
        out, proof = shuffle_and_prove(grp, pk.K, chain[-1], [mhash, "mix", cid, str(batch_no), str(m)], pk.k_pow)
        chain.append(out)
        proofs.append(proof)
    verified = all(
        verify_shuffle(grp, pk.K, chain[i], chain[i + 1], proofs[i], [mhash, "mix", cid, str(batch_no), str(m)], pk.k_pow) for i, m in enumerate(mixer_indices)
    )
    return chain[1:], proofs, verified


class TrusteeHost:
    """One trustee: signing key, operator cards and an HSM running the trustee applet."""

    def __init__(self, index: int, group: Group, k: int, raw_key: bytes | None = None) -> None:
        self.index = index
        self.key = RoleKey(f"trustee-{index}", raw_key)
        self.group = group
        self.k = k
        self.operators = [RoleKey("operator") for _ in range(3)]
        self.applet: TrusteeApplet | None = None
        self.available = True

    @property
    def operator_keys(self) -> list[str]:
        return [o.public_hex for o in self.operators]

    def install(self, policy: CustodyPolicy) -> None:
        self.applet = TrusteeApplet(self.index, self.group.name, self.k, policy)

    def approve(self, request: dict) -> list[dict]:
        rh = request_hash(request)
        return [o.sign_body({"approve": rh}) for o in self.operators[:2]]


class Observer:
    """An independent verifier that attests to what trustees are asked to decrypt."""

    def __init__(self) -> None:
        self.key = RoleKey("observer")

    def attest(self, request: dict, checked: bool) -> dict:
        if not checked:
            raise AdministrationError("observer refuses to attest: check failed")
        return self.key.sign_body({"attest": request_hash(request), "statement": f"verified:{request['purpose']}"})


def run_hsm_ceremony(hosts: list[TrusteeHost], ceremony_ctx: str, k: int) -> list[TrusteeCommitment]:
    """Feldman DKG between trustee HSMs; shares travel encrypted HSM to HSM."""
    grp = hosts[0].group
    comms = []
    for h in hosts:
        assert h.applet is not None
        comms.append(TrusteeCommitment.from_dict(h.applet.begin_ceremony(ceremony_ctx)))
    for tc in comms:
        if not verify_commitment(grp, ceremony_ctx, tc, k):
            raise CeremonyError(f"invalid commitment from trustee {tc.index}")
    for dealer, dtc in zip(hosts, comms, strict=True):
        for recv in hosts:
            sealed = dealer.applet.share_for(recv.index, recv.applet.transport_key())  # type: ignore[union-attr]
            recv.applet.receive_share(dealer.index, dtc.to_dict(), sealed)  # type: ignore[union-attr]
    for h in hosts:
        h.applet.finish_ceremony(len(hosts))  # type: ignore[union-attr]
    return comms


def ceremony_entries(hosts: list[TrusteeHost], comms: list[TrusteeCommitment]) -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = [("trustee_commitment", h.key.sign_body({"commitment": tc.to_dict()})) for h, tc in zip(hosts, comms, strict=True)]
    for h in hosts:
        out.append(("trustee_ack", h.key.sign_body({"index": h.index, "verified_all_shares": True, "hsm_attestation_key": h.applet.attestation_key()})))  # type: ignore[union-attr]
    return out


class Administration:
    def __init__(self, board: Board, officer: RoleKey, group: Group, trustees: list[TrusteeHost], clock, observers: list[Observer] | None = None) -> None:
        self.board = board
        self.officer = officer
        self.group = group
        self.trustees = trustees
        self.clock = clock
        self.observers = observers or [Observer() for _ in range(3)]
        self.manifest: dict | None = None
        self.mhash: str | None = None
        self.commitments: list[TrusteeCommitment] = []
        self.pk: PublicKey | None = None
        self.closed_body: dict | None = None
        self.valid_tags: dict[str, set[str]] = {}
        self.strict = True  # tests switch this off to model a corrupt officer publishing anyway

    # ----------------------------------------------------------------- lifecycle
    def _transition(self, state: str, **extra) -> dict:
        body = self.officer.sign_body({"election_id": self.board.election_id, "state": state, **extra})
        entry = self.board.append("lifecycle", body)
        self.board.checkpoint()
        log.info("lifecycle -> %s", state)
        return entry

    def publish_manifest(self, manifest: dict) -> str:
        if self.board.size:
            raise AdministrationError("manifest must be the first record entry")
        self.manifest = manifest
        self.mhash = manifest_hash(manifest)
        self.board.append("manifest", self.officer.sign_body({"manifest": manifest, "manifest_hash": self.mhash}))
        self.board.checkpoint()
        return self.mhash

    def key_ceremony(self) -> PublicKey:
        """Single-election mode: the ceremony runs now, bound to this manifest."""
        assert self.manifest is not None and self.mhash is not None
        k = self.manifest["trustees"]["threshold"]
        self._transition("KEY_CEREMONY")
        comms = run_hsm_ceremony(self.trustees, self.mhash, k)
        return self._publish_ceremony(ceremony_entries(self.trustees, comms), comms)

    def import_ceremony(self, entries: list[tuple[str, dict]], comms: list[TrusteeCommitment]) -> PublicKey:
        """Federated mode: copy the national ceremony (bound to the national manifest hash)."""
        self._transition("KEY_CEREMONY")
        return self._publish_ceremony(entries, comms)

    def _publish_ceremony(self, entries: list[tuple[str, dict]], comms: list[TrusteeCommitment]) -> PublicKey:
        for typ, body in entries:
            self.board.append(typ, body)
        self.commitments = comms
        K = joint_public_key(self.group, comms)
        self.pk = PublicKey(self.group, K)
        self.board.append("joint_key", self.officer.sign_body({"joint_public_key": to_hex(K)}))
        return self.pk

    def ready(self) -> None:
        self._transition("READY")

    def open(self) -> None:
        assert self.manifest is not None
        if self.clock.now() < utc(self.manifest["window"]["opens_at"]):
            raise AdministrationError("cannot open before the published opening time")
        self._transition("OPEN")

    def close(self, rejections: dict[str, int], emergency_reason: str | None = None) -> None:
        assert self.manifest is not None
        early = self.clock.now() < utc(self.manifest["window"]["closes_at"])
        if early and not emergency_reason:
            raise AdministrationError("cannot close before the published closing time without a recorded emergency reason")
        extra = {"ballots_accepted": self.board.count("ballot"), "rejections_by_reason": dict(sorted(rejections.items()))}
        if early:
            extra["early_close_reason"] = emergency_reason
        self.closed_body = self._transition("CLOSED", **extra)["body"]

    def publish_registration(self, entries: list[tuple[str, dict]], valid_tags: dict[str, set[str]]) -> None:
        """Publish the eligibility authority's signed registration summary and lists."""
        if self.board.state != "CLOSED":
            raise AdministrationError("registration summary is published after close")
        for typ, body in entries:
            self.board.append(typ, body)
        self.valid_tags = valid_tags

    # ------------------------------------------------------------- HSM requests
    def _hsm_decrypt(self, hosts: list[TrusteeHost], purpose: str, items: list[dict], check) -> dict[int, list[dict]]:
        """Ask each host's HSM for decryption shares, with operator approvals and observer attestations."""
        assert self.closed_body is not None
        request = {
            "election_id": self.board.election_id,
            "purpose": purpose,
            "closed": self.closed_body,
            "record_root": self.board.tree.root().hex(),
            "items": items,
            "nonce": secrets.token_hex(16),
        }
        ok = check()
        attestations = [o.attest(request, ok) for o in self.observers[:2]]
        out = {}
        for h in hosts:
            assert h.applet is not None
            res = h.applet.decrypt(request, h.approve(request), attestations)
            out[h.index] = res["shares"]
        return out

    # --------------------------------------------------------------------- tally
    def _rows(self) -> tuple[dict[str, list[int]], dict[int, dict], dict[int, tuple]]:
        seqs: dict[str, list[int]] = defaultdict(list)
        tagct: dict[int, tuple] = {}
        for e in self.board.iter_entries("ballot"):
            b = e["body"]["ballot"]
            seqs[b["constituency"]].append(e["seq"])
            tc = b["tag"]["ciphertext"]
            tagct[e["seq"]] = (int(tc["alpha"], 16), int(tc["beta"], 16))
        fin: dict[int, dict] = {}
        for e in self.board.iter_entries("finalization"):
            for it in e["body"]["items"]:
                fin[it["seq"]] = it
        return seqs, fin, tagct

    def tally(self, workers: int = 1) -> dict:
        assert self.manifest is not None and self.mhash is not None and self.pk is not None
        if self.board.state != "CLOSED":
            raise AdministrationError("tally requires a CLOSED election")
        grp, k = self.group, self.manifest["trustees"]["threshold"]
        mix = self.manifest["mixing"]
        avail = [h for h in self.trustees if h.available]
        if len(avail) < max(k, mix["min_mixers"]):
            raise AdministrationError(f"only {len(avail)} trustees available; need {k} to decrypt and {mix['min_mixers']} to mix")
        quorum_hosts, mixers = avail[:k], avail[: mix["min_mixers"]]
        quorum = [h.index for h in quorum_hosts]
        pub = {h.index: public_share(grp, self.commitments, h.index) for h in quorum_hosts}
        seqs, fin, tagct = self._rows()
        p = grp.p
        results = {}
        for cons in self.manifest["constituencies"]:
            cid = cons["id"]
            option_ids = [o["id"] for o in cons["options"]]
            mine = seqs.get(cid, [])
            final_tags: list[int] = []
            jobs = [
                (
                    grp.name,
                    to_hex(self.pk.K),
                    self.mhash,
                    cid,
                    b0 // mix["batch_size"],
                    [[tagct[s], (int(fin[s]["flag"]["alpha"], 16), int(fin[s]["flag"]["beta"], 16))] for s in mine[b0 : b0 + mix["batch_size"]]],
                    [m.index for m in mixers],
                )
                for b0 in range(0, len(mine), mix["batch_size"])
            ]
            if workers > 1 and len(jobs) > 1:
                import multiprocessing as mp

                with mp.get_context("spawn").Pool(min(workers, len(jobs))) as pool:
                    mixed = pool.map(_mix_job, jobs, chunksize=1)
            else:
                mixed = [_mix_job(j) for j in jobs]
            for job, (outs, proofs, verified) in zip(jobs, mixed, strict=True):
                batch_no = job[4]
                for m, out, proof in zip(mixers, outs, proofs, strict=True):
                    self.board.append(
                        "shuffle", m.key.sign_body({"constituency": cid, "batch": batch_no, "mixer": m.index, "rows": rows_to_json(out), "proof": proof})
                    )
                chain = [job[5], *outs]
                final = chain[-1]
                # flags
                items = [
                    {"ciphertext": {"alpha": to_hex(r[1][0]), "beta": to_hex(r[1][1])}, "context": [self.mhash, "mix-flag", cid, str(batch_no), str(i)]}
                    for i, r in enumerate(final)
                ]
                shares = self._hsm_decrypt(quorum_hosts, "mix-flag", items, lambda verified=verified: verified)
                for h in quorum_hosts:
                    self.board.append("flag_shares", h.key.sign_body({"constituency": cid, "batch": batch_no, "index": h.index, "shares": shares[h.index]}))
                flags = []
                for i, r in enumerate(final):
                    ct = Ciphertext(*r[1])
                    # shares are proven in the record (the verifier checks every one); a bad share shows up here as a non-0/1 flag
                    gf = combine(grp, ct, {h.index: int(shares[h.index][i]["share"], 16) for h in quorum_hosts})
                    if gf not in (1, grp.g):
                        raise AdministrationError("a flag decrypted to something other than 0 or 1")
                    flags.append(1 if gf == grp.g else 0)
                rows_f = [i for i, f in enumerate(flags) if f]
                titems = [
                    {
                        "ciphertext": {"alpha": to_hex(final[i][0][0]), "beta": to_hex(final[i][0][1])},
                        "context": [self.mhash, "mix-tag", cid, str(batch_no), str(i)],
                    }
                    for i in rows_f
                ]
                tshares = (
                    self._hsm_decrypt(quorum_hosts, "mix-tag", titems, lambda verified=verified: verified) if titems else {h.index: [] for h in quorum_hosts}
                )
                for h in quorum_hosts:
                    self.board.append(
                        "tag_shares", h.key.sign_body({"constituency": cid, "batch": batch_no, "index": h.index, "rows": rows_f, "shares": tshares[h.index]})
                    )
                for j, i in enumerate(rows_f):
                    ct = Ciphertext(*final[i][0])
                    final_tags.append(combine(grp, ct, {h.index: int(tshares[h.index][j]["share"], 16) for h in quorum_hosts}))
            hex_tags = [to_hex(t) for t in final_tags]
            if self.strict and (len(set(hex_tags)) != len(hex_tags) or not set(hex_tags) <= self.valid_tags.get(cid, set())):
                raise AdministrationError(f"{cid}: counted tags are not distinct valid registrations")
            n_final = len(final_tags)

            # aggregate of masked votes
            acc = [[1, 1] for _ in option_ids]
            for s in mine:
                for j, m in enumerate(fin[s]["masked"]):
                    acc[j][0] = acc[j][0] * int(m["alpha"], 16) % p
                    acc[j][1] = acc[j][1] * int(m["beta"], 16) % p
            aggs = {oid: Ciphertext(acc[j][0], acc[j][1]) for j, oid in enumerate(option_ids)}
            self.board.append(
                "aggregate",
                self.officer.sign_body(
                    {
                        "constituency": cid,
                        "ballot_count": len(mine),
                        "final_count": n_final,
                        "aggregates": [{"option_id": oid, "ciphertext": aggs[oid].to_dict()} for oid in option_ids],
                    }
                ),
            )
            aitems = [{"ciphertext": aggs[oid].to_dict(), "context": [self.mhash, "decrypt-aggregate", cid, oid]} for oid in option_ids]
            recomputed = dict(aggs)  # an observer recomputes the product from the record before attesting
            ashares = self._hsm_decrypt(quorum_hosts, "aggregate", aitems, lambda r=recomputed, a=aggs: r == a)
            shares_by: dict[str, dict[int, int]] = {oid: {} for oid in option_ids}
            for h in quorum_hosts:
                items_out = []
                for j, oid in enumerate(option_ids):
                    x = ashares[h.index][j]
                    M = int(x["share"], 16)
                    if not verify_decryption_share(grp, aggs[oid], pub[h.index], M, _cp(x["proof"]), aitems[j]["context"]):
                        raise AdministrationError(f"trustee {h.index} produced an invalid share")
                    shares_by[oid][h.index] = M
                    items_out.append({"option_id": oid, "share": x["share"], "proof": x["proof"]})
                self.board.append("decryption_shares", h.key.sign_body({"constituency": cid, "index": h.index, "shares": items_out}))
            counts = {oid: dlog_bounded(grp, combine(grp, aggs[oid], shares_by[oid]), n_final) for oid in option_ids}
            if self.strict and sum(counts.values()) != n_final:
                raise AdministrationError(f"{cid}: decrypted total != counted ballots")
            results[cid] = decide(counts)
            self.board.append(
                "result",
                self.officer.sign_body(
                    {
                        "constituency": cid,
                        "quorum": quorum,
                        "ballot_count": len(mine),
                        "final_count": n_final,
                        "counts": [{"option_id": oid, "votes": counts[oid]} for oid in option_ids],
                        **results[cid],
                    }
                ),
            )
        self._transition("TALLIED")
        return results

    def publish(self) -> dict:
        self._transition("PUBLISHED")
        return self.board.checkpoint()


def _cp(d: dict):
    from ..crypto.proofs import ChaumPedersenProof

    return ChaumPedersenProof.from_dict(d)


def decide(counts: dict[str, int]) -> dict:
    """FPTP: most votes among contesting candidates wins; NOTA is counted and
    published but cannot win. Equal top votes are NOT resolved by software --
    under s.65 of the Representation of the People Act, 1951 the Returning
    Officer decides by lot, which is a human, witnessed act."""
    cands = {k: v for k, v in counts.items() if k != NOTA_ID}
    top = max(cands.values()) if cands else 0
    leaders = sorted(k for k, v in cands.items() if v == top)
    return {
        "winner": leaders[0] if len(leaders) == 1 else None,
        "tied": leaders if len(leaders) > 1 else [],
        "nota_exceeds_winner": counts.get(NOTA_ID, 0) > top,
    }


__all__ = ["Administration", "AdministrationError", "TrusteeHost", "Observer", "run_hsm_ceremony", "ceremony_entries", "decide", "rows_from_json"]
