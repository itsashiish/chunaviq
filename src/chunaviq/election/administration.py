"""Election administration: lifecycle, key ceremony, sealing and tally.

Roles and the keys they hold (separation of duties):

  officer       signs the manifest, lifecycle transitions, aggregates, results
  board         signs checkpoints of the public record
  eligibility   signs issuer keys and the participation summary
  trustee-i     signs its ceremony commitment and decryption shares; holds one
                share of the decryption key (k-of-n needed to decrypt anything)

The officer cannot decrypt ballots and cannot alter the record without
breaking signed checkpoints; trustees decrypt only per-option aggregates,
never individual ballots.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from ..crypto.elgamal import Ciphertext, PublicKey, dlog_bounded
from ..crypto.encoding import to_hex
from ..crypto.group import Group
from ..crypto.signing import RoleKey
from ..crypto.threshold import (
    CeremonyError,
    Trustee,
    TrusteeCommitment,
    combine,
    joint_public_key,
    public_share,
    verify_commitment,
    verify_decryption_share,
)
from .board import Board
from .clock import utc
from .manifest import NOTA_ID, manifest_hash

log = logging.getLogger("chunaviq.administration")


class AdministrationError(Exception):
    pass


class TrusteeHost:
    """One trustee's machine: its signing key and its key-share holder."""

    def __init__(self, index: int, group: Group, k: int, raw_key: bytes | None = None) -> None:
        self.index = index
        self.key = RoleKey(f"trustee-{index}", raw_key)
        self.group = group
        self.k = k
        self.trustee: Trustee | None = None
        self.available = True

    def begin(self, mhash: str) -> Trustee:
        self.trustee = Trustee(self.index, self.group, self.k, mhash)
        return self.trustee


class Administration:
    def __init__(self, board: Board, officer: RoleKey, group: Group, trustees: list[TrusteeHost], clock) -> None:
        self.board = board
        self.officer = officer
        self.group = group
        self.trustees = trustees
        self.clock = clock
        self.manifest: dict | None = None
        self.mhash: str | None = None
        self.commitments: list[TrusteeCommitment] = []
        self.pk: PublicKey | None = None

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
        assert self.manifest is not None and self.mhash is not None
        k = self.manifest["trustees"]["threshold"]
        n = len(self.trustees)
        self._transition("KEY_CEREMONY")
        holders = [h.begin(self.mhash) for h in self.trustees]
        self.commitments = []
        for host, t in zip(self.trustees, holders, strict=True):
            tc = t.commitment()
            self.board.append("trustee_commitment", host.key.sign_body({"commitment": tc.to_dict()}))
            self.commitments.append(tc)
        # Each trustee verifies every published commitment and every share it receives.
        for host, t in zip(self.trustees, holders, strict=True):
            for tc in self.commitments:
                if not verify_commitment(self.group, self.mhash, tc, k):
                    raise CeremonyError(f"trustee {host.index} rejects commitment of trustee {tc.index}")
            for dealer, tc in zip(holders, self.commitments, strict=True):
                t.receive_share(tc, dealer.share_for(t.index))
        for host, t in zip(self.trustees, holders, strict=True):
            t.finalize(n)  # destroys polynomial coefficients
            self.board.append("trustee_ack", host.key.sign_body({"index": host.index, "verified_all_shares": True}))
        K = joint_public_key(self.group, self.commitments)
        self.pk = PublicKey(self.group, K)
        self.board.append("joint_key", self.officer.sign_body({"joint_public_key": to_hex(K)}))
        return self.pk

    def publish_issuer_keys(self, signed_entry: dict) -> None:
        self.board.append("issuer_keys", signed_entry)

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
        self._transition("CLOSED", **extra)

    def publish_participation(self, signed_summary: dict) -> None:
        if self.board.state != "CLOSED":
            raise AdministrationError("participation summary is published after close")
        self.board.append("participation_summary", signed_summary)

    # --------------------------------------------------------------------- tally
    def tally(self) -> dict:
        assert self.manifest is not None and self.mhash is not None and self.pk is not None
        if self.board.state != "CLOSED":
            raise AdministrationError("tally requires a CLOSED election")
        grp, k = self.group, self.manifest["trustees"]["threshold"]
        # One streaming pass over the record: constant memory however many ballots.
        p = grp.p
        sums: dict[str, list[list[int]]] = {}
        n_ballots: dict[str, int] = defaultdict(int)
        for e in self.board.iter_entries("ballot"):
            bal = e["body"]["ballot"]
            acc = sums.setdefault(bal["constituency"], [[1, 1] for _ in bal["selections"]])
            for j, sel in enumerate(bal["selections"]):
                acc[j][0] = acc[j][0] * int(sel["ciphertext"]["alpha"], 16) % p
                acc[j][1] = acc[j][1] * int(sel["ciphertext"]["beta"], 16) % p
            n_ballots[bal["constituency"]] += 1
        quorum_hosts = [h for h in self.trustees if h.available][:k]
        if len(quorum_hosts) < k:
            raise AdministrationError(f"only {len(quorum_hosts)} trustees available; threshold is {k}")
        quorum = [h.index for h in quorum_hosts]
        results = {}
        for cons in self.manifest["constituencies"]:
            cid = cons["id"]
            option_ids = [o["id"] for o in cons["options"]]
            n = n_ballots.get(cid, 0)
            acc = sums.get(cid, [[1, 1] for _ in option_ids])
            aggs = {oid: Ciphertext(acc[j][0], acc[j][1]) for j, oid in enumerate(option_ids)}
            self.board.append(
                "aggregate",
                self.officer.sign_body(
                    {
                        "constituency": cid,
                        "ballot_count": n,
                        "aggregates": [{"option_id": oid, "ciphertext": aggs[oid].to_dict()} for oid in option_ids],
                    }
                ),
            )
            shares: dict[str, dict[int, int]] = {oid: {} for oid in option_ids}
            for host in quorum_hosts:
                assert host.trustee is not None
                items = []
                for oid in option_ids:
                    ctx = [self.mhash, "decrypt-aggregate", cid, oid]
                    M, pr = host.trustee.decryption_share(aggs[oid], ctx)
                    Ki = public_share(grp, self.commitments, host.index)
                    if not verify_decryption_share(grp, aggs[oid], Ki, M, pr, ctx):
                        raise AdministrationError(f"trustee {host.index} produced an invalid share")
                    shares[oid][host.index] = M
                    items.append({"option_id": oid, "share": to_hex(M), "proof": pr.to_dict()})
                self.board.append("decryption_shares", host.key.sign_body({"constituency": cid, "index": host.index, "shares": items}))
            counts = {oid: dlog_bounded(grp, combine(grp, aggs[oid], shares[oid]), n) for oid in option_ids}
            if sum(counts.values()) != n:
                raise AdministrationError(f"{cid}: decrypted total != ballots")
            results[cid] = decide(counts)
            self.board.append(
                "result",
                self.officer.sign_body(
                    {
                        "constituency": cid,
                        "quorum": quorum,
                        "ballot_count": n,
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
