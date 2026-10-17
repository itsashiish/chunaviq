"""Trustee key custody: the code that would run INSIDE each trustee's HSM.

Why custom code: a decryption share is ``alpha^s_i`` plus a Chaum-Pedersen
proof, which needs modular exponentiation with the secret share and scalar
arithmetic mod q. Standard PKCS#11 mechanisms cannot do that without exporting
the share. HSMs that run vendor-signed custom code inside the security
boundary can: Thales Luna "Functionality Modules" (FM SDK), Entrust nShield
"CodeSafe", Utimaco CryptoServer SDK. ``TrusteeApplet`` is that code, written
against a narrow interface; ``seal``/``unseal`` emulate the HSM's protected
storage so the whole flow runs in tests. In a deployment the class body is
ported to the vendor SDK and the key share never exists outside the HSM.

One national key, one share per trustee
---------------------------------------
Protocol v2 uses ONE threshold key for the whole national election (543
constituency shards encrypt under it), so each trustee's HSM holds exactly one
share -- not 543. Separate per-constituency keys would add no protection,
because the same five trustees would hold all of them.

What the applet will and will not do
------------------------------------
  * generate its polynomial inside, send shares to the other trustees' HSMs
    encrypted to their transport keys, verify incoming shares (Feldman check)
    and combine them -- the share is never in plaintext outside the boundary
  * produce decryption shares ONLY when a request carries:
      - the election's CLOSED lifecycle entry, signed by a registered officer key
        (nothing is decrypted while voting is open)
      - approvals from ``operator_quorum`` of this trustee's operator cards
        (no single insider can use the share)
      - attestations from ``observer_quorum`` independent verifiers that the
        ciphertexts are what the purpose says: per-option totals of the record,
        or outputs of verified shuffles (so an individual ballot cannot be
        smuggled in as a "total")
      - a fresh nonce, within the election's decryption budget
  * keep a hash-chained, applet-signed log of every operation, exported for
    publication after the election
  * clone to a second HSM (disaster recovery) only to that HSM's transport key
    and only with operator quorum
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto.elgamal import Ciphertext
from .crypto.encoding import canonical_json, from_hex, sha256_hex, to_hex
from .crypto.group import get_group
from .crypto.signing import SIG_DOMAIN, verify_body
from .crypto.threshold import Trustee, TrusteeCommitment

PURPOSES = ("aggregate", "mix-flag", "mix-tag")
RAW = serialization.Encoding.Raw


class CustodyError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class CustodyPolicy:
    election_ids: list[str]
    officer_keys: list[str]
    operator_keys: list[str]
    operator_quorum: int
    observer_keys: list[str]
    observer_quorum: int
    budget: int  # most ciphertexts this HSM will ever partially decrypt


def request_hash(request: dict) -> str:
    return sha256_hex(canonical_json(request))


def _transport_seal(recipient_pub_hex: str, plaintext: bytes, info: bytes) -> str:
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(recipient_pub_hex)))
    key = HKDF(hashes.SHA256(), 32, None, b"chunaviq/v1/custody-transport\x00" + info).derive(shared)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, info)
    return (eph.public_key().public_bytes(RAW, serialization.PublicFormat.Raw) + nonce + ct).hex()


def _transport_open(priv: X25519PrivateKey, sealed_hex: str, info: bytes) -> bytes:
    raw = bytes.fromhex(sealed_hex)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(raw[:32]))
    key = HKDF(hashes.SHA256(), 32, None, b"chunaviq/v1/custody-transport\x00" + info).derive(shared)
    return AESGCM(key).decrypt(raw[32:44], raw[44:], info)


@dataclass
class _State:
    index: int
    group: str
    k: int
    policy: dict
    sign_key: str
    transport_key: str
    share: int | None = None
    ceremony_ctx: str = ""
    used: int = 0
    nonces: list[str] = field(default_factory=list)
    log: list[dict] = field(default_factory=list)


class TrusteeApplet:
    """Runs inside the HSM. Public methods are the HSM's command interface."""

    def __init__(self, index: int, group_name: str, k: int, policy: CustodyPolicy, _state: _State | None = None) -> None:
        if _state is None:
            sk = Ed25519PrivateKey.generate().private_bytes(RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            tk = X25519PrivateKey.generate().private_bytes(RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            _state = _State(index, group_name, k, asdict(policy), sk.hex(), tk.hex())
        self._s = _state
        self._grp = get_group(_state.group)
        self._trustee: Trustee | None = None

    # ------------------------------------------------------------- identity
    @property
    def index(self) -> int:
        return self._s.index

    @property
    def policy(self) -> CustodyPolicy:
        return CustodyPolicy(**self._s.policy)

    def _sk(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self._s.sign_key))

    def _tk(self) -> X25519PrivateKey:
        return X25519PrivateKey.from_private_bytes(bytes.fromhex(self._s.transport_key))

    def attestation_key(self) -> str:
        return self._sk().public_key().public_bytes(RAW, serialization.PublicFormat.Raw).hex()

    def transport_key(self) -> str:
        return self._tk().public_key().public_bytes(RAW, serialization.PublicFormat.Raw).hex()

    def _log(self, op: str, **detail) -> dict:
        prev = self._s.log[-1]["hash"] if self._s.log else "0" * 64
        body = {"n": len(self._s.log), "op": op, "prev": prev, **detail}
        h = sha256_hex(canonical_json(body))
        sig = self._sk().sign(SIG_DOMAIN + canonical_json({**body, "hash": h})).hex()
        rec = {**body, "hash": h, "signature": sig}
        self._s.log.append(rec)
        return rec

    def audit_log(self) -> list[dict]:
        return list(self._s.log)

    # ------------------------------------------------------------- key ceremony
    def begin_ceremony(self, ceremony_ctx: str) -> dict:
        if self._s.share is not None or self._trustee is not None:
            raise CustodyError("CEREMONY_ALREADY_DONE")
        self._s.ceremony_ctx = ceremony_ctx
        self._trustee = Trustee(self._s.index, self._grp, self._s.k, ceremony_ctx)
        self._log("ceremony-begin", ceremony=ceremony_ctx)
        return self._trustee.commitment().to_dict()

    def share_for(self, other_index: int, other_transport_key: str) -> str:
        if self._trustee is None:
            raise CustodyError("NO_CEREMONY")
        share = self._trustee.share_for(other_index)
        info = f"{self._s.ceremony_ctx}|{self._s.index}->{other_index}".encode()
        return _transport_seal(other_transport_key, to_hex(share).encode(), info)

    def receive_share(self, from_index: int, commitment: dict, sealed: str) -> None:
        if self._trustee is None:
            raise CustodyError("NO_CEREMONY")
        info = f"{self._s.ceremony_ctx}|{from_index}->{self._s.index}".encode()
        share = from_hex(_transport_open(self._tk(), sealed, info).decode())
        self._trustee.receive_share(TrusteeCommitment.from_dict(commitment), share)  # Feldman check inside

    def finish_ceremony(self, n: int) -> dict:
        if self._trustee is None:
            raise CustodyError("NO_CEREMONY")
        self._trustee.finalize(n)  # destroys coefficients
        self._s.share = self._trustee.secret_share
        self._trustee = None
        Ki = self._grp.g_pow(self._s.share)
        self._log("ceremony-finish", public_share=to_hex(Ki))
        return {"index": self._s.index, "public_share": to_hex(Ki)}

    # ------------------------------------------------------------- decryption
    def _count_signers(self, sigs: list[dict], keys: list[str], role: str, body_extra: dict) -> int:
        ok = set()
        for s in sigs:
            body = {**body_extra, "signer": role, "signature": s.get("signature", "")}
            for kk in keys:
                if kk not in ok and verify_body(body, kk, role):
                    ok.add(kk)
                    break
        return len(ok)

    def decrypt(self, request: dict, approvals: list[dict], attestations: list[dict]) -> dict:
        pol = self.policy
        if self._s.share is None:
            raise CustodyError("NO_SHARE")
        try:
            purpose, items, nonce = request["purpose"], request["items"], request["nonce"]
            closed = request["closed"]
            eid = request["election_id"]
        except (KeyError, TypeError):
            raise CustodyError("MALFORMED") from None
        if purpose not in PURPOSES:
            raise CustodyError("PURPOSE_NOT_ALLOWED")
        if eid not in pol.election_ids:
            raise CustodyError("WRONG_ELECTION")
        if not (
            isinstance(closed, dict)
            and closed.get("state") == "CLOSED"
            and closed.get("election_id") == eid
            and any(verify_body(closed, k, "officer") for k in pol.officer_keys)
        ):
            raise CustodyError("ELECTION_NOT_CLOSED")
        if not isinstance(nonce, str) or nonce in self._s.nonces:
            raise CustodyError("REPLAYED_REQUEST")
        rh = request_hash(request)
        if self._count_signers(approvals, pol.operator_keys, "operator", {"approve": rh}) < pol.operator_quorum:
            raise CustodyError("OPERATOR_QUORUM_MISSING")
        statement = f"verified:{purpose}"
        if self._count_signers(attestations, pol.observer_keys, "observer", {"attest": rh, "statement": statement}) < pol.observer_quorum:
            raise CustodyError("OBSERVER_QUORUM_MISSING")
        if self._s.used + len(items) > pol.budget:
            raise CustodyError("BUDGET_EXHAUSTED")
        trustee = Trustee.__new__(Trustee)  # stateless helper around the share
        trustee.index, trustee.group, trustee.k, trustee.manifest_hash = self._s.index, self._grp, self._s.k, self._s.ceremony_ctx
        trustee._coeffs, trustee._received, trustee.secret_share = [], {}, self._s.share
        out = []
        for it in items:
            ct = Ciphertext.from_dict(it["ciphertext"])
            if not self._grp.is_element(ct.alpha):
                raise CustodyError("INVALID_CIPHERTEXT")
            M, pr = trustee.decryption_share(ct, it["context"])
            out.append({"share": to_hex(M), "proof": pr.to_dict()})
        self._s.used += len(items)
        self._s.nonces.append(nonce)
        rec = self._log("decrypt", purpose=purpose, election_id=eid, request=rh, count=len(items))
        return {"shares": out, "log": rec}

    # ------------------------------------------------------------- backup / clone
    def export_clone(self, recipient_transport_key: str, approvals: list[dict]) -> str:
        pol = self.policy
        if self._count_signers(approvals, pol.operator_keys, "operator", {"approve": f"clone:{recipient_transport_key}"}) < pol.operator_quorum:
            raise CustodyError("OPERATOR_QUORUM_MISSING")
        self._log("clone-export", to=recipient_transport_key)
        return _transport_seal(recipient_transport_key, json.dumps(asdict(self._s)).encode(), b"clone")

    @staticmethod
    def import_clone(sealed: str, receiver: TrusteeApplet) -> TrusteeApplet:
        st = _State(**json.loads(_transport_open(receiver._tk(), sealed, b"clone")))
        clone = TrusteeApplet(st.index, st.group, st.k, CustodyPolicy(**st.policy), _state=st)
        clone._log("clone-import")
        return clone

    # ------------------------------------------------------------- protected storage (emulated)
    def seal(self, kek: bytes) -> bytes:
        if self._trustee is not None:
            raise CustodyError("CEREMONY_IN_PROGRESS")
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(kek).encrypt(nonce, json.dumps(asdict(self._s)).encode(), b"chunaviq-hsm-state")

    @staticmethod
    def unseal(blob: bytes, kek: bytes) -> TrusteeApplet:
        st = _State(**json.loads(AESGCM(kek).decrypt(blob[:12], blob[12:], b"chunaviq-hsm-state")))
        return TrusteeApplet(st.index, st.group, st.k, CustodyPolicy(**st.policy), _state=st)


def verify_audit_log(log: list[dict], attestation_key_hex: str) -> bool:
    """Anyone can check an exported HSM log: hash chain intact and every record signed."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(attestation_key_hex))
    prev = "0" * 64
    for n, rec in enumerate(log):
        body = {k: v for k, v in rec.items() if k not in ("hash", "signature")}
        if rec.get("n") != n or rec.get("prev") != prev or sha256_hex(canonical_json(body)) != rec.get("hash"):
            return False
        try:
            pub.verify(bytes.fromhex(rec["signature"]), SIG_DOMAIN + canonical_json({**body, "hash": rec["hash"]}))
        except (InvalidSignature, ValueError):
            return False
        prev = rec["hash"]
    return True


def hsm_kek() -> bytes:
    """Stand-in for the HSM's internal storage key (never leaves real hardware)."""
    return hashlib.sha256(secrets.token_bytes(32)).digest()


__all__ = ["CustodyPolicy", "CustodyError", "TrusteeApplet", "request_hash", "verify_audit_log", "hsm_kek", "PURPOSES"]
