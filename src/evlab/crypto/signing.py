"""Ed25519 role keys (officer, board operator, eligibility authority, trustees).

Uses the `cryptography` library; nothing here is hand-rolled.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .encoding import canonical_json

SIG_DOMAIN = b"evlab/v1/signed-body\x00"


class RoleKey:
    def __init__(self, role: str) -> None:
        self.role = role
        self._sk = Ed25519PrivateKey.generate()
        self.public_hex = self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def sign_body(self, body: dict) -> dict:
        """Return body + {"signer", "signature"}; the signature covers every other field."""
        if "signature" in body or "signer" in body:
            raise ValueError("body already signed")
        unsigned = dict(body, signer=self.role)
        sig = self._sk.sign(SIG_DOMAIN + canonical_json(unsigned)).hex()
        return dict(unsigned, signature=sig)


def verify_body(body: dict, public_hex: str, expected_role: str) -> bool:
    try:
        if body.get("signer") != expected_role:
            return False
        unsigned = {k: v for k, v in body.items() if k != "signature"}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(body["signature"]), SIG_DOMAIN + canonical_json(unsigned))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
