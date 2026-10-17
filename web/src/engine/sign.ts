// Ed25519 role keys (audited @noble/curves). Mirrors src/chunaviq/crypto/signing.py.
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, concat, enc, hexToBytes } from "./bigint";
import { canonicalBytes, type Json } from "./encoding";

const SIG_DOMAIN = enc.encode("chunaviq/v1/signed-body\u0000");

export type Body = { [k: string]: Json };

export class RoleKey {
  private sk = ed25519.utils.randomSecretKey();
  publicHex: string;
  constructor(public role: string) {
    this.publicHex = bytesToHex(ed25519.getPublicKey(this.sk));
  }
  signBody(body: Body): Body {
    if ("signature" in body || "signer" in body) throw new Error("body already signed");
    const unsigned: Body = { ...body, signer: this.role };
    const sig = ed25519.sign(concat(SIG_DOMAIN, canonicalBytes(unsigned)), this.sk);
    return { ...unsigned, signature: bytesToHex(sig) };
  }
}

export function verifyBody(body: Body, publicHex: string, role: string): boolean {
  try {
    if (body.signer !== role || typeof body.signature !== "string") return false;
    const { signature, ...unsigned } = body;
    return ed25519.verify(hexToBytes(signature as string), concat(SIG_DOMAIN, canonicalBytes(unsigned)), hexToBytes(publicHex));
  } catch {
    return false;
  }
}
