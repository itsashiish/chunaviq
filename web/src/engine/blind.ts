// RSA-FDH blind credentials. Mirrors src/chunaviq/crypto/blind.py.
// Key generation uses WebCrypto (native, extractable JWK); only blinding arithmetic is ours.
import { sha256 } from "@noble/hashes/sha2.js";
import { b64urlToBigint, bitLength, bytesToBigint, concat, enc, fromHex, modinv, modpow, randBelow, toHex } from "./bigint";

const FDH_DOMAIN = enc.encode("chunaviq/v1/credential-fdh\u0000");

export type RSAPublic = { n: bigint; e: bigint };
export const rsaToJson = (k: RSAPublic) => ({ n: toHex(k.n), e: toHex(k.e) });
export const rsaFromJson = (d: { n: string; e: string }): RSAPublic => ({ n: fromHex(d.n), e: fromHex(d.e) });

function mgf1(seed: Uint8Array, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let off = 0;
  for (let c = 0; off < len; c++) {
    const h = sha256(concat(seed, new Uint8Array([(c >>> 24) & 255, (c >>> 16) & 255, (c >>> 8) & 255, c & 255])));
    out.set(h.subarray(0, Math.min(32, len - off)), off);
    off += 32;
  }
  return out;
}

export function credentialMessage(electionId: string, constituency: string, token: Uint8Array): Uint8Array {
  if (token.length !== 32) throw new RangeError("token must be 32 bytes");
  return concat(enc.encode(electionId), new Uint8Array([0]), enc.encode(constituency), new Uint8Array([0]), token);
}

export function fdh(n: bigint, msg: Uint8Array): bigint {
  const k = Math.ceil(bitLength(n) / 8);
  return bytesToBigint(mgf1(concat(FDH_DOMAIN, msg), k - 1));
}

export const rsaVerify = (pub: RSAPublic, msg: Uint8Array, sig: bigint) => sig > 0n && sig < pub.n && modpow(sig, pub.e, pub.n) === fdh(pub.n, msg);

export class BlindSigner {
  private constructor(
    public pub: RSAPublic,
    private p: bigint,
    private q: bigint,
    private dp: bigint,
    private dq: bigint,
    private qi: bigint,
  ) {}

  static async generate(bits = 3072): Promise<BlindSigner> {
    const kp = (await crypto.subtle.generateKey(
      { name: "RSA-PSS", modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const j = await crypto.subtle.exportKey("jwk", kp.privateKey);
    const f = (s?: string) => b64urlToBigint(s!);
    return new BlindSigner({ n: f(j.n), e: f(j.e) }, f(j.p), f(j.q), f(j.dp), f(j.dq), f(j.qi));
  }

  signBlinded(m: bigint): bigint {
    const { n, e } = this.pub;
    if (m <= 0n || m >= n) throw new RangeError("blinded message out of range");
    // JWK convention: qi = q^-1 mod p.  s = m2 + q * (qi * (m1 - m2) mod p)
    const m1 = modpow(m, this.dp, this.p);
    const m2 = modpow(m, this.dq, this.q);
    const h = (((this.qi * (m1 - m2)) % this.p) + this.p) % this.p;
    const s = m2 + h * this.q;
    if (modpow(s, e, n) !== m) throw new Error("RSA-CRT self-check failed");
    return s;
  }
}

export function blind(pub: RSAPublic, msg: Uint8Array): { blinded: bigint; r: bigint } {
  let r: bigint;
  for (;;) {
    r = randBelow(pub.n - 2n) + 2n;
    try {
      modinv(r, pub.n);
      break;
    } catch {
      /* not coprime: retry */
    }
  }
  return { blinded: (fdh(pub.n, msg) * modpow(r, pub.e, pub.n)) % pub.n, r };
}

export function unblind(pub: RSAPublic, msg: Uint8Array, r: bigint, blindSig: bigint): bigint {
  const s = (blindSig * modinv(r, pub.n)) % pub.n;
  if (!rsaVerify(pub, msg, s)) throw new Error("issuer returned an invalid blind signature");
  return s;
}
