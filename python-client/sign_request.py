#!/usr/bin/env python3
"""
Sign and POST a /generate request for gated-inference-rs.

Wire format (must match the Rust Verifier byte-for-byte):

  payload = {"prompt": ..., "nonce": ..., "timestamp": ...}
  canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode()
  digest = sha256(canonical)
  sig_compact = ecdsa_secp256k1_sign(digest, priv_key)      # 64 bytes r||s
  body = {"payload": payload, "signature": base64(sig_compact)}

Uses `coincurve`, which is a CFFI binding to Bitcoin Core's libsecp256k1 —
the same library the Rust server verifies with.

Usage:
  python sign_request.py \\
    --privkey-hex 0xabc...def \\
    --prompt "What is the capital of France?" \\
    --url http://localhost:8080/generate

  # Dry-run (no HTTP): print the signed body
  python sign_request.py --privkey-hex ... --prompt "hi" --dry-run

  # Generate a new keypair (prints privkey_hex + pubkey_hex)
  python sign_request.py --gen-key
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import sys
import time
import uuid

from coincurve import PrivateKey


def canonical_json(obj) -> bytes:
    """Must match src/canonical_json.rs::to_bytes byte-for-byte."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _der_to_compact(der: bytes) -> bytes:
    """Convert an ECDSA DER signature to compact 64-byte r||s.

    DER layout for ECDSA:
      0x30 <total-len>
        0x02 <r-len> <r-bytes>
        0x02 <s-len> <s-bytes>
    Each of r and s is a big-endian signed integer, so libsecp256k1 may have
    added a leading 0x00 sign-bit pad; we strip it and left-pad to 32 bytes.
    """
    if len(der) < 8 or der[0] != 0x30:
        raise ValueError("not a DER-encoded ECDSA signature")
    idx = 2
    if der[idx] != 0x02:
        raise ValueError("expected INTEGER for r")
    r_len = der[idx + 1]
    r = der[idx + 2 : idx + 2 + r_len]
    idx += 2 + r_len
    if der[idx] != 0x02:
        raise ValueError("expected INTEGER for s")
    s_len = der[idx + 1]
    s = der[idx + 2 : idx + 2 + s_len]

    r = r.lstrip(b"\x00").rjust(32, b"\x00")
    s = s.lstrip(b"\x00").rjust(32, b"\x00")
    if len(r) != 32 or len(s) != 32:
        raise ValueError(f"r/s overflow: r={len(r)} s={len(s)}")
    return r + s


def sign_compact_b64(priv: PrivateKey, payload: dict) -> str:
    digest = hashlib.sha256(canonical_json(payload)).digest()
    der = priv.sign(digest, hasher=None)  # coincurve skips hashing when hasher=None
    return base64.b64encode(_der_to_compact(der)).decode()


def build_body(priv: PrivateKey, prompt: str, nonce: str | None = None) -> dict:
    payload = {
        "prompt": prompt,
        "nonce": nonce or uuid.uuid4().hex,
        "timestamp": int(time.time()),
    }
    return {"payload": payload, "signature": sign_compact_b64(priv, payload)}


def cmd_gen_key() -> int:
    priv = PrivateKey(secrets.token_bytes(32))
    print(f"privkey_hex: {priv.to_hex()}")
    print(f"pubkey_hex:  {priv.public_key.format(compressed=True).hex()}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gen-key", action="store_true", help="print a new keypair and exit")
    ap.add_argument("--privkey-hex", help="32-byte secp256k1 private key, hex")
    ap.add_argument("--prompt", help="prompt to sign + send")
    ap.add_argument("--nonce", default=None)
    ap.add_argument("--url", default="http://localhost:8080/generate")
    ap.add_argument("--dry-run", action="store_true", help="print the signed body, don't POST")
    args = ap.parse_args()

    if args.gen_key:
        return cmd_gen_key()

    if not args.privkey_hex or not args.prompt:
        ap.error("--privkey-hex and --prompt are required (or use --gen-key)")

    priv_hex = args.privkey_hex.removeprefix("0x")
    priv = PrivateKey(bytes.fromhex(priv_hex))
    body = build_body(priv, args.prompt, args.nonce)

    if args.dry_run:
        print(json.dumps(body, indent=2))
        return 0

    import requests  # imported lazily so --dry-run doesn't need it

    r = requests.post(args.url, json=body, timeout=60)
    if not r.ok:
        print(f"request failed ({r.status_code}): {r.text}", file=sys.stderr)
        return 1
    print(json.dumps(r.json(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
