# python-client

Minimal signer that produces `/generate` request bodies the Rust server
accepts. Uses [`coincurve`](https://github.com/ofek/coincurve) — a CFFI
binding to the same `libsecp256k1` that the Rust server links. Same C
code on both sides, so there's no cross-implementation drift to audit.

## Quickstart

```bash
# From the flake devShell (python + coincurve + requests pinned):
nix develop

# Generate a keypair. Save the privkey somewhere; give the pubkey to the server.
python sign_request.py --gen-key

# Start the server with that pubkey authorized:
AUTHORIZED_PUBKEY=<pubkey_hex> \
  LLM_MODEL_PATH=/path/to/main.gguf \
  cargo run --release

# Sign and POST a prompt:
python sign_request.py \
  --privkey-hex <privkey_hex> \
  --prompt "What is the capital of France?"
```

## Wire format

Request body:

```json
{
  "payload": {
    "prompt": "...",
    "nonce": "hex-or-any-string",
    "timestamp": 1700000000
  },
  "signature": "base64-of-64-byte-compact-r||s"
}
```

Signature = ECDSA-secp256k1 over `sha256(canonical_json(payload))`, where
canonical JSON is `json.dumps(obj, sort_keys=True, separators=(",",":"),
ensure_ascii=False).encode()`. The server enforces the same canonicalization
byte-for-byte — do not change the separators or key-sort order.

## Why DER → compact conversion

`coincurve.PrivateKey.sign` returns DER (variable length). The Rust server
uses `libsecp256k1`'s compact 64-byte form (`r||s`, fixed length, what the
library uses internally). `_der_to_compact` strips DER framing and sign-bit
padding — a ~15-line function with no dependencies.
