# Local testing

End-to-end smoke test of `gated-inference-rs`: build the server, load a
tiny GGUF, sign a request with the Python client, and verify the
signature-gate actually gates.

No Nix, no Docker. Just `cargo`, `curl`, and `python3` with `coincurve`
and `requests`.

## 0. Prereqs

- Rust toolchain as pinned in `rust-toolchain.toml` (rustup will install
  it automatically on first `cargo build`).
- System packages: `cmake`, `clang`, `pkg-config` (for `llama-cpp-sys-2`'s
  build.rs).
- Python 3.10+ with `coincurve` and `requests`:
  ```bash
  pip install coincurve requests
  ```

## 1. Build the server

```bash
cargo build --release
```

First build compiles `llama.cpp` from source via cmake. Expect a few
minutes; subsequent builds are fast.

## 2. Run the unit + interop tests (no GGUF needed)

```bash
cargo test --release
```

Expected: **13 passed** — 5 canonical-JSON, 5 verifier, 1 signer,
2 interop.

These cover: canonical JSON byte-for-byte reproducibility, ECDSA
accept/reject, tamper detection, stale-timestamp rejection, nonce
replay rejection, and signer-verifier roundtrip. They don't touch
llama.cpp, so they're the fastest feedback loop.

## 3. Fetch a small GGUF

```bash
mkdir -p models
curl -L --fail -o models/main.gguf \
  https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf
```

~469 MB. CPU-only inference on this is 300–500 ms for 32 tokens.
`models/*.gguf` is gitignored.

## 4. Mint a client keypair

```bash
python3 python-client/sign_request.py --gen-key
# privkey_hex: <KEEP SECRET>
# pubkey_hex:  <paste into AUTHORIZED_PUBKEY>
```

The **pubkey** gets pinned at server startup. The **privkey** goes into
the Python client. Losing the privkey means you can't talk to this
server instance.

## 5. Start the server

In a dedicated terminal:

```bash
AUTHORIZED_PUBKEY=<pubkey_hex> \
LLM_MODEL_PATH=$PWD/models/main.gguf \
LLM_MAX_TOKENS=32 \
PORT=9300 \
RUST_LOG=info \
./target/release/gated-inference-server
```

You should see lines like:

```
INFO loading LLM weights ...
INFO model loaded
INFO verifier initialized authorized_pubkey=<pubkey_hex>
INFO signer initialized server_pubkey=<boot-ephemeral-pubkey>
INFO listening addr=0.0.0.0:9300
```

The **server_pubkey** is a fresh ECDSA keypair minted at boot. It
signs every response. Every restart rotates it.

## 6. Probe the unauthenticated endpoints

In another terminal:

```bash
curl -sS http://localhost:9300/health | jq
curl -sS http://localhost:9300/pubkey | jq
```

`/health` echoes the pinned `authorized_pubkey` and `boot_time`.
`/pubkey` additionally exposes the server's response-signing
`public_key`.

## 7. Happy-path `/generate`

```bash
python3 python-client/sign_request.py \
  --privkey-hex <privkey_hex> \
  --prompt "What is the capital of France? Answer in one short sentence." \
  --url http://localhost:9300/generate
```

Expected: a JSON blob with

- `result.output` — the model's text
- `result.prompt_sha256` / `result.output_sha256` — content hashes
- `result.nonce` — echoed from the request
- `signature` — base64 of compact (r||s) ECDSA over
  `SHA256(canonical_json(result))`
- `public_key` — the server's boot-ephemeral pubkey (matches `/pubkey`)
- `algorithm` — `"ecdsa-secp256k1"`

Anyone with `(result, signature, public_key)` can re-verify offline
without the server being alive.

## 8. Confirm the gate actually gates

### Replay protection

Send the same nonce twice:

```bash
python3 python-client/sign_request.py \
  --privkey-hex <privkey_hex> \
  --prompt "replay test" --nonce fixed-nonce-1 \
  --url http://localhost:9300/generate
# 200 OK, inference runs

python3 python-client/sign_request.py \
  --privkey-hex <privkey_hex> \
  --prompt "replay test" --nonce fixed-nonce-1 \
  --url http://localhost:9300/generate
# request failed (401): {"error":"nonce replay"}
```

The nonce LRU lives in RAM — a server restart resets it.

### Wrong key

Sign with a key the server didn't authorize:

```bash
python3 python-client/sign_request.py \
  --privkey-hex 1111111111111111111111111111111111111111111111111111111111111111 \
  --prompt "attacker" \
  --url http://localhost:9300/generate
# request failed (401): {"error":"signature verification failed"}
```

### Stale timestamp

The client uses `int(time.time())` automatically. To force a stale
request, use `--dry-run`, edit the timestamp by hand, then POST with
`curl`:

```bash
python3 python-client/sign_request.py \
  --privkey-hex <privkey_hex> --prompt "hi" --dry-run > /tmp/body.json
# hand-edit /tmp/body.json to set payload.timestamp to something old
# NB: editing the payload invalidates the signature, so you'd also have
# to re-sign after the edit — easiest way to exercise this path is the
# `stale_timestamp_rejected` unit test in src/verifier.rs.
```

Realistically, the unit test already covers this; step 2 is where you
confirm it.

### Tampered payload

```bash
python3 python-client/sign_request.py \
  --privkey-hex <privkey_hex> --prompt "hi" --dry-run > /tmp/body.json
# Change payload.prompt to something else:
jq '.payload.prompt = "malicious"' /tmp/body.json \
  | curl -sS -H 'content-type: application/json' \
         -d @- http://localhost:9300/generate
# {"error":"signature verification failed"}
```

## 9. Verify a response signature offline

Save any happy-path response to `/tmp/resp.json` and verify it with
`coincurve` — no running server required:

```python
import base64, hashlib, json
from coincurve import PublicKey

resp = json.load(open("/tmp/resp.json"))
canonical = json.dumps(
    resp["result"], sort_keys=True, separators=(",", ":"),
    ensure_ascii=False,
).encode()
digest = hashlib.sha256(canonical).digest()
compact = base64.b64decode(resp["signature"])
pub = PublicKey(bytes.fromhex(resp["public_key"]))

# coincurve verifies DER; build DER from compact (r||s) first.
from coincurve.utils import int_to_bytes_padded
# Simplest path: use coincurve's `verify` with the compact form via
# cffi helpers, or use the python-ecdsa lib. For a quick smoke check,
# sanity-check the digest and the public_key format and trust the server
# signature unit tests — the Rust + Python stacks share libsecp256k1.
```

(`python-client/sign_request.py` DOES have `_der_to_compact`; going the
other way is ~15 lines if you need it. The unit test
`tests/interop.rs::roundtrip_happy_path` exercises this path inside
Rust, which is the authoritative check.)

## 10. Env vars (reference)

| Var                 | Default              | Notes |
|---------------------|----------------------|-------|
| `AUTHORIZED_PUBKEY` | (required)           | 33-byte SEC1 compressed, hex |
| `LLM_MODEL_PATH`    | `/models/main.gguf`  | GGUF file |
| `LLM_CTX`           | `4096`               | context tokens |
| `LLM_MAX_TOKENS`    | `256`                | max generated tokens per request |
| `MAX_AGE_SECS`      | `60`                 | timestamp freshness window |
| `NONCE_CACHE_SIZE`  | `10000`              | LRU size for replay protection |
| `PORT`              | `8080`               | TCP port |
| `RUST_LOG`          | unset                | e.g. `info,gated_inference=debug` |

## Troubleshooting

- **`cargo build` fails with `edition2024` error** — your rustc is older
  than `rust-toolchain.toml`. Let rustup install the pinned toolchain
  (`rustup show` in the repo root should print the pinned version), or
  update with `rustup update`.
- **llama.cpp fails to compile** — `cmake` / `clang` missing. Install
  both, then `cargo clean -p llama-cpp-sys-2 && cargo build --release`.
- **`/generate` hangs** — the model is loading or generating. Check
  `RUST_LOG=info` output; first request after boot is slowest.
- **`nonce replay` even though the nonce is unique** — you're reusing
  the exact request body. The client auto-generates a UUID nonce; don't
  pass `--nonce` unless you want to pin it.
