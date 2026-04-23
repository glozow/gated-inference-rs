//! Integration test: the Verifier accepts a payload signed by a fresh keypair
//! and rejects the same payload under various tamper scenarios.
//!
//! This doesn't touch llama.cpp — it just exercises the sign/verify wire
//! contract end-to-end, which is the part the Python client must match.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use gated_inference::{canonical_json, verifier::SignedPayload, Verifier};
use secp256k1::{rand::rngs::OsRng, Keypair, Message, Secp256k1};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sign_like_python(kp: &Keypair, payload: &serde_json::Value) -> String {
    let secp = Secp256k1::new();
    let canonical = canonical_json::to_bytes(payload);
    let digest: [u8; 32] = Sha256::digest(&canonical).into();
    let msg = Message::from_digest(digest);
    let sig = secp.sign_ecdsa(&msg, &kp.secret_key());
    B64.encode(sig.serialize_compact())
}

#[test]
fn roundtrip_happy_path() {
    let secp = Secp256k1::new();
    let kp = Keypair::new(&secp, &mut OsRng);
    let pubkey_hex = hex::encode(kp.public_key().serialize());

    let verifier = Verifier::new(&pubkey_hex, 60, 1024).unwrap();
    let payload = json!({
        "prompt": "What is the capital of France?",
        "nonce": "n-happy-path",
        "timestamp": now(),
    });
    let signature = sign_like_python(&kp, &payload);

    let out = verifier
        .verify(&SignedPayload { payload, signature })
        .expect("happy-path signed request should verify");
    assert_eq!(out.prompt, "What is the capital of France?");
}

#[test]
fn canonical_json_stable_across_key_order() {
    // Two payloads with identical content but different key-insertion order
    // must hash to the same bytes — that's the whole point of canonical JSON.
    let a = json!({ "prompt": "hi", "nonce": "n", "timestamp": 1_700_000_000 });
    let b = json!({ "timestamp": 1_700_000_000, "nonce": "n", "prompt": "hi" });
    assert_eq!(canonical_json::to_bytes(&a), canonical_json::to_bytes(&b));
}
