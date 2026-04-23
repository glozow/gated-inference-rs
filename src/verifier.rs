//! Verify incoming `/generate` requests.
//!
//! Wire format:
//!   { "payload": { "prompt": "...", "nonce": "...", "timestamp": 1700000000 },
//!     "signature": "<base64 of 64-byte compact ECDSA r||s>" }
//!
//! Checks (in order):
//!   1. signature parses as compact 64-byte ECDSA
//!   2. ECDSA verify over SHA256(canonical_json(payload)) against pinned pubkey
//!   3. payload shape (prompt/nonce/timestamp)
//!   4. timestamp within freshness window (default ±60s forward, +5s back for clock skew)
//!   5. nonce not in the in-memory LRU (replay protection; lost on restart)

use crate::canonical_json;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use lru::LruCache;
use parking_lot::Mutex;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, VerifyOnly};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed signature: {0}")]
    MalformedSignature(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("malformed payload: {0}")]
    MalformedPayload(String),
    #[error("timestamp out of freshness window (age={age}s, max={max}s)")]
    StaleTimestamp { age: i64, max: i64 },
    #[error("nonce replay")]
    NonceReplay,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignedPayload {
    pub payload: serde_json::Value,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Payload {
    pub prompt: String,
    pub nonce: String,
    pub timestamp: i64,
}

pub struct Verifier {
    secp: Secp256k1<VerifyOnly>,
    pubkey: PublicKey,
    max_age_secs: i64,
    nonce_cache: Arc<Mutex<LruCache<String, ()>>>,
}

impl Verifier {
    /// `pubkey_hex` is the 33-byte compressed SEC1 encoding, hex.
    pub fn new(
        pubkey_hex: &str,
        max_age_secs: i64,
        nonce_cache_size: usize,
    ) -> anyhow::Result<Self> {
        let pubkey_bytes = hex::decode(pubkey_hex.trim().trim_start_matches("0x"))?;
        let pubkey = PublicKey::from_slice(&pubkey_bytes)?;
        let cache_size = NonZeroUsize::new(nonce_cache_size.max(1)).unwrap();
        Ok(Self {
            secp: Secp256k1::verification_only(),
            pubkey,
            max_age_secs,
            nonce_cache: Arc::new(Mutex::new(LruCache::new(cache_size))),
        })
    }

    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.pubkey.serialize())
    }

    pub fn verify(&self, signed: &SignedPayload) -> Result<Payload, VerifyError> {
        let sig_bytes = B64
            .decode(&signed.signature)
            .map_err(|e| VerifyError::MalformedSignature(e.to_string()))?;
        let sig = Signature::from_compact(&sig_bytes)
            .map_err(|e| VerifyError::MalformedSignature(e.to_string()))?;

        let canonical = canonical_json::to_bytes(&signed.payload);
        let digest: [u8; 32] = Sha256::digest(&canonical).into();
        let msg = Message::from_digest(digest);

        self.secp
            .verify_ecdsa(&msg, &sig, &self.pubkey)
            .map_err(|_| VerifyError::BadSignature)?;

        let payload: Payload = serde_json::from_value(signed.payload.clone())
            .map_err(|e| VerifyError::MalformedPayload(e.to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before unix epoch")
            .as_secs() as i64;
        let age = now - payload.timestamp;
        if age < -5 || age > self.max_age_secs {
            return Err(VerifyError::StaleTimestamp {
                age,
                max: self.max_age_secs,
            });
        }

        let mut cache = self.nonce_cache.lock();
        if cache.put(payload.nonce.clone(), ()).is_some() {
            return Err(VerifyError::NonceReplay);
        }

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{rand::rngs::OsRng, Keypair, Secp256k1 as Secp};
    use serde_json::json;

    fn sign_compact_b64(
        secp: &Secp<secp256k1::All>,
        kp: &Keypair,
        payload: &serde_json::Value,
    ) -> String {
        let canonical = canonical_json::to_bytes(payload);
        let digest: [u8; 32] = Sha256::digest(&canonical).into();
        let msg = Message::from_digest(digest);
        let sig = secp.sign_ecdsa(&msg, &kp.secret_key());
        B64.encode(sig.serialize_compact())
    }

    fn fresh_payload(prompt: &str, nonce: &str) -> serde_json::Value {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        json!({ "prompt": prompt, "nonce": nonce, "timestamp": ts })
    }

    #[test]
    fn good_signature_accepted() {
        let secp = Secp::new();
        let kp = Keypair::new(&secp, &mut OsRng);
        let pubkey_hex = hex::encode(kp.public_key().serialize());

        let v = Verifier::new(&pubkey_hex, 60, 1024).unwrap();
        let payload = fresh_payload("hi", "n1");
        let sig = sign_compact_b64(&secp, &kp, &payload);

        let out = v
            .verify(&SignedPayload {
                payload,
                signature: sig,
            })
            .unwrap();
        assert_eq!(out.prompt, "hi");
        assert_eq!(out.nonce, "n1");
    }

    #[test]
    fn wrong_key_rejected() {
        let secp = Secp::new();
        let authorized = Keypair::new(&secp, &mut OsRng);
        let attacker = Keypair::new(&secp, &mut OsRng);
        let v = Verifier::new(&hex::encode(authorized.public_key().serialize()), 60, 1024).unwrap();
        let payload = fresh_payload("hi", "n1");
        let sig = sign_compact_b64(&secp, &attacker, &payload);
        assert!(matches!(
            v.verify(&SignedPayload {
                payload,
                signature: sig
            }),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn tampered_payload_rejected() {
        let secp = Secp::new();
        let kp = Keypair::new(&secp, &mut OsRng);
        let v = Verifier::new(&hex::encode(kp.public_key().serialize()), 60, 1024).unwrap();
        let payload = fresh_payload("hi", "n1");
        let sig = sign_compact_b64(&secp, &kp, &payload);

        let mut tampered = payload.clone();
        tampered["prompt"] = json!("bye");
        assert!(matches!(
            v.verify(&SignedPayload {
                payload: tampered,
                signature: sig
            }),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn stale_timestamp_rejected() {
        let secp = Secp::new();
        let kp = Keypair::new(&secp, &mut OsRng);
        let v = Verifier::new(&hex::encode(kp.public_key().serialize()), 60, 1024).unwrap();
        let payload = json!({ "prompt": "hi", "nonce": "n1", "timestamp": 0_i64 });
        let sig = sign_compact_b64(&secp, &kp, &payload);
        assert!(matches!(
            v.verify(&SignedPayload {
                payload,
                signature: sig
            }),
            Err(VerifyError::StaleTimestamp { .. })
        ));
    }

    #[test]
    fn replay_rejected() {
        let secp = Secp::new();
        let kp = Keypair::new(&secp, &mut OsRng);
        let v = Verifier::new(&hex::encode(kp.public_key().serialize()), 60, 1024).unwrap();
        let payload = fresh_payload("hi", "same-nonce");
        let sig = sign_compact_b64(&secp, &kp, &payload);

        assert!(v
            .verify(&SignedPayload {
                payload: payload.clone(),
                signature: sig.clone()
            })
            .is_ok());
        assert!(matches!(
            v.verify(&SignedPayload {
                payload,
                signature: sig
            }),
            Err(VerifyError::NonceReplay)
        ));
    }
}
