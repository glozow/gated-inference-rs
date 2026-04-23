//! Boot-ephemeral ECDSA-secp256k1 keypair. Signs the server's response payload
//! over SHA256(canonical_json(payload)). Produces compact 64-byte r||s, base64.
//!
//! The private key never leaves this process and never touches disk. Each
//! boot generates a new key; `/pubkey` exposes the public half so clients
//! can pin it per session (and, in production, bind it via attestation).

use crate::canonical_json;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use secp256k1::{rand::rngs::OsRng, Message, PublicKey, Secp256k1, SecretKey, SignOnly};
use sha2::{Digest, Sha256};

pub struct Signer {
    secp: Secp256k1<SignOnly>,
    secret: SecretKey,
    pubkey: PublicKey,
}

impl Signer {
    pub fn generate() -> Self {
        let secp = Secp256k1::signing_only();
        // SAFETY note: OsRng pulls from the OS CSPRNG. Do not substitute a
        // deterministic RNG here — the session-ephemeral key must be unpredictable.
        let full = Secp256k1::new();
        let (secret, pubkey) = full.generate_keypair(&mut OsRng);
        Self {
            secp,
            secret,
            pubkey,
        }
    }

    /// 33-byte compressed SEC1 pubkey, hex-encoded (matches Verifier::new input format).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.pubkey.serialize())
    }

    /// Sign the canonical-JSON serialization of `payload`.
    /// Returns base64-encoded 64-byte compact ECDSA signature.
    pub fn sign(&self, payload: &serde_json::Value) -> String {
        let canonical = canonical_json::to_bytes(payload);
        let digest: [u8; 32] = Sha256::digest(&canonical).into();
        let msg = Message::from_digest(digest);
        let sig = self.secp.sign_ecdsa(&msg, &self.secret);
        B64.encode(sig.serialize_compact())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::{SignedPayload, Verifier};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn signer_output_verifies_against_its_own_pubkey() {
        let signer = Signer::generate();
        let v = Verifier::new(&signer.public_key_hex(), 60, 16).unwrap();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let payload = json!({ "prompt": "x", "nonce": "unique", "timestamp": ts });
        let signature = signer.sign(&payload);
        assert!(v.verify(&SignedPayload { payload, signature }).is_ok());
    }
}
