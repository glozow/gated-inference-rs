//! gated-inference — signature-gated LLM inference.
//!
//! Trust model: the server pins one authorized ECDSA-secp256k1 public key at
//! startup. Every `/generate` request must carry a payload signed by that key
//! over SHA256(canonical_json(payload)). The LLM is only invoked after the
//! signature, nonce (replay), and timestamp (freshness) checks pass.
//!
//! The server also signs its own response with a boot-time ephemeral ECDSA
//! keypair, so archived `(result, signature, public_key)` blobs can be
//! re-verified later without the server still being alive.

pub mod canonical_json;
pub mod llama;
pub mod signer;
pub mod verifier;

pub use signer::Signer;
pub use verifier::{Payload, SignedPayload, Verifier, VerifyError};
