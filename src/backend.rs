//! Inference backend: real llama.cpp, or a deterministic stub used by
//! integration tests that exercise the sign/verify/HTTP path without
//! needing a GGUF on disk.
//!
//! The stub branch is selected at startup via `LLM_STUB=1` in `main.rs`.

use crate::llama::LlamaSession;
use anyhow::Result;

pub enum Backend {
    Llama(LlamaSession),
    Stub,
}

impl Backend {
    pub fn generate(&self, prompt: &str) -> Result<String> {
        match self {
            Backend::Llama(s) => s.generate(prompt),
            Backend::Stub => Ok(format!("[stub] {prompt}")),
        }
    }
}
