//! Thin wrapper over `llama-cpp-2` for text generation.
//!
//! Design notes:
//!   - The model (weights) is loaded once at process start — a missing/corrupt
//!     model fails container boot loudly, matching the reference Python service.
//!   - `generate()` takes `&self` and creates a fresh context per call; the
//!     caller is responsible for serialization (llama.cpp contexts are not
//!     thread-safe). `main.rs` holds a `tokio::sync::Mutex<LlamaSession>`.
//!   - Sampling is greedy for determinism in tests; swap for a temperature /
//!     top-k / top-p sampler once this is wired end-to-end.
//!
//! The `llama-cpp-2` crate's API is still pre-1.0 and shifts between minor
//! versions. The functions here follow the current shape; if a Nix build
//! surfaces API drift, the fixes are localized to this file.

use anyhow::{anyhow, Context, Result};
use llama_cpp_2::{
    context::params::LlamaContextParams,
    llama_backend::LlamaBackend,
    llama_batch::LlamaBatch,
    model::{params::LlamaModelParams, AddBos, LlamaModel, Special},
    token::data_array::LlamaTokenDataArray,
};
use std::num::NonZeroU32;
use std::path::Path;

pub struct LlamaSession {
    backend: LlamaBackend,
    model: LlamaModel,
    n_ctx: u32,
    max_tokens: u32,
}

impl LlamaSession {
    pub fn load(model_path: &Path, n_ctx: u32, max_tokens: u32) -> Result<Self> {
        if !model_path.exists() {
            return Err(anyhow!(
                "LLM_MODEL_PATH does not exist: {}",
                model_path.display()
            ));
        }
        let backend = LlamaBackend::init().context("llama backend init")?;
        let model_params = LlamaModelParams::default();
        let model = LlamaModel::load_from_file(&backend, model_path, &model_params)
            .context("load gguf model")?;
        Ok(Self {
            backend,
            model,
            n_ctx,
            max_tokens,
        })
    }

    pub fn generate(&self, prompt: &str) -> Result<String> {
        let ctx_params = LlamaContextParams::default().with_n_ctx(NonZeroU32::new(self.n_ctx));
        let mut ctx = self
            .model
            .new_context(&self.backend, ctx_params)
            .context("create llama context")?;

        let tokens = self
            .model
            .str_to_token(prompt, AddBos::Always)
            .context("tokenize prompt")?;

        let batch_cap = self.n_ctx.max(512) as usize;
        let mut batch = LlamaBatch::new(batch_cap, 1);
        let last_idx = tokens.len().saturating_sub(1);
        for (i, token) in tokens.iter().enumerate() {
            batch
                .add(*token, i as i32, &[0], i == last_idx)
                .context("batch.add prompt token")?;
        }
        ctx.decode(&mut batch).context("decode prompt")?;

        let mut out = String::new();
        let mut n_cur = tokens.len() as i32;
        let stop_at = n_cur + self.max_tokens as i32;

        while n_cur < stop_at {
            let candidates = ctx.candidates_ith(batch.n_tokens() - 1);
            let mut arr = LlamaTokenDataArray::from_iter(candidates, false);
            let token = ctx.sample_token_greedy(arr);

            if self.model.is_eog_token(token) {
                break;
            }

            let piece = self
                .model
                .token_to_str(token, Special::Tokenize)
                .context("detokenize")?;
            out.push_str(&piece);

            batch.clear();
            batch
                .add(token, n_cur, &[0], true)
                .context("batch.add next token")?;
            ctx.decode(&mut batch).context("decode next token")?;
            n_cur += 1;
        }

        Ok(out)
    }
}
