//! gated-inference server binary.
//!
//! Env vars:
//!   AUTHORIZED_PUBKEY   compressed SEC1 hex (66 chars). Required.
//!   LLM_MODEL_PATH      path to the GGUF file. Default: /models/main.gguf
//!   LLM_CTX             context size in tokens. Default: 4096
//!   LLM_MAX_TOKENS      max tokens to generate. Default: 256
//!   MAX_AGE_SECS        request-timestamp freshness window. Default: 60
//!   NONCE_CACHE_SIZE    in-memory LRU for replay protection. Default: 10000
//!   PORT                TCP port. Default: 8080
//!   RUST_LOG            tracing filter, e.g. "info,gated_inference=debug"

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use gated_inference::{
    llama::LlamaSession,
    verifier::{SignedPayload, VerifyError},
    Backend, Signer, Verifier,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tracing::{error, info};

struct AppState {
    verifier: Verifier,
    signer: Signer,
    backend: Mutex<Backend>,
    boot_time: i64,
}

fn env_required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing required env var: {name}"))
}

fn env_parsed<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let authorized_pubkey = env_required("AUTHORIZED_PUBKEY")?;
    let model_path: PathBuf = std::env::var("LLM_MODEL_PATH")
        .unwrap_or_else(|_| "/models/main.gguf".into())
        .into();
    let n_ctx: u32 = env_parsed("LLM_CTX", 4096);
    let max_tokens: u32 = env_parsed("LLM_MAX_TOKENS", 256);
    let max_age_secs: i64 = env_parsed("MAX_AGE_SECS", 60);
    let nonce_cache_size: usize = env_parsed("NONCE_CACHE_SIZE", 10_000);
    let port: u16 = env_parsed("PORT", 8080);

    let stub_mode = std::env::var("LLM_STUB").ok().as_deref() == Some("1");
    let backend = if stub_mode {
        info!("LLM_STUB=1 — skipping model load, using deterministic stub backend");
        Backend::Stub
    } else {
        info!(model = %model_path.display(), n_ctx, max_tokens, "loading LLM weights");
        let llama =
            LlamaSession::load(&model_path, n_ctx, max_tokens).context("loading llama model")?;
        info!("model loaded");
        Backend::Llama(llama)
    };

    let verifier = Verifier::new(&authorized_pubkey, max_age_secs, nonce_cache_size)
        .context("initializing verifier (check AUTHORIZED_PUBKEY format)")?;
    let signer = Signer::generate();
    let boot_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    info!(authorized_pubkey = %verifier.pubkey_hex(), "verifier initialized");
    info!(server_pubkey = %signer.public_key_hex(), "signer initialized");

    let state = Arc::new(AppState {
        verifier,
        signer,
        backend: Mutex::new(backend),
        boot_time,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/pubkey", get(pubkey))
        .route("/generate", post(generate))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, "listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(s): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "boot_time": s.boot_time,
        "authorized_pubkey": s.verifier.pubkey_hex(),
    }))
}

async fn pubkey(State(s): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "public_key": s.signer.public_key_hex(),
        "algorithm": "ecdsa-secp256k1",
        "boot_time": s.boot_time,
        "authorized_pubkey": s.verifier.pubkey_hex(),
    }))
}

#[derive(Serialize)]
struct GenerateResponse {
    result: Value,
    signature: String,
    public_key: String,
    algorithm: &'static str,
}

async fn generate(State(s): State<Arc<AppState>>, Json(signed): Json<SignedPayload>) -> Response {
    let payload = match s.verifier.verify(&signed) {
        Ok(p) => p,
        Err(e) => {
            let status = match e {
                VerifyError::BadSignature
                | VerifyError::StaleTimestamp { .. }
                | VerifyError::NonceReplay => StatusCode::UNAUTHORIZED,
                VerifyError::MalformedSignature(_) | VerifyError::MalformedPayload(_) => {
                    StatusCode::BAD_REQUEST
                }
            };
            return (status, Json(json!({ "error": e.to_string() }))).into_response();
        }
    };

    let t_llm = Instant::now();
    let output = match s.backend.lock().await.generate(&payload.prompt) {
        Ok(o) => o,
        Err(e) => {
            error!("backend generate failed: {e:#}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "inference failed" })),
            )
                .into_response();
        }
    };
    let llm_ms = t_llm.elapsed().as_millis() as u64;

    let prompt_sha256 = hex::encode(Sha256::digest(payload.prompt.as_bytes()));
    let output_sha256 = hex::encode(Sha256::digest(output.as_bytes()));
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let result = json!({
        "output": output,
        "prompt_sha256": prompt_sha256,
        "output_sha256": output_sha256,
        "prompt_length": payload.prompt.len(),
        "output_length": output.len(),
        "nonce": payload.nonce,
        "request_timestamp": payload.timestamp,
        "timestamp": timestamp,
        "boot_time": s.boot_time,
        "llm_duration_ms": llm_ms,
    });

    let signature = s.signer.sign(&result);
    Json(GenerateResponse {
        result,
        signature,
        public_key: s.signer.public_key_hex(),
        algorithm: "ecdsa-secp256k1",
    })
    .into_response()
}
