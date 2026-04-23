//! End-to-end test of the Python client ↔ Rust server wire contract.
//!
//! Boots the server binary in stub mode (`LLM_STUB=1`), generates a
//! keypair, shells out to `python-client/sign_request.py` to sign and
//! POST a request, and verifies the server's response signature
//! directly (independent of the `Verifier` type — the response payload
//! has a different shape than the request `Payload` struct).
//!
//! Skips gracefully if `python3` or `coincurve` is unavailable so the
//! test suite still passes on bare CI runners.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use gated_inference::canonical_json;
use secp256k1::{ecdsa::Signature, rand::rngs::OsRng, Keypair, Message, PublicKey, Secp256k1};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn have_python_with_coincurve() -> bool {
    Command::new("python3")
        .args(["-c", "import coincurve, requests"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn pick_free_port() -> u16 {
    // Bind to an OS-assigned port, then drop the listener so the
    // server can grab it. Racy in theory; fine in practice for tests.
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    l.local_addr().unwrap().port()
}

fn wait_for_tcp(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// RAII server handle: kills the child on drop so a failing assert
/// can't leak the process.
struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn python_client_roundtrip_with_stub_backend() {
    if !have_python_with_coincurve() {
        eprintln!("skipping: python3 with `coincurve` + `requests` not available");
        return;
    }

    // Fresh keypair — the hex goes to both the server (AUTHORIZED_PUBKEY)
    // and the Python client (--privkey-hex).
    let secp = Secp256k1::new();
    let kp = Keypair::new(&secp, &mut OsRng);
    let privkey_hex = hex::encode(kp.secret_key().secret_bytes());
    let pubkey_hex = hex::encode(kp.public_key().serialize());

    let port = pick_free_port();
    let bin = env!("CARGO_BIN_EXE_gated-inference-server");
    let child = Command::new(bin)
        .env("AUTHORIZED_PUBKEY", &pubkey_hex)
        .env("LLM_STUB", "1")
        .env("PORT", port.to_string())
        // Keep logs off stderr so a failing test's panic message isn't buried.
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server binary");
    let _guard = ServerGuard(child);

    assert!(
        wait_for_tcp(port, Duration::from_secs(10)),
        "server did not start listening on port {port} within 10s"
    );

    // Sanity-check /health before we drive /generate.
    let health = http_get_json(port, "/health").expect("GET /health");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["authorized_pubkey"], pubkey_hex);

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let script: PathBuf = [manifest_dir, "python-client", "sign_request.py"]
        .iter()
        .collect();
    let url = format!("http://127.0.0.1:{port}/generate");
    let prompt = "hello from interop test";

    let out = Command::new("python3")
        .arg(&script)
        .args(["--privkey-hex", &privkey_hex])
        .args(["--prompt", prompt])
        .args(["--url", &url])
        .output()
        .expect("run python client");

    assert!(
        out.status.success(),
        "python client exited non-zero: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let resp: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "client stdout is not JSON ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    });

    // The stub deterministically echoes the prompt with a marker prefix.
    let output = resp["result"]["output"].as_str().expect("result.output");
    assert_eq!(output, format!("[stub] {prompt}"));

    // Echoed-back request bookkeeping.
    assert_eq!(
        resp["result"]["prompt_length"]
            .as_u64()
            .expect("prompt_length"),
        prompt.len() as u64
    );

    // Verify the server's response signature offline using nothing but
    // canonical JSON + ECDSA — the exact flow an archived blob would use.
    let server_pub_hex = resp["public_key"].as_str().expect("public_key");
    let sig_b64 = resp["signature"].as_str().expect("signature");
    assert_eq!(resp["algorithm"], "ecdsa-secp256k1");

    let pub_bytes = hex::decode(server_pub_hex).expect("decode server pubkey hex");
    let server_pub = PublicKey::from_slice(&pub_bytes).expect("parse server pubkey");
    let sig_bytes = B64.decode(sig_b64).expect("decode signature base64");
    let sig = Signature::from_compact(&sig_bytes).expect("parse compact signature");
    let canonical = canonical_json::to_bytes(&resp["result"]);
    let digest: [u8; 32] = Sha256::digest(&canonical).into();
    let msg = Message::from_digest(digest);
    Secp256k1::verification_only()
        .verify_ecdsa(&msg, &sig, &server_pub)
        .expect("server response signature must verify under /pubkey");
}

/// Minimal blocking HTTP/1.0 GET — avoids pulling reqwest into dev-deps
/// for a single status+JSON probe.
fn http_get_json(port: u16, path: &str) -> anyhow::Result<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let sep = b"\r\n\r\n";
    let body_start = buf
        .windows(sep.len())
        .position(|w| w == sep)
        .ok_or_else(|| anyhow::anyhow!("no HTTP header terminator"))?
        + sep.len();
    Ok(serde_json::from_slice(&buf[body_start..])?)
}
