//! Host DePIN demo runner: attest (live RPC) → sign → submit → watch.
//!
//!   source demo/keys/env.sh
//!   cargo run --manifest-path demo/runner/Cargo.toml --release
//!   DEPIN_SUBMIT=1 cargo run --manifest-path demo/runner/Cargo.toml --release

use std::collections::HashMap;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use depin_attest::rpc::HttpClient as AttestHttp;
use depin_attest::{CoreError as AttestError, CoreResult as AttestResult};
use depin_uptime_watch::rpc::HttpClient as WatchHttp;
use depin_uptime_watch::{CoreError as WatchError, CoreResult as WatchResult};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

struct UreqHttp;

impl AttestHttp for UreqHttp {
    fn post_json(&self, url: &str, body: &Value) -> AttestResult<Value> {
        ureq_post(url, body).map_err(AttestError::msg)
    }
}

impl WatchHttp for UreqHttp {
    fn post_json(&self, url: &str, body: &Value) -> WatchResult<Value> {
        ureq_post(url, body).map_err(WatchError::msg)
    }
}

fn ureq_post(url: &str, body: &Value) -> Result<Value, String> {
    ureq::post(url)
        .set("Content-Type", "application/json")
        .send_json(body.clone())
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn require_env(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("missing env {key} — run: source demo/keys/env.sh"))
}

fn load_solana_keypair(path: &str) -> SigningKey {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let bytes: Vec<u8> =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse keypair json: {e}"));
    assert!(
        bytes.len() >= 32,
        "keypair file too short (need 64-byte solana keypair json)"
    );
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[..32]);
    SigningKey::from_bytes(&seed)
}

/// Legacy unsigned tx: compact-u16(1) + 64 zero bytes + message.
/// Replace the first signature slot with an ed25519 signature over the message.
fn sign_legacy_tx(unsigned: &[u8], key: &SigningKey) -> Vec<u8> {
    assert!(!unsigned.is_empty(), "empty tx");
    assert_eq!(unsigned[0], 1, "expected single-signature legacy tx");
    assert!(unsigned.len() > 1 + 64, "tx too short");
    let message = &unsigned[1 + 64..];
    let sig = key.sign(message);
    let mut out = unsigned.to_vec();
    out[1..1 + 64].copy_from_slice(&sig.to_bytes());
    out
}

fn send_transaction(rpc: &str, signed: &[u8]) -> Value {
    let b64 = Engine::encode(&base64::engine::general_purpose::STANDARD, signed);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendTransaction",
        "params": [b64, {"encoding": "base64", "preflightCommitment": "confirmed"}]
    });
    ureq_post(rpc, &body).expect("sendTransaction")
}

fn main() {
    let rpc = require_env("DEPIN_RPC_URL");
    let payer = require_env("DEPIN_PAYER");
    let nonce = require_env("DEPIN_NONCE_ACCOUNT");
    let keypair_path = env::var("DEPIN_PAYER_KEYPAIR").unwrap_or_default();
    let device = env::var("DEPIN_DEVICE_ID").unwrap_or_else(|_| "pi-greenhouse-7".into());
    let reading: f64 = env::var("DEPIN_READING")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(21.4);
    let do_submit = env::var("DEPIN_SUBMIT").ok().as_deref() == Some("1");

    let cfg = HashMap::from([
        ("rpc_url".into(), rpc.clone()),
        ("payer".into(), payer.clone()),
        ("nonce_account".into(), nonce),
        ("max_abs_reading".into(), "1000".into()),
        (
            "allowed_metrics".into(),
            "temperature,humidity,uptime,pressure,air_quality".into(),
        ),
    ]);

    let args = serde_json::json!({
        "device_id": device,
        "reading": reading,
        "unit": "celsius",
        "metric": "temperature"
    })
    .to_string();

    println!("== depin_attest (live RPC) ==");
    let out = depin_attest::attest::execute(&args, &cfg, &UreqHttp, now_unix())
        .unwrap_or_else(|e| panic!("attest failed: {e}"));
    println!("{}\n", out.summary);

    if do_submit {
        assert!(
            !keypair_path.is_empty(),
            "set DEPIN_PAYER_KEYPAIR for submit"
        );
        let key = load_solana_keypair(&keypair_path);
        let unsigned = Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &out.unsigned_tx_base64,
        )
        .expect("decode unsigned tx");
        let signed = sign_legacy_tx(&unsigned, &key);
        println!("== submit signed attestation ==");
        let resp = send_transaction(&rpc, &signed);
        println!("{resp}\n");
        if let Some(sig) = resp.get("result").and_then(Value::as_str) {
            println!("explorer: https://explorer.solana.com/tx/{sig}?cluster=devnet\n");
            // brief wait for indexing
            std::thread::sleep(std::time::Duration::from_secs(3));
        } else {
            eprintln!("submit did not return a signature — check RPC error above");
        }
    }

    println!("== depin_uptime_watch ==");
    let watch_cfg = HashMap::from([
        ("rpc_url".into(), rpc),
        ("payer".into(), payer),
        ("max_age_secs".into(), "3600".into()),
        ("memo_prefix".into(), "ZCDEPIN".into()),
        ("scan_limit".into(), "25".into()),
    ]);
    let watch_args = serde_json::json!({ "device_id": device }).to_string();
    match depin_uptime_watch::watch::execute(&watch_args, &watch_cfg, &UreqHttp, now_unix()) {
        Ok(w) => println!("{}", w.summary),
        Err(e) => println!("watch error: {e}"),
    }
}
