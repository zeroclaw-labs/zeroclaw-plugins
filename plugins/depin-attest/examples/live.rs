//! Host-side harness: run the exact attestation pipeline on saved RPC responses.
//!
//! Usage: cargo run --example live -- <device_pubkey> <signatures.json> <blockhash.json>
//!
//! Fetch the fixtures with curl so `cargo test` stays network-free, per the
//! same rule the sibling `token-risk-check` plugin follows:
//!
//!   curl -s -X POST "$RPC" -H 'Content-Type: application/json' \
//!     -d '{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash",
//!          "params":[{"commitment":"finalized"}]}' > blockhash.json
//!   curl -s -X POST "$RPC" -H 'Content-Type: application/json' \
//!     -d '{"jsonrpc":"2.0","id":1,"method":"getSignaturesForAddress",
//!          "params":["<device_pubkey>",{"limit":10}]}' > signatures.json
//!
//! This is what produces the transcript quoted in the README: real mainnet
//! responses through the real code path, rather than an illustrative sketch.

use serde_json::{json, Value};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, device, sigs_path, bh_path] = &args[..] else {
        eprintln!("usage: live <device_pubkey> <signatures.json> <blockhash.json>");
        std::process::exit(2);
    };
    let read = |p: &String| std::fs::read_to_string(p).expect("read fixture");
    let sigs = read(sigs_path);
    let bh = read(bh_path);

    // Transport stub: route by JSON-RPC method, exactly as the host would.
    let mut post = |_url: &str, body: &Value| -> Result<String, String> {
        match body.get("method").and_then(Value::as_str) {
            Some("getSignaturesForAddress") => Ok(sigs.clone()),
            Some("getLatestBlockhash") => Ok(bh.clone()),
            other => Err(format!("unexpected RPC method: {other:?}")),
        }
    };

    let args_json = json!({
        "metric": "temp_c",
        "value": 23.5,
        "__config": {
            "device_pubkey": device,
            "metrics": "temp_c:-40:85:C, humidity_pct:0:100:%",
            // The harness never contacts the network; the URL is only echoed
            // into the request the stub intercepts. Never put a real key here.
            "rpc_url": "https://example.invalid/rpc"
        }
    })
    .to_string();

    // Fixed timestamp so the transcript is reproducible from the same fixtures.
    let now_unix: u64 = std::env::var("ATTEST_TS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_785_000_000);

    match depin_attest::att::run(&args_json, &mut post, now_unix) {
        Ok(out) => println!("{out}"),
        Err(e) => {
            eprintln!("pipeline error: {e}");
            std::process::exit(1);
        }
    }
}
