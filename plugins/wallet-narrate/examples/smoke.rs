//! Dev-only smoke check: narrate a real wallet via the public RPC.
//! Not part of `cargo test` (tests are offline/mocked). Run:
//!   cargo run --example smoke -- <address>
use wallet_narrate::narrate::*;

fn rpc(url: &str, body: serde_json::Value) -> serde_json::Value {
    let out = std::process::Command::new("curl")
        .args(["-s", "-m", "20", "-H", "Content-Type: application/json", "-d", &body.to_string(), url])
        .output()
        .expect("curl");
    serde_json::from_slice(&out.stdout).expect("json")
}

fn main() {
    let addr = std::env::args().nth(1).expect("usage: smoke <address>");
    validate_address(&addr).expect("invalid address");
    let cfg = NarrateConfig::default();
    let sigs = rpc(&cfg.rpc_url, serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"getSignaturesForAddress","params":[addr, {"limit": 5}]
    }));
    let signatures = parse_signatures(&sigs);
    let mut narrations = Vec::new();
    for sig in signatures.iter().take(5) {
        let tx = rpc(&cfg.rpc_url, serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"getTransaction",
            "params":[sig, {"encoding":"jsonParsed","maxSupportedTransactionVersion":0}]
        }));
        if let Some(s) = narrate_transaction(&addr, &tx, &cfg) { narrations.push(s); }
    }
    println!("{}", compose_report(&addr, &narrations));
}
