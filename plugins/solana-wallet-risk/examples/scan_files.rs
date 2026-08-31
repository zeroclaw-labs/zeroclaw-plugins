//! Run the REAL scanning core against pre-fetched RPC JSON on files — no network,
//! no mocking of the logic. `demo.sh` curls a live Solana RPC into these files and
//! pipes them here, so you see the exact plugin verdict on a real wallet.
//!
//! Usage: scan_files <owner> <spl_accounts.json> <t22_accounts.json> <mints.json>
//!   mints.json: { "<mint>": <getAccountInfo response>, ... }

use serde_json::Value;
use solana_wallet_risk::handler;
use std::fs;

fn read(path: &str) -> Value {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: scan_files <owner> <spl.json> <t22.json> <mints.json>");
        std::process::exit(2);
    }
    let owner = a[1].clone();
    let spl = read(&a[2]);
    let t22 = read(&a[3]);
    let mints = read(&a[4]);

    // File-backed fetcher: serves the pre-fetched response per RPC call. This
    // reuses handler::run verbatim — the same path the wasm component executes.
    let fetch = move |_url: &str, method: &str, params: Value| -> Result<Value, String> {
        match method {
            "getTokenAccountsByOwner" => {
                let prog = params
                    .get(1)
                    .and_then(|p| p.get("programId"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("");
                if prog == handler::TOKEN_2022_PROGRAM {
                    if t22.is_null() { Err("not fetched".into()) } else { Ok(t22.clone()) }
                } else if spl.is_null() {
                    Err("not fetched".into())
                } else {
                    Ok(spl.clone())
                }
            }
            "getAccountInfo" => {
                let key = params.get(0).and_then(|x| x.as_str()).unwrap_or("");
                mints.get(key).cloned().ok_or_else(|| "mint not pre-fetched".to_string())
            }
            other => Err(format!("unexpected method {other}")),
        }
    };

    let input = serde_json::json!({ "owner": owner }).to_string();
    let (out, ok) = handler::run(&input, &fetch);
    let pretty = serde_json::from_str::<Value>(&out)
        .map(|v| serde_json::to_string_pretty(&v).unwrap())
        .unwrap_or(out);
    println!("{pretty}");
    if !ok {
        std::process::exit(1);
    }
}
