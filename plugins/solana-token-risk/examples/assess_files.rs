//! Run the REAL scoring core against pre-fetched RPC JSON on files — no network,
//! no mocking of the logic. `demo.sh` curls a live Solana RPC into these files and
//! pipes them here, so the judge sees the exact plugin verdict on real chain data.
//!
//! Usage: assess_files <mint> <getAccountInfo.json> [largest.json] [owners.json]
//!   owners.json (optional): {"<tokenAccountAddress>": <getAccountInfo response>, ...}
//!   so the live demo can resolve top-holder owners (LP vs wallet) with no network.

use solana_token_risk::handler;
use serde_json::Value;
use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: assess_files <mint> <account_info.json> [largest.json] [owners.json]");
        std::process::exit(2);
    }
    let mint = args[1].clone();
    let mint_for_input = mint.clone();
    let acct: Value = serde_json::from_str(&fs::read_to_string(&args[2]).expect("read account json"))
        .expect("parse account json");
    let largest: Value = if args.len() > 3 {
        serde_json::from_str(&fs::read_to_string(&args[3]).expect("read largest json"))
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    // Optional map of token-account -> its getAccountInfo response (for owners).
    let owners: Value = if args.len() > 4 {
        serde_json::from_str(&fs::read_to_string(&args[4]).unwrap_or_default()).unwrap_or(Value::Null)
    } else {
        Value::Null
    };

    // A file-backed fetcher: return the pre-fetched response per RPC call. This
    // reuses handler::run verbatim — the same path the wasm component executes.
    let fetch = move |_url: &str, method: &str, params: Value| -> Result<Value, String> {
        match method {
            "getAccountInfo" => {
                let first = params.get(0).and_then(|x| x.as_str()).unwrap_or("");
                if first == mint {
                    Ok(acct.clone())
                } else if let Some(resp) = owners.get(first) {
                    Ok(resp.clone())
                } else {
                    Err("owner not pre-fetched".into())
                }
            }
            "getTokenLargestAccounts" => {
                if largest.is_null() { Err("not provided".into()) } else { Ok(largest.clone()) }
            }
            other => Err(format!("unexpected method {other}")),
        }
    };

    let input = serde_json::json!({ "mint": mint_for_input }).to_string();
    let (out, ok) = handler::run(&input, &fetch);
    // Pretty-print for the demo.
    let pretty = serde_json::from_str::<Value>(&out)
        .map(|v| serde_json::to_string_pretty(&v).unwrap())
        .unwrap_or(out);
    println!("{pretty}");
    if !ok {
        std::process::exit(1);
    }
}
