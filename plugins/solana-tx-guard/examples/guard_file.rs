//! Guard a transaction using pre-fetched RPC responses — the REAL decode + verdict
//! + balance-delta core on real (or clearly-labeled constructed) chain data, no
//! mocking of the logic.
//!
//! Usage: guard_file <tx_base64> <simulateTransaction.json> [getMultipleAccounts.json]
//!
//! The third file is optional: when present, the guard computes the fee payer's
//! balance change (pre from getMultipleAccounts, post from the sim's `accounts`).
use serde_json::Value;
use solana_tx_guard::handler;
use std::fs;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: guard_file <tx_base64> <sim_response.json> [get_multiple_accounts.json]");
        std::process::exit(2);
    }
    let tx = a[1].clone();
    let sim: Value = serde_json::from_str(&fs::read_to_string(&a[2]).unwrap_or_default())
        .unwrap_or(Value::Null);
    let pre: Value = a
        .get(3)
        .map(|p| serde_json::from_str(&fs::read_to_string(p).unwrap_or_default()).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    // Route by method so the balance-delta path (getMultipleAccounts + simulate) is
    // exercised exactly as the wasm component runs it.
    let fetch = move |_u: &str, method: &str, _p: Value| -> Result<Value, String> {
        match method {
            "getMultipleAccounts" if !pre.is_null() => Ok(pre.clone()),
            "getMultipleAccounts" => Err("no pre-balance file provided".into()),
            _ => Ok(sim.clone()),
        }
    };
    let (out, ok) = handler::run(&serde_json::json!({ "transaction": tx }).to_string(), &fetch);
    let pretty = serde_json::from_str::<Value>(&out)
        .map(|v| serde_json::to_string_pretty(&v).unwrap())
        .unwrap_or(out);
    println!("{pretty}");
    std::process::exit(if ok { 0 } else { 1 });
}
