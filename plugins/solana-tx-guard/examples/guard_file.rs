//! Guard a transaction using a pre-fetched simulateTransaction response — the
//! REAL decode + verdict core on real chain data, no mocking of the logic.
//! Usage: guard_file <tx_base64> <sim_response.json>

use serde_json::Value;
use solana_tx_guard::handler;
use std::fs;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: guard_file <tx_base64> <sim_response.json>");
        std::process::exit(2);
    }
    let tx = a[1].clone();
    let sim: Value = serde_json::from_str(&fs::read_to_string(&a[2]).unwrap_or_default())
        .unwrap_or(Value::Null);
    let fetch = move |_u: &str, _m: &str, _p: Value| -> Result<Value, String> { Ok(sim.clone()) };
    let (out, ok) = handler::run(&serde_json::json!({ "transaction": tx }).to_string(), &fetch);
    let pretty = serde_json::from_str::<Value>(&out)
        .map(|v| serde_json::to_string_pretty(&v).unwrap())
        .unwrap_or(out);
    println!("{pretty}");
    std::process::exit(if ok { 0 } else { 1 });
}
