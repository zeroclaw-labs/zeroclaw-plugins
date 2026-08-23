//! Developer helper: pipe a `getTransaction` JSON response to the pure narrator.

use std::io::{self, Read};

use wallet_activity_narrator::activity::summarize_transaction;

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let wallet = args
        .next()
        .ok_or_else(|| "usage: narrate_stdin <wallet> <signature>".to_string())?;
    let signature = args
        .next()
        .ok_or_else(|| "usage: narrate_stdin <wallet> <signature>".to_string())?;
    if args.next().is_some() {
        return Err("usage: narrate_stdin <wallet> <signature>".to_string());
    }

    let mut response = String::new();
    io::stdin()
        .read_to_string(&mut response)
        .map_err(|error| format!("read stdin: {error}"))?;
    if response.trim().is_empty() {
        response = std::env::var("TRANSACTION_JSON")
            .map_err(|_| "provide RPC JSON on stdin or in TRANSACTION_JSON".to_string())?;
    }
    let item = summarize_transaction(&wallet, &signature, &response)?
        .ok_or_else(|| "transaction is not available".to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&item)
            .map_err(|error| format!("serialize activity item: {error}"))?
    );
    Ok(())
}
