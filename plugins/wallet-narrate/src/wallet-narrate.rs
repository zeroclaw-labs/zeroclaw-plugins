//! Pure transaction narrative core.
//! No wasm dependencies — testable on host with `cargo test`.

use serde::{Deserialize, Serialize};

/// A human-readable transaction narrative
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Narrative {
    pub short: String,
    pub type_: String,
    pub parties: Vec<String>,
    pub direction: String,
}

#[derive(Debug, Clone)]
pub struct ParsedTx {
    pub tx_type: String,
    pub amount: Option<f64>,
    pub token: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub program: Option<String>,
}

pub fn narrate(signature: &str, rpc_url: &str) -> Option<Narrative> {
    let raw = fetch_transaction(signature, rpc_url)?;
    let parsed = parse_transaction(&raw)?;
    Some(build_narrative(&parsed))
}

pub fn narrate_address(address: &str, rpc_url: &str) -> Option<Narrative> {
    let sigs = fetch_signatures(address, rpc_url, 1)?;
    if sigs.is_empty() {
        return Some(Narrative {
            short: format!("No recent transactions found for {}...", &address[..8]),
            type_: "NONE".to_string(),
            parties: vec![],
            direction: "self".to_string(),
        });
    }
    narrate(&sigs[0], rpc_url)
}

fn fetch_transaction(sig: &str, rpc_url: &str) -> Option<serde_json::Value> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getTransaction",
        "params": [sig, { "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0 }]
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10)).build().ok()?;
    let resp = client.post(rpc_url).header("Content-Type", "application/json").json(&payload).send().ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&resp.text().ok()?).ok()?;
    parsed.get("result").cloned()
}

fn fetch_signatures(address: &str, rpc_url: &str, limit: usize) -> Option<Vec<String>> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getSignaturesForAddress",
        "params": [address, { "limit": limit, "commitment": "confirmed" }]
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10)).build().ok()?;
    let resp = client.post(rpc_url).header("Content-Type", "application/json").json(&payload).send().ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&resp.text().ok()?).ok()?;
    let sigs = parsed.get("result")?.as_array()?;
    Some(sigs.iter().filter_map(|s| s.get("signature")?.as_str().map(String::from)).collect())
}

fn parse_transaction(tx: &serde_json::Value) -> Option<ParsedTx> {
    let meta = tx.get("meta")?;
    let transaction = tx.get("transaction")?;
    let message = transaction.get("message")?;
    let logs = meta.get("logMessages")?.as_array()?;
    let log_strs: Vec<&str> = logs.iter().filter_map(|l| l.as_str()).collect();
    let tx_type = detect_tx_type(&log_strs);
    let (amount, token, from, to, program) = parse_instructions(message)?;
    Some(ParsedTx { tx_type, amount, token, from, to, program })
}

fn detect_tx_type(logs: &[&str]) -> String {
    let all = logs.join(" ");
    if all.contains("Swap") || all.contains("swap") || all.contains("jupiter") { "SWAP".to_string() }
    else if all.contains("Stake") || all.contains("stake") { "STAKE".to_string() }
    else if all.contains("NFT") || all.contains("Metaplex") { "NFT".to_string() }
    else if all.contains("burn") || all.contains("Burn") { "BURN".to_string() }
    else if all.contains("mint") || all.contains("Mint") { "MINT".to_string() }
    else if all.contains("Transfer") || all.contains("transfer") { "TRANSFER".to_string() }
    else { "UNKNOWN".to_string() }
}

fn parse_instructions(message: &serde_json::Value) -> Option<(Option<f64>, Option<String>, Option<String>, Option<String>, Option<String>)> {
    let instructions = message.get("instructions")?.as_array()?;
    for ix in instructions {
        let program_id = ix.get("programId")?.as_str()?;
        let parsed = ix.get("parsed")?;
        if program_id == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" {
            let ix_type = parsed.get("type")?.as_str()?;
            if ix_type == "transfer" || ix_type == "transferChecked" {
                let amount_str = parsed.get("info")?.get("amount")?.as_str()?;
                let decimals = parsed.get("info")?.get("decimals")?.as_u64().unwrap_or(6);
                let amount = amount_str.parse::<f64>().ok().map(|a| a / 10_f64.powi(decimals as i32));
                let token = parsed.get("info")?.get("mint")?.as_str().map(String::from);
                let from = parsed.get("info")?.get("source")?.as_str().map(String::from);
                let to = parsed.get("info")?.get("destination")?.as_str().map(String::from);
                return Some((amount, token, from, to, Some("SPL Token".to_string())));
            }
        }
        if program_id == "11111111111111111111111111111111" {
            let ix_type = parsed.get("type")?.as_str()?;
            if ix_type == "transfer" {
                let lamports = parsed.get("info")?.get("lamports")?.as_u64()?;
                let from = parsed.get("info")?.get("from")?.as_str().map(String::from);
                let to = parsed.get("info")?.get("to")?.as_str().map(String::from);
                let sol = lamports as f64 / 1_000_000_000.0;
                return Some((Some(sol), Some("SOL".to_string()), from, to, Some("System Program".to_string())));
            }
        }
    }
    Some((None, None, None, None, None))
}

fn build_narrative(tx: &ParsedTx) -> Narrative {
    let short = match tx.tx_type.as_str() {
        "TRANSFER" => {
            let amount = tx.amount.map(|a| format!("{:.4}", a)).unwrap_or_default();
            let token = tx.token.as_deref().unwrap_or("tokens");
            let from_s = tx.from.as_ref().map(|f| format!(" from {}", &f[..8])).unwrap_or_default();
            let to_s = tx.to.as_ref().map(|t| format!(" to {}", &t[..8])).unwrap_or_default();
            format!("Transferred {} {}{}{}", amount, token, from_s, to_s)
        }
        "SWAP" => {
            let amount = tx.amount.map(|a| format!("{:.4}", a)).unwrap_or_default();
            let token = tx.token.as_deref().unwrap_or("tokens");
            format!("Swapped {} {}", amount, token)
        }
        "STAKE" => {
            let amount = tx.amount.map(|a| format!("{:.4}", a)).unwrap_or_default();
            format!("Staked {} SOL", amount)
        }
        "BURN" => {
            let amount = tx.amount.map(|a| format!("{:.4}", a)).unwrap_or_default();
            let token = tx.token.as_deref().unwrap_or("tokens");
            format!("Burned {} {}", amount, token)
        }
        "NFT" => "NFT transfer".to_string(),
        "MINT" => {
            let amount = tx.amount.map(|a| format!("{:.2}", a)).unwrap_or_default();
            let token = tx.token.as_deref().unwrap_or("tokens");
            format!("Minted {} {}", amount, token)
        }
        _ => "Transaction executed".to_string(),
    };
    let direction = if tx.amount.map(|a| a > 0.0).unwrap_or(false) { "in".to_string() } else { "out".to_string() };
    let parties: Vec<String> = tx.from.iter().chain(tx.to.iter()).filter_map(|s| s.as_ref()).cloned().collect();
    Narrative { short, type_: tx.tx_type.clone(), parties, direction }
}
