
use serde_json::Value;

pub fn tx_to_sentence(wallet: &str, tx_raw: &str) -> String {
    let v: Value = match serde_json::from_str(tx_raw) {
        Ok(v) => v,
        Err(_) => return "Invalid transaction".to_string(),
    };

    if let Some(err) = v["result"]["meta"]["err"].as_object() {
        if !err.is_empty() {
            return "Failed transaction".to_string();
        }
    }

    let instructions = match v["result"]["transaction"]["message"]["instructions"].as_array() {
        Some(ixs) => ixs,
        None => return "Unknown transaction".to_string(),
    };

    for ix in instructions {
        let program = ix["program"].as_str().unwrap_or("");
        let ix_type = ix["parsed"]["type"].as_str().unwrap_or("");

        match (program, ix_type) {
            ("spl-token", "transfer") | ("spl-token", "transferChecked") => {
                let info = &ix["parsed"]["info"];
                let amount = info["tokenAmount"]["uiAmountString"]
                    .as_str()
                    .or_else(|| info["amount"].as_str())
                    .unwrap_or("?");
                let source = info["source"].as_str().unwrap_or("?");
                let dest = info["destination"].as_str().unwrap_or("?");
                let short_src = &source[..source.len().min(6)];
                let short_dst = &dest[..dest.len().min(6)];
                if source.starts_with(wallet) {
                    return format!("Sent {} tokens to {}...", amount, short_dst);
                } else {
                    return format!("Received {} tokens from {}...", amount, short_src);
                }
            }
            ("system", "transfer") => {
                let info = &ix["parsed"]["info"];
                let lamports = info["lamports"].as_u64().unwrap_or(0);
                let sol = lamports as f64 / 1_000_000_000.0;
                let source = info["source"].as_str().unwrap_or("?");
                let dest = info["destination"].as_str().unwrap_or("?");
                let short_src = &source[..source.len().min(6)];
                let short_dst = &dest[..dest.len().min(6)];
                if source == wallet {
                    return format!("Sent {:.4} SOL to {}...", sol, short_dst);
                } else {
                    return format!("Received {:.4} SOL from {}...", sol, short_src);
                }
            }
            _ => continue,
        }
    }

    "Complex transaction (swap or contract call)".to_string()
}

pub fn narrate(
    wallet: &str,
    sigs_raw: &str,
    get_tx: impl Fn(&str) -> Result<String, String>,
) -> Vec<String> {
    let v: Value = match serde_json::from_str(sigs_raw) {
        Ok(v) => v,
        Err(_) => return vec!["Failed to fetch signatures".to_string()],
    };

    let sigs = match v["result"].as_array() {
        Some(s) if !s.is_empty() => s,
        _ => return vec!["No recent transactions found".to_string()],
    };

    let mut out = Vec::new();
    for sig_obj in sigs.iter().take(5) {
        if let Some(sig) = sig_obj["signature"].as_str() {
            let sentence = match get_tx(sig) {
                Ok(raw) => tx_to_sentence(wallet, &raw),
                Err(_) => "Could not fetch transaction".to_string(),
            };
            out.push(sentence);
        }
    }

    if out.is_empty() {
        out.push("No transactions to narrate".to_string());
    }

    out
}
