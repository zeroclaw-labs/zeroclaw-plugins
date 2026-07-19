//! Pure portfolio brief core.
//! Shapes large RPC responses into ~200 tokens for LLM consumption.
//! No wasm dependencies.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortfolioBrief {
    pub wallet: String,
    pub total_usd: Option<f64>,
    pub tokens: Vec<TokenEntry>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub mint: String,
    pub symbol: String,
    pub amount: f64,
    pub decimals: u8,
    pub usd_value: Option<f64>,
    pub price_24h_change: Option<f64>,
}

pub fn brief(wallet: &str, rpc_url: &str, price_api_url: &str) -> Option<PortfolioBrief> {
    let tokens = fetch_token_balances(wallet, rpc_url)?;
    let tokens_with_prices = enrich_with_prices(tokens, price_api_url);
    let total_usd: f64 = tokens_with_prices.iter().filter_map(|t| t.usd_value).sum();
    let summary = build_summary(&tokens_with_prices, total_usd);
    Some(PortfolioBrief {
        wallet: wallet.to_string(),
        total_usd: Some(total_usd),
        tokens: tokens_with_prices,
        summary,
    })
}

pub fn fetch_token_balances(wallet: &str, rpc_url: &str) -> Option<Vec<TokenEntry>> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountsByOwner",
        "params": [
            wallet,
            { "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" },
            { "encoding": "jsonParsed" }
        ]
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15)).build().ok()?;
    let resp = client.post(rpc_url).header("Content-Type", "application/json").json(&payload).send().ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&resp.text().ok()?).ok()?;
    let accounts = parsed.pointer("/result/value")?.as_array()?.clone();
    let mut tokens = Vec::new();
    for account in accounts {
        let mint = account.get("account")?.get("data")?.get("parsed")?.get("info")?.get("mint")?.as_str()?.to_string();
        let amount_str = account.get("account")?.get("data")?.get("parsed")?.get("info")?.get("tokenAmount")?.get("amount")?.as_str()?;
        let decimals = account.get("account")?.get("data")?.get("parsed")?.get("info")?.get("tokenAmount")?.get("decimals")?.as_u64()? as u8;
        let ui_amount = account.get("account")?.get("data")?.get("parsed")?.get("info")?.get("tokenAmount")?.get("uiAmount")?.as_f64().unwrap_or(0.0);
        if ui_amount > 0.0 {
            tokens.push(TokenEntry {
                mint: mint.clone(),
                symbol: short_symbol(&mint),
                amount: ui_amount,
                decimals,
                usd_value: None,
                price_24h_change: None,
            });
        }
    }
    Some(tokens)
}

fn enrich_with_prices(mut tokens: Vec<TokenEntry>, price_api_url: &str) -> Vec<TokenEntry> {
    if tokens.is_empty() { return tokens; }
    // Try Birdeye-style price API
    let mints: Vec<&str> = tokens.iter().map(|t| t.mint.as_str()).collect();
    let payload = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts",
        "params": [mints, { "encoding": "jsonParsed" }]
    });
    // For now, just return without prices if API not available
    // Real implementation would call Birdeye/Jupiter price API here
    let _ = price_api_url;
    tokens
}

fn short_symbol(mint: &str) -> String {
    // Well-known mints
    match mint {
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" => "USDC".to_string(),
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" => "USDT".to_string(),
        "So11111111111111111111111111111111111111112" => "SOL".to_string(),
        "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So" => "mSOL".to_string(),
        "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn" => "jitoSOL".to_string(),
        "7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs" => "EUTH".to_string(),
        _ => format!("{}...", &mint[..4]),
    }
}

fn build_summary(tokens: &[TokenEntry], total_usd: f64) -> String {
    if tokens.is_empty() {
        return "Portfolio is empty — no token balances found.".to_string();
    }
    let top = &tokens[..tokens.len().min(5)];
    let lines: Vec<String> = top.iter().map(|t| {
        let val = t.usd_value.map(|v| format!("${:.2}", v)).unwrap_or_else(|| format!("{:.4} {}", t.amount, t.symbol));
        format!("{}: {}", t.symbol, val)
    }).collect();
    format!(
        "Portfolio ({} tokens, ~${:.2} total): {}",
        tokens.len(), total_usd, lines.join(" | ")
    )
}
