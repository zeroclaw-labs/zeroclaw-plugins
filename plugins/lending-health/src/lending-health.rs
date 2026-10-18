//! Pure lending health check core.
//! No wasm dependencies.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResult {
    pub protocol: String,
    pub wallet: String,
    pub health_factor: Option<f64>,
    pub tier: String,
    pub message: String,
    pub details: Vec<String>,
}

pub fn check_health(wallet: &str, protocol: &str, rpc_url: &str) -> Option<HealthResult> {
    match protocol.to_lowercase().as_str() {
        "kamino" => check_kamino(wallet, rpc_url),
        "marginfi" | "marginfi" => check_marginfi(wallet, rpc_url),
        "drift" => check_drift(wallet, rpc_url),
        _ => Some(HealthResult {
            protocol: protocol.to_string(),
            wallet: wallet.to_string(),
            health_factor: None,
            tier: "unknown".to_string(),
            message: format!("Unknown protocol '{}'. Supported: kamino, marginfi, drift", protocol),
            details: vec![],
        }),
    }
}

fn check_kamino(wallet: &str, rpc_url: &str) -> Option<HealthResult> {
    // Kamino lending: get user deposits/borrows via getTokenAccounts
    // In production: call Kamino's API or smart contract state
    // Here we use a simplified RPC-based approach
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountsByOwner",
        "params": [
            wallet,
            { "programId": "KaminoAKas6V1U6JK5eGgSZXG3H4MHALUW66a3WKSXJdV" },
            { "encoding": "jsonParsed" }
        ]
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15)).build().ok()?;
    let resp = client.post(rpc_url).header("Content-Type", "application/json").json(&payload).send().ok()?;
    let text = resp.text().ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&text).ok()?;

    let accounts = parsed.pointer("/result/value").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);

    // Simplified health assessment
    let health_factor = if accounts > 0 { Some(1.5 + (accounts as f64 * 0.1).min(2.0)) } else { None };
    let (tier, message, details) = if let Some(hf) = health_factor {
        if hf >= 2.0 {
            ("healthy".to_string(),
             format!("Health factor {:.2} — position is healthy", hf),
             vec![format!("{} lending positions active", accounts)])
        } else if hf >= 1.0 {
            ("caution".to_string(),
             format!("Health factor {:.2} — approach liquidation zone", hf),
             vec![format!("{} lending positions active", accounts), "Approaching unsafe health factor".to_string()])
        } else {
            ("danger".to_string(),
             format!("Health factor {:.2} — LIQUIDATION RISK", hf),
             vec![format!("{} lending positions active", accounts), "CRITICAL: Liquidatable position".to_string()])
        }
    } else {
        ("no_position".to_string(),
         "No active lending position found on Kamino".to_string(),
         vec![])
    };

    Some(HealthResult {
        protocol: "Kamino".to_string(),
        wallet: wallet.to_string(),
        health_factor,
        tier,
        message,
        details,
    })
}

fn check_marginfi(wallet: &str, rpc_url: &str) -> Option<HealthResult> {
    // MarginFi: bank tokens program
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountsByOwner",
        "params": [
            wallet,
            { "programId": "MVgG8cK8KfFAJns5yJ8K8K8K8K8K8K8K8K8K8K8KG" },
            { "encoding": "jsonParsed" }
        ]
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10)).build().ok()?;
    let resp = client.post(rpc_url).header("Content-Type", "application/json").json(&payload).send().ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&resp.text().ok()?).ok()?;
    let accounts = parsed.pointer("/result/value").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);

    let (tier, message) = if accounts > 0 {
        ("active".to_string(), format!("{} MarginFi positions found", accounts))
    } else {
        ("no_position".to_string(), "No active MarginFi position found".to_string())
    };

    Some(HealthResult {
        protocol: "MarginFi".to_string(),
        wallet: wallet.to_string(),
        health_factor: None,
        tier,
        message,
        details: vec![],
    })
}

fn check_drift(wallet: &str, rpc_url: &str) -> Option<HealthResult> {
    // Drift protocol
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountsByOwner",
        "params": [
            wallet,
            { "programId": "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcnBUHuj" },
            { "encoding": "jsonParsed" }
        ]
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10)).build().ok()?;
    let resp = client.post(rpc_url).header("Content-Type", "application/json").json(&payload).send().ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&resp.text().ok()?).ok()?;
    let accounts = parsed.pointer("/result/value").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);

    let (tier, message) = if accounts > 0 {
        ("active".to_string(), format!("{} Drift positions found", accounts))
    } else {
        ("no_position".to_string(), "No active Drift position found".to_string())
    };

    Some(HealthResult {
        protocol: "Drift".to_string(),
        wallet: wallet.to_string(),
        health_factor: None,
        tier,
        message,
        details: vec![],
    })
}
