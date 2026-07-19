//! Pure SNS/ANS resolution core.
//! No wasm dependencies.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionResult {
    pub name: String,
    pub address: Option<String>,
    pub found: bool,
    pub message: String,
}

/// Resolve a .sol domain via the Solana Name Service API.
pub fn resolve(name: &str, rpc_url: &str) -> ResolutionResult {
    let name = name.trim().to_lowercase();
    let name = name.strip_suffix(".sol").unwrap_or(&name);

    // Try resolving via get Solana domain
    if let Some(addr) = resolve_sns(&name, rpc_url) {
        return ResolutionResult {
            name: format!("{}.sol", name),
            address: Some(addr),
            found: true,
            message: format!("Resolved {}.sol to {}", name, &addr[..8]),
        };
    }

    ResolutionResult {
        name: format!("{}.sol", name),
        address: None,
        found: false,
        message: format!("Domain {}.sol not found or not registered", name),
    }
}

fn resolve_sns(name: &str, rpc_url: &str) -> Option<String> {
    // SNS uses a reverse lookup: hash(name) -> pubkey
    // The SNS API endpoint for resolution
    let url = format!("https://sns-api.bonfida.com/domains/{}", name);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10)).build().ok()?;
    let resp = client.get(&url)
        .header("Content-Type", "application/json")
        .send().ok()?;
    let text = resp.text().ok().unwrap_or_default();

    // Try to extract owner/address from the response
    let parsed: serde_json::Value = serde_json::from_str(&text).ok()?;
    let owner = parsed.get("owner")?.as_str()?;
    Some(owner.to_string())
}
