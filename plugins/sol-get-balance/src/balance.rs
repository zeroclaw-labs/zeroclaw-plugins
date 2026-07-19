//! Pure logic for the `sol-get-balance` tool.
//!
//! Everything here — resolving config, validating a base58 pubkey, building the
//! JSON-RPC request, parsing the response, and formatting lamports as SOL — has
//! no wit-bindgen or wasm dependency, so it compiles and tests on the host with
//! a plain `cargo test`. The wasm component reuses the exact same functions
//! through `lib.rs`, keeping the component glue too thin to be wrong.

use std::collections::HashMap;

/// Public Solana mainnet-beta JSON-RPC endpoint, used when the operator has not
/// configured an override.
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// 1 SOL = 1_000_000_000 lamports.
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

/// Runtime configuration resolved from the plugin's own jailed config section.
pub struct BalanceConfig {
    /// JSON-RPC endpoint the tool POSTs to.
    pub rpc_url: String,
}

impl BalanceConfig {
    /// Build from the flat `string -> string` section the host injects. An
    /// absent, empty, or whitespace-only `rpc_url` falls back to the public
    /// mainnet endpoint, which is also exactly what an unprivileged plugin
    /// (no `config_read` permission) sees.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let rpc_url = section
            .get("rpc_url")
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        Self { rpc_url }
    }
}

/// Validate a base58-encoded Solana public key: it must decode cleanly to
/// exactly 32 bytes. Returns the trimmed, normalized address on success and a
/// human-readable reason on failure.
pub fn validate_pubkey(address: &str) -> Result<String, String> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err("address is empty".to_string());
    }
    let decoded = bs58::decode(trimmed)
        .into_vec()
        .map_err(|e| format!("address is not valid base58: {e}"))?;
    if decoded.len() != 32 {
        return Err(format!(
            "address must decode to 32 bytes, got {}",
            decoded.len()
        ));
    }
    Ok(trimmed.to_string())
}

/// Build the JSON-RPC 2.0 request body for `getBalance` against `address`.
/// The caller is expected to have validated the address already.
pub fn build_request_body(address: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address],
    })
    .to_string()
}

/// Parse a `getBalance` JSON-RPC response, returning the balance in lamports.
/// A JSON-RPC `error.message` is surfaced as `Err` so the caller can report it
/// to the model; a well-formed success returns `result.value`.
pub fn parse_balance_response(body: &str) -> Result<u64, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("RPC response is not valid JSON: {e}"))?;

    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown RPC error");
        return Err(format!("RPC error: {msg}"));
    }

    v.get("result")
        .and_then(|r| r.get("value"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "RPC response missing result.value".to_string())
}

/// Convert lamports to SOL as an `f64` (1 SOL = 1e9 lamports). Note that `sol`
/// is a display convenience: for balances above 2^53 lamports it is an
/// approximation, whereas the returned lamports value is always exact.
pub fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / LAMPORTS_PER_SOL as f64
}

/// Format a successful balance lookup as a compact JSON object string — the
/// `output` the tool hands back to the model. `lamports` is exact; `sol` is the
/// human-readable conversion.
pub fn format_output(address: &str, lamports: u64, rpc_url: &str) -> String {
    serde_json::json!({
        "address": address,
        "lamports": lamports,
        "sol": lamports_to_sol(lamports),
        "rpc_url": rpc_url,
    })
    .to_string()
}
