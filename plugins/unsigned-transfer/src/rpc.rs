//! Minimal Solana JSON-RPC core over `wasi:http` (via the blocking `waki` client).
//!
//! The request-building and response-unwrapping helpers are pure and
//! native-testable; only [`call`] (the actual HTTP round-trip) is wasm-gated.
//! This is the shared substrate every read-tool in the toolbox reuses, with the
//! transport hardening applied ONCE here: HTTP status-code check before parse,
//! a connect timeout, and one consistent error convention. `waki` 0.5.1 does
//! not expose an overall/read timeout on its request builder.

use std::collections::HashMap;

use serde_json::{json, Value};

/// Public mainnet RPC used when the operator has not set `rpc_url` in config.
pub const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

/// Resolve the RPC endpoint from host-injected config, else the public default.
pub fn rpc_url(config: &HashMap<String, String>) -> String {
    config
        .get("rpc_url")
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| DEFAULT_RPC.to_string())
}

/// Build a JSON-RPC 2.0 request body. Pure.
pub fn body(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
}

/// Unwrap the `result` from a JSON-RPC response, surfacing any RPC-level error. Pure.
pub fn result(resp: &Value) -> Result<&Value, String> {
    if let Some(e) = resp.get("error") {
        return Err(format!("RPC error: {e}"));
    }
    resp.get("result")
        .ok_or_else(|| "malformed RPC response: no `result`".to_string())
}

/// wasm-only: POST a JSON-RPC call and return the parsed response `Value`.
/// Checks the HTTP status before parsing so a 429/5xx yields a clear message
/// instead of a misleading JSON-parse error.
#[cfg(target_family = "wasm")]
pub fn call(url: &str, method: &str, params: Value) -> Result<Value, String> {
    use std::time::Duration;

    let resp = waki::Client::new()
        .post(url)
        .json(&body(method, params))
        // `waki` 0.5.1 exposes only a connect timeout, not an overall/read timeout.
        .connect_timeout(Duration::from_secs(8))
        .send()
        .map_err(|e| format!("RPC request failed: {e}"))?;

    let status = resp.status_code();
    let bytes = resp.body().map_err(|e| format!("read RPC body: {e}"))?;
    if !(200..300).contains(&status) {
        let snippet: String = String::from_utf8_lossy(&bytes).chars().take(160).collect();
        return Err(format!("RPC HTTP {status}: {snippet}"));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("parse RPC JSON: {e}"))
}
