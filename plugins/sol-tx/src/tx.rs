//! Pure logic for the `sol-tx` tool.
//!
//! Everything here — resolving config, validating a base58 signature, building
//! the JSON-RPC requests, parsing the `getTransaction` response, and formatting
//! the result — has no wit-bindgen or wasm dependency, so it compiles and tests
//! on the host with a plain `cargo test`. The wasm component reuses the exact
//! same functions through `lib.rs`, keeping the component glue too thin to be
//! wrong.

use serde_json::Value;
use std::collections::HashMap;

/// Public Solana mainnet-beta JSON-RPC endpoint, used when the operator has not
/// configured an override.
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// 1 SOL = 1_000_000_000 lamports.
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

/// A Solana transaction signature is a 64-byte ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Runtime configuration resolved from the plugin's own jailed config section.
pub struct TxConfig {
    /// JSON-RPC endpoint the tool POSTs to.
    pub rpc_url: String,
}

impl TxConfig {
    /// Build from the flat `string -> string` section the host injects. An
    /// absent, empty, or whitespace-only `rpc_url` falls back to the public
    /// mainnet endpoint, which is also exactly what an unprivileged plugin (no
    /// `config_read` permission) sees.
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

/// Validate a base58-encoded transaction signature: it must decode cleanly to
/// exactly 64 bytes. Returns the trimmed, normalized signature on success and a
/// human-readable reason on failure.
pub fn validate_signature(signature: &str) -> Result<String, String> {
    let trimmed = signature.trim();
    if trimmed.is_empty() {
        return Err("signature is empty".to_string());
    }
    let decoded = bs58::decode(trimmed)
        .into_vec()
        .map_err(|e| format!("signature is not valid base58: {e}"))?;
    if decoded.len() != SIGNATURE_LEN {
        return Err(format!(
            "signature must decode to {SIGNATURE_LEN} bytes, got {}",
            decoded.len()
        ));
    }
    Ok(trimmed.to_string())
}

/// Build the JSON-RPC 2.0 request body for `getTransaction` against
/// `signature`, using `jsonParsed` encoding and `maxSupportedTransactionVersion:
/// 0` so versioned (v0) transactions are returned rather than erroring. The
/// caller is expected to have validated the signature already.
pub fn build_request_body(signature: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            { "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0 },
        ],
    })
    .to_string()
}

/// Build the JSON-RPC 2.0 request body for `getSignaturesForAddress`. Used only
/// by the live smoke test to discover a real, recent signature rather than
/// hardcoding one that may age out.
pub fn build_signatures_request(address: &str, limit: u32) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [address, { "limit": limit }],
    })
    .to_string()
}

/// Extract the first (most recent) signature from a `getSignaturesForAddress`
/// response. Returns `None` when the list is empty.
pub fn parse_first_signature(body: &str) -> Result<Option<String>, String> {
    let v: Value =
        serde_json::from_str(body).map_err(|e| format!("RPC response is not valid JSON: {e}"))?;
    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown RPC error");
        return Err(format!("RPC error: {msg}"));
    }
    Ok(v.get("result")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|e| e.get("signature"))
        .and_then(Value::as_str)
        .map(str::to_string))
}

/// A parsed, LLM-friendly view of a confirmed transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct TxSummary {
    pub signature: String,
    /// True when the transaction executed without error.
    pub success: bool,
    /// The raw JSON-encoded `meta.err` when the transaction failed, else `None`.
    pub err: Option<String>,
    pub slot: u64,
    /// Unix timestamp (seconds); `None` if the cluster has no block time.
    pub block_time: Option<i64>,
    /// Fee paid, in lamports.
    pub fee_lamports: u64,
    /// Transaction version: `Some(0)` for v0, `None` for legacy.
    pub version: Option<u64>,
    /// Account keys involved in the transaction, in order.
    pub account_keys: Vec<String>,
}

/// Outcome of parsing a `getTransaction` response.
#[derive(Debug, Clone, PartialEq)]
pub enum TxLookup {
    /// The transaction was found and decoded.
    Found(TxSummary),
    /// `result` was `null`: the signature is valid but the transaction is not
    /// found or not yet finalized on this endpoint.
    NotFound,
}

/// Parse a `getTransaction` (`jsonParsed`) response. A JSON-RPC `error.message`
/// is surfaced as `Err`; a `null` result maps to [`TxLookup::NotFound`]; a
/// well-formed result maps to [`TxLookup::Found`].
pub fn parse_tx_response(signature: &str, body: &str) -> Result<TxLookup, String> {
    let v: Value =
        serde_json::from_str(body).map_err(|e| format!("RPC response is not valid JSON: {e}"))?;

    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown RPC error");
        return Err(format!("RPC error: {msg}"));
    }

    let result = match v.get("result") {
        // `result: null` (or absent) => not found / not finalized.
        None | Some(Value::Null) => return Ok(TxLookup::NotFound),
        Some(r) => r,
    };

    let slot = result
        .get("slot")
        .and_then(Value::as_u64)
        .ok_or("transaction result missing slot")?;

    let block_time = result.get("blockTime").and_then(Value::as_i64);

    let version = result.get("version").and_then(Value::as_u64);

    let meta = result.get("meta");
    let err_value = meta.and_then(|m| m.get("err")).filter(|e| !e.is_null());
    let success = err_value.is_none();
    let err = err_value.map(|e| e.to_string());

    let fee_lamports = meta
        .and_then(|m| m.get("fee"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let account_keys = result
        .pointer("/transaction/message/accountKeys")
        .and_then(Value::as_array)
        .map(|keys| {
            keys.iter()
                .filter_map(|k| {
                    // jsonParsed gives objects ({pubkey, signer, ...}); legacy
                    // json gives bare strings. Handle both.
                    k.as_str()
                        .map(str::to_string)
                        .or_else(|| k.get("pubkey").and_then(Value::as_str).map(str::to_string))
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(TxLookup::Found(TxSummary {
        signature: signature.to_string(),
        success,
        err,
        slot,
        block_time,
        fee_lamports,
        version,
        account_keys,
    }))
}

/// Convert lamports to SOL as an `f64` (display convenience; lamports is exact).
pub fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / LAMPORTS_PER_SOL as f64
}

/// Format a lookup as a compact JSON object string — the `output` the tool
/// hands back to the model. A not-found signature returns `found: false` with a
/// clear message (a legitimate result, not an error).
pub fn format_output(lookup: &TxLookup, signature: &str, rpc_url: &str) -> String {
    match lookup {
        TxLookup::NotFound => serde_json::json!({
            "signature": signature,
            "found": false,
            "message": "transaction not found or not yet finalized on this RPC endpoint",
            "rpc_url": rpc_url,
        })
        .to_string(),
        TxLookup::Found(tx) => serde_json::json!({
            "signature": tx.signature,
            "found": true,
            "status": if tx.success { "success" } else { "failed" },
            "success": tx.success,
            "err": tx.err,
            "slot": tx.slot,
            "block_time": tx.block_time,
            "fee_lamports": tx.fee_lamports,
            "fee_sol": lamports_to_sol(tx.fee_lamports),
            "version": tx.version.map(Value::from).unwrap_or(Value::from("legacy")),
            "account_count": tx.account_keys.len(),
            "account_keys": tx.account_keys,
            "rpc_url": rpc_url,
        })
        .to_string(),
    }
}
