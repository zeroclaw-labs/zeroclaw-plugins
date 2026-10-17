//! The only I/O-shaping module: builds every outbound [`HttpRequest`] the
//! guard pipeline issues and parses the handful of raw response shapes that
//! aren't already owned by `kamino.rs` (obligations/prices/reserve-metrics
//! parsing lives there; this module only shapes requests plus the two RPC
//! response bodies it alone issues).
//!
//! Closed endpoint set (safety invariant 2): every URL is built from
//! [`API_BASE`] or a caller-supplied `rpc_url` (already https-only
//! enforced by `config::Config::from_map`) — no other host string exists
//! anywhere in `src/`.
//!
//! Closed RPC method set: exactly `getGenesisHash` (cluster proof),
//! `getLatestBlockhash`, `getTokenAccountBalance`, and `getAccountInfo`
//! (durable-nonce account read) — all four read-only. No tx-submitting or
//! simulating RPC method name is ever spelled out anywhere in `src/` (not
//! even in a comment, so a grep for one can't false-positive on this
//! module's own docs) — broadcast is structurally impossible.
//!
//! No retry loop anywhere: [`check_response`] reports a non-200 once: the
//! caller decides what to do (typically give up on that call), never
//! retries here.

use crate::guard::{HttpRequest, HttpResponse, Method};

/// Base URL for every Kamino Lend REST call this plugin makes.
pub const API_BASE: &str = "https://api.kamino.finance";

/// Which read-only Kamino REST endpoint to call.
pub enum ApiCall<'a> {
    /// `GET /kamino-market/{market}/users/{wallet}/obligations`.
    Obligations { market: &'a str, wallet: &'a str },
    /// `GET /oracles/prices`.
    Prices,
    /// `GET /kamino-market/{market}/reserves/metrics`.
    ReservesMetrics { market: &'a str },
    /// `GET /kamino-market/reserves/account-data?markets={market}`.
    ReserveAccountData { market: &'a str },
}

/// Builds the `GET` request for a Kamino REST endpoint. Never fails: the
/// URL is always well-formed from [`API_BASE`] plus the caller-supplied
/// market/wallet strings (already base58-validated by `args::parse_call`).
pub fn api_request(c: &ApiCall) -> HttpRequest {
    let url = match c {
        ApiCall::Obligations { market, wallet } => {
            format!("{API_BASE}/kamino-market/{market}/users/{wallet}/obligations")
        }
        ApiCall::Prices => format!("{API_BASE}/oracles/prices"),
        ApiCall::ReservesMetrics { market } => {
            format!("{API_BASE}/kamino-market/{market}/reserves/metrics")
        }
        ApiCall::ReserveAccountData { market } => {
            format!("{API_BASE}/kamino-market/reserves/account-data?markets={market}")
        }
    };
    HttpRequest {
        method: Method::Get,
        url,
        body: None,
    }
}

/// Builds a `getGenesisHash` JSON-RPC request against `rpc_url`. Issued
/// once before any transaction build so the endpoint can prove which
/// cluster it serves; see `guard::MAINNET_GENESIS_HASH`.
pub fn rpc_get_genesis_hash(rpc_url: &str) -> HttpRequest {
    HttpRequest {
        method: Method::Post,
        url: rpc_url.to_string(),
        body: Some(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getGenesisHash"
            })
            .to_string(),
        ),
    }
}

/// Builds a `getLatestBlockhash` JSON-RPC request against `rpc_url` (the
/// config-validated, https-only endpoint — never model-supplied).
pub fn rpc_get_latest_blockhash(rpc_url: &str) -> HttpRequest {
    HttpRequest {
        method: Method::Post,
        url: rpc_url.to_string(),
        body: Some(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLatestBlockhash",
                "params": [{"commitment": "finalized"}]
            })
            .to_string(),
        ),
    }
}

/// Builds a `getTokenAccountBalance` JSON-RPC request for `ata` against
/// `rpc_url`. Used only for the optional wallet-balance repay cap — a
/// failed or skipped call never blocks the rescue pipeline.
pub fn rpc_get_token_account_balance(rpc_url: &str, ata: &str) -> HttpRequest {
    HttpRequest {
        method: Method::Post,
        url: rpc_url.to_string(),
        body: Some(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTokenAccountBalance",
                "params": [ata]
            })
            .to_string(),
        ),
    }
}

/// Builds a `getAccountInfo` JSON-RPC request for `pubkey` against
/// `rpc_url`, requesting base64-encoded account data. Used only to read the
/// opt-in durable-nonce account (`config::nonce_account`) — never to fetch
/// anything that could be broadcast.
pub fn rpc_get_account_info(rpc_url: &str, pubkey: &str) -> HttpRequest {
    HttpRequest {
        method: Method::Post,
        url: rpc_url.to_string(),
        body: Some(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": [pubkey, {"encoding": "base64"}]
            })
            .to_string(),
        ),
    }
}

/// Validates an [`HttpResponse`]: `Ok` with the body on `200`, a typed
/// `Err` naming the status on anything else (including `429`). Never
/// retries — the caller reports this once.
pub fn check_response(r: &HttpResponse) -> Result<&str, String> {
    if r.status == 200 {
        Ok(r.body.as_str())
    } else {
        Err(format!("HTTP {}", r.status))
    }
}

/// Parses a `getGenesisHash` JSON-RPC response body into the genesis hash
/// string (`result` is a bare base58 string, not an object). A JSON-RPC
/// `error` object or a malformed/missing result is a typed `Err` — the
/// caller refuses to build a transaction on anything but a proven match,
/// so an unreadable answer must never degrade to "assume mainnet".
pub fn parse_genesis_hash_response(body: &str) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid genesis hash response: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("getGenesisHash RPC error: {err}"));
    }
    v.get("result")
        .and_then(|r| r.as_str())
        .map(str::to_string)
        .ok_or_else(|| "malformed getGenesisHash response: missing result".to_string())
}

/// Parses a `getLatestBlockhash` JSON-RPC response body into the
/// blockhash string. A JSON-RPC `error` object (still HTTP 200) is a typed
/// `Err`, same as a malformed/missing result.
pub fn parse_blockhash_response(body: &str) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid blockhash response: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("getLatestBlockhash RPC error: {err}"));
    }
    v.get("result")
        .and_then(|r| r.get("value"))
        .and_then(|val| val.get("blockhash"))
        .and_then(|b| b.as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            "malformed getLatestBlockhash response: missing result.value.blockhash".to_string()
        })
}

/// Parses a `getAccountInfo` JSON-RPC response body (requested with
/// `base64` encoding) into `(owner, data)`: the account's owning program id
/// and its raw decoded bytes. A JSON-RPC `error` object, a null `result.
/// value` (account not found), or a malformed body is a typed `Err` — the
/// caller (the durable-nonce read path) treats every one of these as a hard
/// failure, never a silent fallback.
pub fn parse_account_info_response(body: &str) -> Result<(String, Vec<u8>), String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid account info response: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("getAccountInfo RPC error: {err}"));
    }
    let value = match v.get("result").and_then(|r| r.get("value")) {
        Some(val) if !val.is_null() => val,
        _ => return Err("account not found: getAccountInfo result.value is null".to_string()),
    };
    let owner = value
        .get("owner")
        .and_then(|o| o.as_str())
        .ok_or_else(|| "malformed getAccountInfo response: missing result.value.owner".to_string())?
        .to_string();
    let data_b64 = value
        .get("data")
        .and_then(|d| d.as_array())
        .and_then(|arr| arr.first())
        .and_then(|d0| d0.as_str())
        .ok_or_else(|| {
            "malformed getAccountInfo response: missing result.value.data[0]".to_string()
        })?;
    let data = crate::rescue::base64_decode(data_b64)?;
    Ok((owner, data))
}

/// Parses a `getTokenAccountBalance` JSON-RPC response body into the UI
/// (decimal) balance. A JSON-RPC `error` object, missing account (`result`
/// present but `value` null), or malformed body is a typed `Err` — the
/// caller treats this as "balance unknown", never as zero.
pub fn parse_token_balance_response(body: &str) -> Result<f64, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid token balance response: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("getTokenAccountBalance RPC error: {err}"));
    }
    let value = v
        .get("result")
        .and_then(|r| r.get("value"))
        .ok_or_else(|| {
            "malformed getTokenAccountBalance response: missing result.value".to_string()
        })?;
    if let Some(ui) = value.get("uiAmount").and_then(serde_json::Value::as_f64) {
        return Ok(ui);
    }
    let amount = value
        .get("amount")
        .and_then(|a| a.as_str())
        .ok_or_else(|| {
            "malformed getTokenAccountBalance response: missing value.amount".to_string()
        })?;
    let decimals = value
        .get("decimals")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            "malformed getTokenAccountBalance response: missing value.decimals".to_string()
        })?;
    let raw: f64 = amount
        .parse()
        .map_err(|_| format!("invalid `amount` value: {amount:?}"))?;
    Ok(raw / 10f64.powi(decimals as i32))
}
