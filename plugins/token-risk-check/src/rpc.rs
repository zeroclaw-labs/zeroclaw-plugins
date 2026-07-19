//! Pure JSON-RPC request building and response parsing for the three Solana
//! calls this tool makes. No transport here — the wasm shim owns HTTP, and
//! host tests feed canned JSON straight into the parsers.

use base64::Engine;
use serde_json::{json, Value};

/// The three RPC calls, in the order the shim performs them.
pub fn build_get_account_info(mint: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
        "params": [mint, {"encoding": "base64", "commitment": "confirmed"}]
    })
}

pub fn build_get_token_supply(mint: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 2, "method": "getTokenSupply",
        "params": [mint, {"commitment": "confirmed"}]
    })
}

pub fn build_get_token_largest_accounts(mint: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 3, "method": "getTokenLargestAccounts",
        "params": [mint, {"commitment": "confirmed"}]
    })
}

/// Pull `result` out of a JSON-RPC envelope, surfacing RPC-level errors.
fn unwrap_envelope(resp: &str) -> Result<Value, String> {
    let v: Value =
        serde_json::from_str(resp).map_err(|e| format!("RPC response is not JSON: {e}"))?;
    if let Some(err) = v.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown RPC error");
        return Err(format!("RPC error {code}: {msg}"));
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| "RPC response has neither result nor error".into())
}

/// getAccountInfo → (owner program id, raw account data).
/// `Ok(None)` means the account does not exist.
pub fn parse_account_info(resp: &str) -> Result<Option<(String, Vec<u8>)>, String> {
    let result = unwrap_envelope(resp)?;
    let value = result.get("value").ok_or("getAccountInfo missing value")?;
    if value.is_null() {
        return Ok(None);
    }
    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or("account missing owner")?
        .to_string();
    let data_b64 = value
        .get("data")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .ok_or("account missing base64 data")?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .map_err(|e| format!("account data is not valid base64: {e}"))?;
    Ok(Some((owner, data)))
}

/// getTokenSupply → (raw amount, decimals).
pub fn parse_token_supply(resp: &str) -> Result<(u128, u8), String> {
    let result = unwrap_envelope(resp)?;
    let value = result.get("value").ok_or("getTokenSupply missing value")?;
    let amount = value
        .get("amount")
        .and_then(Value::as_str)
        .ok_or("supply missing amount")?
        .parse::<u128>()
        .map_err(|e| format!("supply amount is not an integer: {e}"))?;
    let decimals = value
        .get("decimals")
        .and_then(Value::as_u64)
        .ok_or("supply missing decimals")? as u8;
    Ok((amount, decimals))
}

/// getTokenLargestAccounts → raw amounts, largest first.
pub fn parse_largest_amounts(resp: &str) -> Result<Vec<u128>, String> {
    let result = unwrap_envelope(resp)?;
    let list = result
        .get("value")
        .and_then(Value::as_array)
        .ok_or("getTokenLargestAccounts missing value list")?;
    let mut amounts = Vec::with_capacity(list.len());
    for entry in list {
        let amt = entry
            .get("amount")
            .and_then(Value::as_str)
            .ok_or("largest-accounts entry missing amount")?
            .parse::<u128>()
            .map_err(|e| format!("largest-accounts amount is not an integer: {e}"))?;
        amounts.push(amt);
    }
    amounts.sort_unstable_by(|a, b| b.cmp(a));
    Ok(amounts)
}
