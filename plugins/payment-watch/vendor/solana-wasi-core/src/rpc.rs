//! JSON-RPC request builders and response parsers — pure functions over
//! `serde_json::Value`. The wasm shim does the actual HTTP via `waki`; tests
//! feed canned RPC fixtures. No network in this crate, ever.

use serde_json::{json, Value};

/// Build a JSON-RPC 2.0 request body.
pub fn rpc_request(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
}

pub fn get_latest_blockhash() -> Value {
    rpc_request("getLatestBlockhash", json!([{ "commitment": "confirmed" }]))
}

pub fn get_account_info_b64(pubkey: &str) -> Value {
    rpc_request(
        "getAccountInfo",
        json!([pubkey, { "encoding": "base64", "commitment": "confirmed" }]),
    )
}

pub fn get_token_decimals(mint: &str) -> Value {
    rpc_request(
        "getTokenSupply",
        json!([mint, { "commitment": "confirmed" }]),
    )
}

/// getSignaturesForAddress — used by payment-watch to scan recent activity.
pub fn get_signatures_for_address(address: &str, limit: u32) -> Value {
    rpc_request(
        "getSignaturesForAddress",
        json!([address, { "limit": limit, "commitment": "confirmed" }]),
    )
}

pub fn get_transaction(signature: &str) -> Value {
    rpc_request(
        "getTransaction",
        json!([signature, { "encoding": "jsonParsed", "commitment": "confirmed", "maxSupportedTransactionVersion": 0 }]),
    )
}

/// Extract `result` or surface the RPC error — fail closed on both transport
/// and application-level errors.
pub fn unwrap_result(response: &Value) -> Result<&Value, String> {
    if let Some(err) = response.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown RPC error");
        return Err(format!("RPC error: {msg}"));
    }
    response
        .get("result")
        .ok_or_else(|| "malformed RPC response: no result".to_string())
}

/// Parse `getLatestBlockhash` → 32-byte blockhash.
pub fn parse_latest_blockhash(response: &Value) -> Result<[u8; 32], String> {
    let result = unwrap_result(response)?;
    let hash_str = result
        .pointer("/value/blockhash")
        .and_then(Value::as_str)
        .ok_or("no blockhash in response")?;
    let bytes = bs58::decode(hash_str)
        .into_vec()
        .map_err(|e| format!("bad blockhash base58: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "blockhash is not 32 bytes".to_string())
}

/// Parse `getAccountInfo` (base64 encoding) → raw account data.
pub fn parse_account_data_b64(response: &Value) -> Result<String, String> {
    let result = unwrap_result(response)?;
    if result.get("value").map(Value::is_null).unwrap_or(true) {
        return Err("account not found".into());
    }
    result
        .pointer("/value/data/0")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "no base64 data in account response".to_string())
}

/// Parse `getTokenSupply` → decimals.
pub fn parse_decimals(response: &Value) -> Result<u8, String> {
    let result = unwrap_result(response)?;
    result
        .pointer("/value/decimals")
        .and_then(Value::as_u64)
        .map(|d| d as u8)
        .ok_or_else(|| "no decimals in response".to_string())
}

/// A single inbound token transfer observed on-chain.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedTransfer {
    pub signature: String,
    pub from: Option<String>,
    pub mint: String,
    /// UI amount string as reported by jsonParsed (e.g. "25.0").
    pub ui_amount: String,
    pub memo: Option<String>,
    pub slot: u64,
    pub err: bool,
}

/// Scan a `getTransaction` (jsonParsed) response for SPL token transfers into
/// `watched_ata` (or `watched_owner` via parsed info). Pure parser — feeds
/// payment-watch.
pub fn parse_inbound_transfers(
    tx_response: &Value,
    signature: &str,
    watched: &str,
) -> Result<Vec<ObservedTransfer>, String> {
    let result = unwrap_result(tx_response)?;
    if result.is_null() {
        return Err("transaction not found".into());
    }
    let err = !result
        .pointer("/meta/err")
        .map(Value::is_null)
        .unwrap_or(true);
    let slot = result.get("slot").and_then(Value::as_u64).unwrap_or(0);

    // memo: scan log messages for the memo program output
    let memo = result
        .pointer("/meta/logMessages")
        .and_then(Value::as_array)
        .and_then(|logs| {
            logs.iter().filter_map(Value::as_str).find_map(|l| {
                l.split("Program log: Memo").nth(1).map(|rest| {
                    rest.trim_start_matches(|c| c != '"')
                        .trim_matches('"')
                        .trim_start_matches("(len ")
                        .to_string()
                })
            })
        });

    let mut out = Vec::new();
    let empty = Vec::new();
    let instructions = result
        .pointer("/transaction/message/instructions")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let inner: Vec<&Value> = result
        .pointer("/meta/innerInstructions")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("instructions").and_then(Value::as_array))
                .flatten()
                .collect()
        })
        .unwrap_or_default();

    for ix in instructions.iter().chain(inner) {
        let parsed = match ix.pointer("/parsed") {
            Some(p) => p,
            None => continue,
        };
        let ix_type = parsed.get("type").and_then(Value::as_str).unwrap_or("");
        if ix_type != "transferChecked" && ix_type != "transfer" {
            continue;
        }
        let info = match parsed.get("info") {
            Some(i) => i,
            None => continue,
        };
        let dest = info
            .get("destination")
            .and_then(Value::as_str)
            .unwrap_or("");
        let dest_owner = info
            .pointer("/destinationOwner")
            .and_then(Value::as_str)
            .unwrap_or("");
        if dest != watched && dest_owner != watched {
            continue;
        }
        let ui_amount = info
            .pointer("/tokenAmount/uiAmountString")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                info.get("amount")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default();
        out.push(ObservedTransfer {
            signature: signature.to_string(),
            from: info
                .get("authority")
                .or_else(|| info.get("source"))
                .and_then(Value::as_str)
                .map(str::to_string),
            mint: info
                .get("mint")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            ui_amount,
            memo: memo.clone(),
            slot,
            err,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwrap_surfaces_rpc_error() {
        let resp =
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid pubkey"}});
        assert!(unwrap_result(&resp).unwrap_err().contains("invalid pubkey"));
    }

    #[test]
    fn parses_blockhash() {
        let resp = json!({"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},
            "value":{"blockhash":"11111111111111111111111111111111","lastValidBlockHeight":100}}});
        assert_eq!(parse_latest_blockhash(&resp).unwrap(), [0u8; 32]);
    }

    #[test]
    fn account_not_found_fails_closed() {
        let resp = json!({"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":null}});
        assert!(parse_account_data_b64(&resp).is_err());
    }

    #[test]
    fn parses_inbound_transfer_checked() {
        let resp = json!({"jsonrpc":"2.0","id":1,"result":{
        "slot": 12345,
        "meta": {"err": null, "logMessages": [], "innerInstructions": []},
        "transaction": {"message": {"instructions": [
            {"parsed": {"type": "transferChecked", "info": {
                "authority": "PayerOwner11111111111111111111111111111111",
                "destination": "WatchedAta111111111111111111111111111111111",
                "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "tokenAmount": {"uiAmountString": "25.0", "decimals": 6}
            }}}]}}}});
        let transfers = parse_inbound_transfers(
            &resp,
            "sig111",
            "WatchedAta111111111111111111111111111111111",
        )
        .unwrap();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].ui_amount, "25.0");
        assert!(!transfers[0].err);
    }

    #[test]
    fn ignores_transfers_to_other_accounts() {
        let resp = json!({"jsonrpc":"2.0","id":1,"result":{
        "slot": 1, "meta": {"err": null},
        "transaction": {"message": {"instructions": [
            {"parsed": {"type": "transferChecked", "info": {
                "destination": "SomeoneElse1111111111111111111111111111111",
                "mint": "m", "tokenAmount": {"uiAmountString": "1"}
            }}}]}}}});
        let transfers = parse_inbound_transfers(&resp, "s", "WatchedAta").unwrap();
        assert!(transfers.is_empty());
    }
}
