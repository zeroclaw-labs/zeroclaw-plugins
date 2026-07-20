//! JSON-RPC request builders + typed parsers. No I/O here beyond the trait.
use crate::{CoreError, HttpClient};
use serde_json::{json, Value};

pub fn get_latest_blockhash(http: &impl HttpClient, url: &str) -> Result<String, CoreError> {
    let result = call(
        http,
        url,
        "getLatestBlockhash",
        json!([{"commitment": "confirmed"}]),
    )?;
    result["value"]["blockhash"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| CoreError::Rpc("missing blockhash".into()))
}

pub fn get_balance_lamports(
    http: &impl HttpClient,
    url: &str,
    pubkey: &str,
) -> Result<u64, CoreError> {
    let result = call(http, url, "getBalance", json!([pubkey]))?;
    result["value"]
        .as_u64()
        .ok_or_else(|| CoreError::Rpc("missing balance".into()))
}

/// Build a JSON-RPC request, POST it over the seam, and return the `result`
/// value — mapping a JSON-RPC `error` object to `CoreError::Rpc`.
fn call(
    http: &impl HttpClient,
    url: &str,
    method: &str,
    params: Value,
) -> Result<Value, CoreError> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let resp = http.post_json(url, &body.to_string())?;
    let mut v: Value = serde_json::from_str(&resp).map_err(|e| CoreError::Parse(e.to_string()))?;
    if let Some(err) = v.get("error") {
        if !err.is_null() {
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown rpc error");
            return Err(CoreError::Rpc(msg.to_string()));
        }
    }
    Ok(v["result"].take())
}

/// One entry from `getSignaturesForAddress`. `err` is `true` when the tx
/// failed; `memo` carries the SPL-Memo text when present.
#[derive(Debug, Clone, PartialEq)]
pub struct SignatureInfo {
    pub signature: String,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub err: bool,
    pub memo: Option<String>,
}

/// Recent signatures for an address, newest first. Used to find the most
/// recent attestation (replay-nonce derivation) and reward activity.
pub fn get_signatures_for_address(
    http: &impl HttpClient,
    url: &str,
    pubkey: &str,
    limit: u32,
) -> Result<Vec<SignatureInfo>, CoreError> {
    let result = call(
        http,
        url,
        "getSignaturesForAddress",
        json!([pubkey, {"limit": limit, "commitment": "confirmed"}]),
    )?;
    let arr = result
        .as_array()
        .ok_or_else(|| CoreError::Rpc("expected array result".into()))?;
    Ok(arr
        .iter()
        .map(|e| SignatureInfo {
            signature: e["signature"].as_str().unwrap_or("").to_string(),
            slot: e["slot"].as_u64().unwrap_or(0),
            block_time: e["blockTime"].as_i64(),
            err: !e["err"].is_null(),
            memo: e["memo"].as_str().map(str::to_owned),
        })
        .collect())
}

/// A parsed SPL-token account balance (from `getTokenAccountsByOwner`,
/// `jsonParsed` encoding). Powers the rewards read.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenBalance {
    pub mint: String,
    pub amount_raw: u64,
    pub decimals: u8,
    pub ui_amount: f64,
}

/// Token accounts a wallet owns for a given mint, with parsed balances.
pub fn get_token_accounts_by_owner(
    http: &impl HttpClient,
    url: &str,
    owner: &str,
    mint: &str,
) -> Result<Vec<TokenBalance>, CoreError> {
    let result = call(
        http,
        url,
        "getTokenAccountsByOwner",
        json!([owner, {"mint": mint}, {"encoding": "jsonParsed", "commitment": "confirmed"}]),
    )?;
    let arr = result["value"]
        .as_array()
        .ok_or_else(|| CoreError::Rpc("expected value array".into()))?;
    arr.iter()
        .map(|e| {
            let info = &e["account"]["data"]["parsed"]["info"];
            let amount = &info["tokenAmount"];
            Ok(TokenBalance {
                mint: info["mint"].as_str().unwrap_or("").to_string(),
                amount_raw: amount["amount"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .ok_or_else(|| CoreError::Rpc("bad tokenAmount.amount".into()))?,
                decimals: amount["decimals"].as_u64().unwrap_or(0) as u8,
                ui_amount: amount["uiAmount"].as_f64().unwrap_or(0.0),
            })
        })
        .collect()
}

/// A confirmed transaction, reduced to what we need: slot, time, failure
/// flag, and the program log lines (where the SPL-Memo text shows up).
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionInfo {
    pub slot: u64,
    pub block_time: Option<i64>,
    pub err: bool,
    pub log_messages: Vec<String>,
}

/// Fetch a transaction by signature. Returns `Ok(None)` when it is not found
/// (RPC `result: null`).
pub fn get_transaction(
    http: &impl HttpClient,
    url: &str,
    signature: &str,
) -> Result<Option<TransactionInfo>, CoreError> {
    let result = call(
        http,
        url,
        "getTransaction",
        json!([signature, {"encoding": "json", "maxSupportedTransactionVersion": 0, "commitment": "confirmed"}]),
    )?;
    if result.is_null() {
        return Ok(None);
    }
    let meta = &result["meta"];
    let log_messages = meta["logMessages"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|l| l.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(TransactionInfo {
        slot: result["slot"].as_u64().unwrap_or(0),
        block_time: result["blockTime"].as_i64(),
        err: !meta["err"].is_null(),
        log_messages,
    }))
}

/// Pull the SPL-Memo text out of program logs. Memo logs look like:
/// `Program log: Memo (len 32): "the memo text"`. Returns the quoted text.
pub fn memo_from_logs(logs: &[String]) -> Option<String> {
    logs.iter().find(|l| l.contains("Memo (len")).and_then(|l| {
        let start = l.find('"')? + 1;
        let end = l.rfind('"')?;
        (end > start).then(|| l[start..end].to_string())
    })
}

/// An on-chain account, as returned by `getAccountInfo` (base64 encoding).
/// Used to read a durable-nonce account's stored blockhash.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountInfo {
    pub lamports: u64,
    pub owner: String,
    pub data_base64: String,
    pub executable: bool,
}

/// Fetch an account. Returns `Ok(None)` when the account does not exist
/// (RPC `value: null`).
pub fn get_account_info(
    http: &impl HttpClient,
    url: &str,
    pubkey: &str,
) -> Result<Option<AccountInfo>, CoreError> {
    let result = call(
        http,
        url,
        "getAccountInfo",
        json!([pubkey, {"encoding": "base64", "commitment": "confirmed"}]),
    )?;
    let value = &result["value"];
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(AccountInfo {
        lamports: value["lamports"]
            .as_u64()
            .ok_or_else(|| CoreError::Rpc("missing lamports".into()))?,
        owner: value["owner"]
            .as_str()
            .ok_or_else(|| CoreError::Rpc("missing owner".into()))?
            .to_string(),
        data_base64: value["data"][0].as_str().unwrap_or("").to_string(),
        executable: value["executable"].as_bool().unwrap_or(false),
    }))
}
