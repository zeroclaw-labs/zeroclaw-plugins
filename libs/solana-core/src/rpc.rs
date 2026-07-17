//! Transport-agnostic JSON-RPC: build request bodies, parse response shapes.
//!
//! The core never talks to the network. The wasm shim performs the POST with
//! `waki`; host tests feed captured fixtures through the same parsers. Every
//! parser is strict and fails closed, and every shaping function keeps the
//! output small: the model needs 200 tokens, not the 40KB the RPC sent.

use serde::Deserialize;
use serde_json::json;

use crate::encoding::base64_decode;
use crate::pubkey::Pubkey;

/// Build a JSON-RPC 2.0 request body.
pub fn request_body(method: &str, params: serde_json::Value) -> String {
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string()
}

/// getAccountInfo with base64 encoding.
pub fn get_account_info(pubkey: &Pubkey) -> String {
    request_body(
        "getAccountInfo",
        json!([pubkey.to_base58(), { "encoding": "base64" }]),
    )
}

/// getSignaturesForAddress, optionally bounded by `until` (exclusive).
pub fn get_signatures_for_address(address: &Pubkey, limit: u16, until: Option<&str>) -> String {
    let mut opts = json!({ "limit": limit });
    if let Some(u) = until {
        opts["until"] = json!(u);
    }
    request_body(
        "getSignaturesForAddress",
        json!([address.to_base58(), opts]),
    )
}

/// getTransaction, jsonParsed, v0-capable.
pub fn get_transaction(signature: &str) -> String {
    request_body(
        "getTransaction",
        json!([signature, { "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0 }]),
    )
}

/// Error from RPC response parsing.
#[derive(Debug, PartialEq, Eq)]
pub enum RpcError {
    BadJson(String),
    RpcReturnedError(String),
    MissingField(&'static str),
    AccountNotFound,
    BadData(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::BadJson(e) => write!(f, "response is not valid JSON: {e}"),
            RpcError::RpcReturnedError(e) => write!(f, "rpc error: {e}"),
            RpcError::MissingField(x) => write!(f, "response missing field {x}"),
            RpcError::AccountNotFound => write!(f, "account not found"),
            RpcError::BadData(e) => write!(f, "bad account data: {e}"),
        }
    }
}

fn parse_envelope(raw: &str) -> Result<serde_json::Value, RpcError> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| RpcError::BadJson(e.to_string()))?;
    if let Some(err) = v.get("error") {
        return Err(RpcError::RpcReturnedError(err.to_string()));
    }
    v.get("result")
        .cloned()
        .ok_or(RpcError::MissingField("result"))
}

/// Parse a getAccountInfo response into (raw data bytes, owner). Fails on
/// null value (account missing) and on non-base64 payloads.
pub fn parse_account_info(raw: &str) -> Result<(Vec<u8>, Pubkey), RpcError> {
    let result = parse_envelope(raw)?;
    let value = result.get("value").ok_or(RpcError::MissingField("value"))?;
    if value.is_null() {
        return Err(RpcError::AccountNotFound);
    }
    let data_b64 = value
        .get("data")
        .and_then(|d| d.get(0))
        .and_then(|s| s.as_str())
        .ok_or(RpcError::MissingField("data[0]"))?;
    let data = base64_decode(data_b64).ok_or_else(|| RpcError::BadData("not base64".into()))?;
    let owner_str = value
        .get("owner")
        .and_then(|s| s.as_str())
        .ok_or(RpcError::MissingField("owner"))?;
    let owner = Pubkey::parse(owner_str).map_err(|e| RpcError::BadData(e.to_string()))?;
    Ok((data, owner))
}

/// Whether an account exists (getAccountInfo value != null).
pub fn parse_account_exists(raw: &str) -> Result<bool, RpcError> {
    match parse_account_info(raw) {
        Ok(_) => Ok(true),
        Err(RpcError::AccountNotFound) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Decimals of a mint from its raw 82+ byte account data (offset 44).
pub fn mint_decimals(data: &[u8]) -> Result<u8, RpcError> {
    if data.len() < 82 {
        return Err(RpcError::BadData(format!(
            "mint account is {} bytes, expected >= 82",
            data.len()
        )));
    }
    if data[45] != 1 {
        return Err(RpcError::BadData("mint is not initialized".into()));
    }
    Ok(data[44])
}

/// One signature entry from getSignaturesForAddress.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct SignatureEntry {
    pub signature: String,
    pub slot: u64,
    /// null err = success.
    pub err: Option<serde_json::Value>,
    #[serde(rename = "blockTime")]
    pub block_time: Option<i64>,
    #[serde(rename = "confirmationStatus")]
    pub confirmation_status: Option<String>,
}

/// Parse getSignaturesForAddress.
pub fn parse_signatures(raw: &str) -> Result<Vec<SignatureEntry>, RpcError> {
    let result = parse_envelope(raw)?;
    serde_json::from_value(result).map_err(|e| RpcError::BadJson(e.to_string()))
}

/// A token-balance delta extracted from a confirmed transaction.
#[derive(Debug, PartialEq, Eq)]
pub struct TokenDelta {
    pub owner: String,
    pub mint: String,
    /// Base units received (post - pre), positive only.
    pub received_base_units: u64,
    pub decimals: u8,
}

/// From a getTransaction (jsonParsed) response, compute the positive token
/// deltas per (owner, mint). Fails if the transaction errored.
pub fn parse_token_deltas(raw: &str) -> Result<Vec<TokenDelta>, RpcError> {
    let result = parse_envelope(raw)?;
    let meta = result.get("meta").ok_or(RpcError::MissingField("meta"))?;
    if !meta.get("err").map(|e| e.is_null()).unwrap_or(false) {
        return Err(RpcError::RpcReturnedError(format!(
            "transaction failed: {}",
            meta.get("err").unwrap_or(&serde_json::Value::Null)
        )));
    }
    #[derive(Deserialize)]
    struct Bal {
        owner: Option<String>,
        mint: String,
        #[serde(rename = "uiTokenAmount")]
        ui: UiAmt,
    }
    #[derive(Deserialize)]
    struct UiAmt {
        amount: String,
        decimals: u8,
    }
    let parse_bals = |key: &'static str| -> Result<Vec<Bal>, RpcError> {
        serde_json::from_value(meta.get(key).cloned().unwrap_or_else(|| json!([])))
            .map_err(|e| RpcError::BadJson(format!("{key}: {e}")))
    };
    let pre = parse_bals("preTokenBalances")?;
    let post = parse_bals("postTokenBalances")?;
    let mut deltas = Vec::new();
    for p in &post {
        let owner = p.owner.clone().unwrap_or_default();
        let pre_amt: u64 = pre
            .iter()
            .find(|b| b.owner.as_deref() == p.owner.as_deref() && b.mint == p.mint)
            .and_then(|b| b.ui.amount.parse().ok())
            .unwrap_or(0);
        let post_amt: u64 = p.ui.amount.parse().unwrap_or(0);
        if post_amt > pre_amt {
            deltas.push(TokenDelta {
                owner,
                mint: p.mint.clone(),
                received_base_units: post_amt - pre_amt,
                decimals: p.ui.decimals,
            });
        }
    }
    Ok(deltas)
}

/// Lamport delta for a wallet from pre/postBalances (native SOL payments).
pub fn parse_lamport_delta(raw: &str, account_keys_owner_index: usize) -> Result<i128, RpcError> {
    let result = parse_envelope(raw)?;
    let meta = result.get("meta").ok_or(RpcError::MissingField("meta"))?;
    let pre = meta
        .get("preBalances")
        .and_then(|v| v.get(account_keys_owner_index))
        .and_then(|v| v.as_u64())
        .ok_or(RpcError::MissingField("preBalances[i]"))?;
    let post = meta
        .get("postBalances")
        .and_then(|v| v.get(account_keys_owner_index))
        .and_then(|v| v.as_u64())
        .ok_or(RpcError::MissingField("postBalances[i]"))?;
    Ok(post as i128 - pre as i128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_request_bodies() {
        let b = get_account_info(&Pubkey([0; 32]));
        assert!(b.contains("\"getAccountInfo\"") && b.contains("base64"));
        let s = get_signatures_for_address(&Pubkey([0; 32]), 10, Some("sig"));
        assert!(s.contains("\"until\":\"sig\""));
        let t = get_transaction("abc");
        assert!(t.contains("maxSupportedTransactionVersion"));
    }

    #[test]
    fn parses_account_info() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"data":["AQID","base64"],"owner":"11111111111111111111111111111111","lamports":5,"executable":false,"rentEpoch":0,"space":3}}}"#;
        let (data, owner) = parse_account_info(raw).unwrap();
        assert_eq!(data, vec![1, 2, 3]);
        assert_eq!(owner.to_base58(), "11111111111111111111111111111111");
    }

    #[test]
    fn missing_account_fails_closed() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":null}}"#;
        assert_eq!(
            parse_account_info(raw).unwrap_err(),
            RpcError::AccountNotFound
        );
        assert!(!parse_account_exists(raw).unwrap());
    }

    #[test]
    fn rpc_error_surfaces() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad params"}}"#;
        assert!(matches!(
            parse_account_info(raw),
            Err(RpcError::RpcReturnedError(_))
        ));
    }

    #[test]
    fn parses_signatures() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"result":[{"signature":"s1","slot":5,"err":null,"memo":null,"blockTime":100,"confirmationStatus":"finalized"}]}"#;
        let sigs = parse_signatures(raw).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].signature, "s1");
        assert!(sigs[0].err.is_none());
    }

    #[test]
    fn token_deltas_from_transaction() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"result":{"meta":{"err":null,
            "preTokenBalances":[{"accountIndex":1,"mint":"M1","owner":"W1","uiTokenAmount":{"amount":"1000","decimals":6,"uiAmountString":"0.001"}}],
            "postTokenBalances":[{"accountIndex":1,"mint":"M1","owner":"W1","uiTokenAmount":{"amount":"26000","decimals":6,"uiAmountString":"0.026"}}]
        }}}"#;
        let deltas = parse_token_deltas(raw).unwrap();
        assert_eq!(
            deltas,
            vec![TokenDelta {
                owner: "W1".into(),
                mint: "M1".into(),
                received_base_units: 25_000,
                decimals: 6
            }]
        );
    }

    #[test]
    fn failed_transaction_rejected() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"result":{"meta":{"err":{"InstructionError":[0,"Custom"]},"preTokenBalances":[],"postTokenBalances":[]}}}"#;
        assert!(matches!(
            parse_token_deltas(raw),
            Err(RpcError::RpcReturnedError(_))
        ));
    }

    #[test]
    fn mint_decimals_parses() {
        let mut mint = vec![0u8; 82];
        mint[44] = 6;
        mint[45] = 1;
        assert_eq!(mint_decimals(&mint).unwrap(), 6);
        mint[45] = 0;
        assert!(mint_decimals(&mint).is_err());
        assert!(mint_decimals(&[0u8; 10]).is_err());
    }
}
