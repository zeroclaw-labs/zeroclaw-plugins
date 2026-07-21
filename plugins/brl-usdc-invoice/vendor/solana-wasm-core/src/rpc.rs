//! Minimal Solana JSON-RPC client surface for invoice status checks.
//!
//! Transport is injected via [`HttpTransport`] so host tests can mock HTTP
//! and WASM plugins can plug in `waki` (or similar) without this crate
//! depending on any network stack.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;

/// Transport error for JSON-RPC calls.
#[derive(Debug, Clone)]
pub struct RpcError {
    pub message: String,
}

impl RpcError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rpc error: {}", self.message)
    }
}

impl std::error::Error for RpcError {}

/// Pluggable HTTP POST JSON transport.
pub trait HttpTransport {
    fn post_json(&self, url: &str, body: &Value) -> Result<Value, RpcError>;
}

/// Thin JSON-RPC 2.0 client.
pub struct RpcClient<T: HttpTransport> {
    pub endpoint: String,
    pub http: T,
}

impl<T: HttpTransport> RpcClient<T> {
    pub fn new(endpoint: impl Into<String>, http: T) -> Self {
        Self {
            endpoint: endpoint.into(),
            http,
        }
    }

    /// Call `getSignaturesForAddress` (JSON-RPC 2.0).
    pub fn get_signatures_for_address(
        &self,
        address: &str,
        limit: u64,
    ) -> Result<Vec<SignatureInfo>, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": [
                address,
                {
                    "limit": limit
                }
            ]
        });

        let resp = self.http.post_json(&self.endpoint, &body)?;

        if let Some(err) = resp.get("error") {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown rpc error");
            return Err(RpcError::new(msg));
        }

        let result = resp
            .get("result")
            .ok_or_else(|| RpcError::new("missing result field"))?;

        let list = result
            .as_array()
            .ok_or_else(|| RpcError::new("result is not an array"))?;

        let mut out = Vec::with_capacity(list.len());
        for item in list {
            out.push(SignatureInfo::from_value(item)?);
        }
        Ok(out)
    }

    /// Call `getBalance` — returns lamports for a system account.
    pub fn get_balance(&self, address: &str) -> Result<u64, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [address]
        });
        let resp = self.http.post_json(&self.endpoint, &body)?;
        Self::rpc_result(&resp)?;
        resp.get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| RpcError::new("getBalance: missing result.value"))
    }

    /// Sum UI amounts of SPL token accounts for `owner` filtered by `mint`
    /// using `getTokenAccountsByOwner` + `jsonParsed`.
    pub fn get_token_ui_balance(&self, owner: &str, mint: &str) -> Result<String, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenAccountsByOwner",
            "params": [
                owner,
                { "mint": mint },
                { "encoding": "jsonParsed" }
            ]
        });
        let resp = self.http.post_json(&self.endpoint, &body)?;
        Self::rpc_result(&resp)?;
        let arr = resp
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcError::new("getTokenAccountsByOwner: missing result.value"))?;

        let mut total: f64 = 0.0;
        let mut found = false;
        for item in arr {
            if let Some(ui) = item
                .pointer("/account/data/parsed/info/tokenAmount/uiAmount")
                .and_then(|v| v.as_f64())
            {
                total += ui;
                found = true;
            } else if let Some(s) = item
                .pointer("/account/data/parsed/info/tokenAmount/uiAmountString")
                .and_then(|v| v.as_str())
            {
                if let Ok(x) = s.parse::<f64>() {
                    total += x;
                    found = true;
                }
            }
        }
        if !found {
            return Ok("0".to_string());
        }
        // Trim trailing zeros for display
        let s = format!("{total:.6}");
        Ok(trim_trailing_zeros(&s))
    }

    /// Call `getTransaction` with `jsonParsed` and extract the net amount of
    /// `usdc_mint` tokens **received by `merchant`** in that transaction.
    ///
    /// Uses `meta.preTokenBalances` / `meta.postTokenBalances` (owner + mint
    /// filtered), so both `transfer` and `transferChecked` are covered without
    /// parsing instructions. `delta = post − pre`.
    ///
    /// Returns:
    /// - `Ok(Some(ReceivedAmount))` when the transaction + `meta` are present
    ///   (even if the computed delta is `0.0`).
    /// - `Ok(None)` when the RPC returned no transaction (`result` null) or the
    ///   `meta` block is absent — i.e. the value cannot be verified. Callers
    ///   must degrade honestly and never report PAID in that case.
    /// - `Err(RpcError)` on a transport / JSON-RPC error.
    pub fn get_transaction(
        &self,
        signature: &str,
        usdc_mint: &str,
        merchant: &str,
    ) -> Result<Option<ReceivedAmount>, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                {
                    "encoding": "jsonParsed",
                    "maxSupportedTransactionVersion": 0
                }
            ]
        });
        let resp = self.http.post_json(&self.endpoint, &body)?;
        Self::rpc_result(&resp)?;

        let result = match resp.get("result") {
            Some(r) if !r.is_null() => r,
            _ => return Ok(None), // transaction not found / not confirmed
        };
        let meta = match result.get("meta") {
            Some(m) if !m.is_null() => m,
            _ => return Ok(None), // no meta → cannot verify value honestly
        };

        let pre = sum_owner_mint(meta.get("preTokenBalances"), usdc_mint, merchant);
        let post = sum_owner_mint(meta.get("postTokenBalances"), usdc_mint, merchant);
        let ui_amount = post - pre;

        let block_time = result.get("blockTime").and_then(|t| t.as_i64());
        let slot = result.get("slot").and_then(|s| s.as_u64());
        let decimals = meta
            .get("postTokenBalances")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|b| {
                    let m = b.get("mint").and_then(|v| v.as_str());
                    if m == Some(usdc_mint) {
                        b.pointer("/uiTokenAmount/decimals")
                            .and_then(|v| v.as_u64())
                            .map(|d| d as u8)
                    } else {
                        None
                    }
                })
            });

        Ok(Some(ReceivedAmount {
            ui_amount,
            block_time,
            slot,
            decimals,
        }))
    }

    fn rpc_result(resp: &Value) -> Result<(), RpcError> {
        if let Some(err) = resp.get("error") {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown rpc error");
            return Err(RpcError::new(msg));
        }
        Ok(())
    }
}

/// Net token amount received by an owner in a single transaction.
///
/// `ui_amount` is `postTokenBalances − preTokenBalances` (owner + mint
/// filtered). A value `<= 0.0` means the owner received nothing for that mint.
#[derive(Debug, Clone, PartialEq)]
pub struct ReceivedAmount {
    /// Net UI amount (human units) received by the owner for the mint.
    pub ui_amount: f64,
    /// Block time (unix seconds) from the transaction, if available.
    pub block_time: Option<i64>,
    /// Slot of the transaction, if available.
    pub slot: Option<u64>,
    /// Token decimals for the mint, if reported.
    pub decimals: Option<u8>,
}

/// Sum `uiTokenAmount` UI values for entries matching `mint` **and** `owner`.
///
/// Defensive: accepts `uiAmount` (number, may be null) or `uiAmountString`
/// (decimal string). Missing / unparseable entries contribute `0.0`.
fn sum_owner_mint(balances: Option<&Value>, mint: &str, owner: &str) -> f64 {
    let arr = match balances.and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return 0.0,
    };
    let mut total = 0.0_f64;
    for b in arr {
        let m = b.get("mint").and_then(|v| v.as_str());
        let o = b.get("owner").and_then(|v| v.as_str());
        if m != Some(mint) || o != Some(owner) {
            continue;
        }
        if let Some(ui) = b
            .pointer("/uiTokenAmount/uiAmount")
            .and_then(|v| v.as_f64())
        {
            total += ui;
        } else if let Some(s) = b
            .pointer("/uiTokenAmount/uiAmountString")
            .and_then(|v| v.as_str())
        {
            if let Ok(x) = s.parse::<f64>() {
                total += x;
            }
        }
    }
    total
}

fn trim_trailing_zeros(s: &str) -> String {
    if !s.contains('.') {
        return s.to_string();
    }
    let t = s.trim_end_matches('0').trim_end_matches('.');
    if t.is_empty() {
        "0".into()
    } else {
        t.to_string()
    }
}

/// Compact signature info returned by `getSignaturesForAddress`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureInfo {
    pub signature: String,
    pub slot: u64,
    pub err: Option<Value>,
    pub memo: Option<String>,
    pub block_time: Option<i64>,
    pub confirmation_status: Option<String>,
}

impl SignatureInfo {
    fn from_value(v: &Value) -> Result<Self, RpcError> {
        let signature = v
            .get("signature")
            .and_then(|s| s.as_str())
            .ok_or_else(|| RpcError::new("signature missing"))?
            .to_string();
        let slot = v
            .get("slot")
            .and_then(|s| s.as_u64())
            .ok_or_else(|| RpcError::new("slot missing"))?;
        let err = v.get("err").cloned().filter(|e| !e.is_null());
        let memo = v
            .get("memo")
            .and_then(|m| if m.is_null() { None } else { m.as_str().map(|s| s.to_string()) });
        let block_time = v.get("blockTime").and_then(|t| t.as_i64());
        let confirmation_status = v
            .get("confirmationStatus")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());

        Ok(Self {
            signature,
            slot,
            err,
            memo,
            block_time,
            confirmation_status,
        })
    }

    /// True when the transaction succeeded (err is null / absent).
    pub fn is_success(&self) -> bool {
        self.err.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockHttp {
        response: RefCell<Value>,
        last_body: RefCell<Option<Value>>,
    }

    impl HttpTransport for MockHttp {
        fn post_json(&self, _url: &str, body: &Value) -> Result<Value, RpcError> {
            *self.last_body.borrow_mut() = Some(body.clone());
            Ok(self.response.borrow().clone())
        }
    }

    #[test]
    fn get_signatures_parses_result() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [
                {
                    "signature": "Sig111",
                    "slot": 42,
                    "err": null,
                    "memo": "PIX|BRL|inv-001|x",
                    "blockTime": 1_700_000_000,
                    "confirmationStatus": "finalized"
                }
            ]
        });
        let http = MockHttp {
            response: RefCell::new(response),
            last_body: RefCell::new(None),
        };
        let client = RpcClient::new("https://api.mainnet-beta.solana.com", http);
        let sigs = client
            .get_signatures_for_address("SomeRef111111111111111111111111111", 5)
            .unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].signature, "Sig111");
        assert!(sigs[0].is_success());
        assert_eq!(sigs[0].memo.as_deref(), Some("PIX|BRL|inv-001|x"));

        let body = client.http.last_body.borrow().clone().unwrap();
        assert_eq!(body["method"], "getSignaturesForAddress");
        assert_eq!(body["params"][1]["limit"], 5);
    }

    fn tx_client(result: Value) -> RpcClient<MockHttp> {
        let response = json!({ "jsonrpc": "2.0", "id": 1, "result": result });
        let http = MockHttp {
            response: RefCell::new(response),
            last_body: RefCell::new(None),
        };
        RpcClient::new("http://localhost", http)
    }

    const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const MERCHANT: &str = "MerchantOwner1111111111111111111111111111111";

    fn bal(mint: &str, owner: &str, ui: f64) -> Value {
        json!({
            "accountIndex": 1,
            "mint": mint,
            "owner": owner,
            "uiTokenAmount": {
                "amount": format!("{}", (ui * 1_000_000.0) as u64),
                "decimals": 6,
                "uiAmount": ui,
                "uiAmountString": format!("{ui}")
            }
        })
    }

    #[test]
    fn get_transaction_extracts_delta() {
        let result = json!({
            "blockTime": 1_700_000_000,
            "slot": 99,
            "meta": {
                "err": null,
                "preTokenBalances": [ bal(MINT, MERCHANT, 5.0) ],
                "postTokenBalances": [ bal(MINT, MERCHANT, 32.27) ]
            }
        });
        let client = tx_client(result);
        let got = client.get_transaction("Sig", MINT, MERCHANT).unwrap().unwrap();
        assert!((got.ui_amount - 27.27).abs() < 1e-9, "delta={}", got.ui_amount);
        assert_eq!(got.block_time, Some(1_700_000_000));
        assert_eq!(got.decimals, Some(6));

        let body = client.http.last_body.borrow().clone().unwrap();
        assert_eq!(body["method"], "getTransaction");
        assert_eq!(body["params"][1]["encoding"], "jsonParsed");
        assert_eq!(body["params"][1]["maxSupportedTransactionVersion"], 0);
    }

    #[test]
    fn get_transaction_account_created_this_tx() {
        // No pre-balance for the merchant (ATA created in this tx) → delta = post.
        let result = json!({
            "blockTime": 1,
            "meta": {
                "preTokenBalances": [],
                "postTokenBalances": [ bal(MINT, MERCHANT, 90.0) ]
            }
        });
        let client = tx_client(result);
        let got = client.get_transaction("Sig", MINT, MERCHANT).unwrap().unwrap();
        assert!((got.ui_amount - 90.0).abs() < 1e-9);
    }

    #[test]
    fn get_transaction_other_mint_does_not_count() {
        let result = json!({
            "meta": {
                "preTokenBalances": [],
                "postTokenBalances": [ bal("SomeOtherMint111", MERCHANT, 90.0) ]
            }
        });
        let client = tx_client(result);
        let got = client.get_transaction("Sig", MINT, MERCHANT).unwrap().unwrap();
        assert_eq!(got.ui_amount, 0.0);
    }

    #[test]
    fn get_transaction_wrong_owner_does_not_count() {
        let result = json!({
            "meta": {
                "preTokenBalances": [],
                "postTokenBalances": [ bal(MINT, "SomeoneElse111", 90.0) ]
            }
        });
        let client = tx_client(result);
        let got = client.get_transaction("Sig", MINT, MERCHANT).unwrap().unwrap();
        assert_eq!(got.ui_amount, 0.0);
    }

    #[test]
    fn get_transaction_missing_meta_returns_none() {
        let result = json!({ "blockTime": 1, "slot": 5 });
        let client = tx_client(result);
        assert_eq!(client.get_transaction("Sig", MINT, MERCHANT).unwrap(), None);
    }

    #[test]
    fn get_transaction_null_result_returns_none() {
        let client = tx_client(Value::Null);
        assert_eq!(client.get_transaction("Sig", MINT, MERCHANT).unwrap(), None);
    }

    #[test]
    fn get_transaction_parses_ui_amount_string_when_uiamount_null() {
        let result = json!({
            "meta": {
                "preTokenBalances": [],
                "postTokenBalances": [{
                    "mint": MINT,
                    "owner": MERCHANT,
                    "uiTokenAmount": {
                        "amount": "90000000",
                        "decimals": 6,
                        "uiAmount": null,
                        "uiAmountString": "90"
                    }
                }]
            }
        });
        let client = tx_client(result);
        let got = client.get_transaction("Sig", MINT, MERCHANT).unwrap().unwrap();
        assert!((got.ui_amount - 90.0).abs() < 1e-9);
    }

    #[test]
    fn rpc_error_propagates() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32600, "message": "Invalid Request" }
        });
        let http = MockHttp {
            response: RefCell::new(response),
            last_body: RefCell::new(None),
        };
        let client = RpcClient::new("http://localhost", http);
        let err = client.get_signatures_for_address("x", 1).unwrap_err();
        assert!(err.message.contains("Invalid Request"));
    }
}
