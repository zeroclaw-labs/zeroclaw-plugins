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

/// A shared reference to a transport is a transport, so a test can keep the
/// mock (and whatever it recorded) after handing it to a client.
impl<T: HttpTransport + ?Sized> HttpTransport for &T {
    fn post_json(&self, url: &str, body: &Value) -> Result<Value, RpcError> {
        (**self).post_json(url, body)
    }
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
    /// The delta is computed from `uiTokenAmount.amount` — the **integer string
    /// of minor units** — together with `uiTokenAmount.decimals`. `uiAmount` is
    /// a JSON double and is deliberately never read: this is the one number the
    /// whole product is about, so it is exact or it is not reported.
    ///
    /// Returns:
    /// - `Ok(Some(ReceivedAmount))` when the transaction + `meta` are present
    ///   and every matching balance entry could be read exactly (even if the
    ///   computed delta is `0`).
    /// - `Ok(None)` when the value cannot be verified: no transaction
    ///   (`result` null), no `meta`, an unreadable/absent `amount`, a missing
    ///   `decimals`, decimals disagreeing between entries of the same mint, or
    ///   an arithmetic overflow. Callers must degrade honestly and never report
    ///   PAID in that case.
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

        // A missing `pre` entry is normal: the ATA was created in this very
        // transaction, so the merchant had no prior balance.
        let pre = match sum_owner_mint_units(meta.get("preTokenBalances"), usdc_mint, merchant) {
            BalanceSum::Exact { units, decimals } => Some((units, decimals)),
            BalanceSum::NoMatch => None,
            BalanceSum::Unreadable => return Ok(None),
        };
        let post = match sum_owner_mint_units(meta.get("postTokenBalances"), usdc_mint, merchant) {
            BalanceSum::Exact { units, decimals } => Some((units, decimals)),
            BalanceSum::NoMatch => None,
            BalanceSum::Unreadable => return Ok(None),
        };

        // Decimals are a property of the mint, so both sides must agree.
        // Disagreement means the data cannot be trusted for a money verdict.
        let decimals = match (pre, post) {
            (Some((_, a)), Some((_, b))) if a != b => return Ok(None),
            (Some((_, d)), _) | (_, Some((_, d))) => d,
            // Nothing of this mint touched the merchant in this transaction:
            // a genuine zero. Decimals are irrelevant to "nothing arrived".
            (None, None) => 0,
        };

        // Only a positive delta is a receipt; an outgoing transfer in the same
        // transaction must neither go negative nor underflow.
        let received_units = post
            .map(|(u, _)| u)
            .unwrap_or(0)
            .saturating_sub(pre.map(|(u, _)| u).unwrap_or(0));

        let block_time = result.get("blockTime").and_then(|t| t.as_i64());
        let slot = result.get("slot").and_then(|s| s.as_u64());

        Ok(Some(ReceivedAmount {
            received_units,
            decimals,
            block_time,
            slot,
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

/// Net token amount received by an owner in a single transaction, **exact**.
///
/// `received_units` is `postTokenBalances − preTokenBalances` in minor units
/// (owner + mint filtered), saturating at zero. `0` means the owner received
/// nothing for that mint. Pair it with `decimals` to render or compare it —
/// see [`crate::amount::format_minor_units`] and
/// [`crate::amount::compare_units_to_decimal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedAmount {
    /// Net amount received by the owner for the mint, in minor units.
    pub received_units: u128,
    /// Token decimals for the mint, as reported by the RPC.
    pub decimals: u32,
    /// Block time (unix seconds) from the transaction, if available.
    pub block_time: Option<i64>,
    /// Slot of the transaction, if available.
    pub slot: Option<u64>,
}

/// Outcome of summing token balance entries for one mint + owner.
enum BalanceSum {
    /// Exact sum in minor units, at the decimals every matching entry agreed on.
    Exact { units: u128, decimals: u32 },
    /// No entry matched mint + owner at all — a structural zero.
    NoMatch,
    /// An entry matched but could not be read exactly — missing or malformed
    /// `amount`, missing `decimals`, decimals disagreeing between entries, or
    /// overflow. The caller must not build a verdict from this.
    Unreadable,
}

/// Read `uiTokenAmount.decimals` as a scale, rejecting absurd values.
fn json_decimals(v: &Value) -> Option<u32> {
    match v.as_u64() {
        Some(d) if d <= 32 => Some(d as u32),
        _ => None,
    }
}

/// Read an exact integer from a JSON value that is a decimal string (what the
/// RPC spec says `uiTokenAmount.amount` is) or a JSON integer (what some
/// providers send). Never a float — this is the number a payment verdict is
/// built from, so an unreadable value must be `None`, not a lossy guess.
fn json_units(v: &Value) -> Option<u128> {
    match v.as_str() {
        Some(s) => s.trim().parse::<u128>().ok(),
        None => v.as_u64().map(u128::from),
    }
}

/// Sum `uiTokenAmount.amount` (integer minor units) for entries matching `mint`
/// **and** `owner`.
///
/// Deliberately ignores `uiAmount` / `uiAmountString`: those are floating-point
/// renderings, and this sum decides whether a merchant gets told they were paid.
/// A matching entry that cannot be read exactly poisons the whole sum
/// ([`BalanceSum::Unreadable`]) rather than silently contributing zero — a
/// silent zero would understate what arrived and, worse, could be made to look
/// like an underpayment.
fn sum_owner_mint_units(balances: Option<&Value>, mint: &str, owner: &str) -> BalanceSum {
    let arr = match balances.and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return BalanceSum::NoMatch,
    };
    let mut total: u128 = 0;
    let mut decimals: Option<u32> = None;
    let mut matched = false;

    for b in arr {
        let m = b.get("mint").and_then(|v| v.as_str());
        let o = b.get("owner").and_then(|v| v.as_str());
        if m != Some(mint) || o != Some(owner) {
            continue;
        }
        matched = true;

        let raw_decimals = b.pointer("/uiTokenAmount/decimals");
        let d = match raw_decimals.and_then(json_decimals) {
            Some(d) => d,
            None => return BalanceSum::Unreadable,
        };
        match decimals {
            None => decimals = Some(d),
            Some(prev) if prev == d => {}
            Some(_) => return BalanceSum::Unreadable,
        }

        let raw_amount = b.pointer("/uiTokenAmount/amount");
        let units = match raw_amount.and_then(json_units) {
            Some(u) => u,
            None => return BalanceSum::Unreadable,
        };
        total = match total.checked_add(units) {
            Some(t) => t,
            None => return BalanceSum::Unreadable,
        };
    }

    match (matched, decimals) {
        (false, _) => BalanceSum::NoMatch,
        (true, Some(d)) => BalanceSum::Exact {
            units: total,
            decimals: d,
        },
        // Unreachable: a match always sets decimals or returns Unreadable.
        (true, None) => BalanceSum::Unreadable,
    }
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
        let memo = v.get("memo").and_then(|m| {
            if m.is_null() {
                None
            } else {
                m.as_str().map(|s| s.to_string())
            }
        });
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

    /// Balance entry from an exact minor-unit string (6 decimals, like USDC).
    fn bal_units(mint: &str, owner: &str, units: u128) -> Value {
        json!({
            "accountIndex": 1,
            "mint": mint,
            "owner": owner,
            "uiTokenAmount": {
                "amount": units.to_string(),
                "decimals": 6,
                "uiAmount": (units as f64) / 1_000_000.0,
                "uiAmountString": format!("{}", (units as f64) / 1_000_000.0)
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
                "preTokenBalances": [ bal_units(MINT, MERCHANT, 5_000_000) ],
                "postTokenBalances": [ bal_units(MINT, MERCHANT, 32_270_000) ]
            }
        });
        let client = tx_client(result);
        let got = client
            .get_transaction("Sig", MINT, MERCHANT)
            .unwrap()
            .unwrap();
        assert_eq!(got.received_units, 27_270_000);
        assert_eq!(got.decimals, 6);
        assert_eq!(got.block_time, Some(1_700_000_000));

        let body = client.http.last_body.borrow().clone().unwrap();
        assert_eq!(body["method"], "getTransaction");
        assert_eq!(body["params"][1]["encoding"], "jsonParsed");
        assert_eq!(body["params"][1]["maxSupportedTransactionVersion"], 0);
    }

    /// The delta is read from the integer `amount` string, so a value that no
    /// `f64` can hold exactly still comes out exact.
    #[test]
    fn get_transaction_delta_is_exact_not_float() {
        // 0.1 + 0.2 in USDC minor units: the classic float trap.
        let result = json!({
            "meta": {
                "preTokenBalances": [ bal_units(MINT, MERCHANT, 100_000) ],
                "postTokenBalances": [ bal_units(MINT, MERCHANT, 300_000) ]
            }
        });
        let client = tx_client(result);
        let got = client
            .get_transaction("Sig", MINT, MERCHANT)
            .unwrap()
            .unwrap();
        assert_eq!(got.received_units, 200_000);

        // A balance far beyond f64's 2^53 integer precision.
        let result = json!({
            "meta": {
                "preTokenBalances": [ bal_units(MINT, MERCHANT, 9_007_199_254_740_993) ],
                "postTokenBalances": [ bal_units(MINT, MERCHANT, 9_007_199_254_740_994) ]
            }
        });
        let client = tx_client(result);
        let got = client
            .get_transaction("Sig", MINT, MERCHANT)
            .unwrap()
            .unwrap();
        assert_eq!(got.received_units, 1);
    }

    #[test]
    fn get_transaction_account_created_this_tx() {
        // No pre-balance for the merchant (ATA created in this tx) → delta = post.
        let result = json!({
            "blockTime": 1,
            "meta": {
                "preTokenBalances": [],
                "postTokenBalances": [ bal_units(MINT, MERCHANT, 90_000_000) ]
            }
        });
        let client = tx_client(result);
        let got = client
            .get_transaction("Sig", MINT, MERCHANT)
            .unwrap()
            .unwrap();
        assert_eq!(got.received_units, 90_000_000);
        assert_eq!(got.decimals, 6);
    }

    #[test]
    fn get_transaction_other_mint_does_not_count() {
        let result = json!({
            "meta": {
                "preTokenBalances": [],
                "postTokenBalances": [ bal_units("SomeOtherMint111", MERCHANT, 90_000_000) ]
            }
        });
        let client = tx_client(result);
        let got = client
            .get_transaction("Sig", MINT, MERCHANT)
            .unwrap()
            .unwrap();
        assert_eq!(got.received_units, 0);
    }

    #[test]
    fn get_transaction_wrong_owner_does_not_count() {
        let result = json!({
            "meta": {
                "preTokenBalances": [],
                "postTokenBalances": [ bal_units(MINT, "SomeoneElse111", 90_000_000) ]
            }
        });
        let client = tx_client(result);
        let got = client
            .get_transaction("Sig", MINT, MERCHANT)
            .unwrap()
            .unwrap();
        assert_eq!(got.received_units, 0);
    }

    #[test]
    fn get_transaction_outgoing_transfer_does_not_underflow() {
        let result = json!({
            "meta": {
                "preTokenBalances": [ bal_units(MINT, MERCHANT, 90_000_000) ],
                "postTokenBalances": [ bal_units(MINT, MERCHANT, 10_000_000) ]
            }
        });
        let client = tx_client(result);
        let got = client
            .get_transaction("Sig", MINT, MERCHANT)
            .unwrap()
            .unwrap();
        assert_eq!(got.received_units, 0);
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

    /// `uiAmount` / `uiAmountString` are never read; the integer `amount` is.
    /// A null `uiAmount` is therefore irrelevant, and a *missing* `amount` on a
    /// matching entry makes the whole transaction unverifiable (never a silent
    /// zero, which would understate what arrived).
    #[test]
    fn get_transaction_ignores_ui_amount_and_needs_the_integer() {
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
        let got = client
            .get_transaction("Sig", MINT, MERCHANT)
            .unwrap()
            .unwrap();
        assert_eq!(got.received_units, 90_000_000);

        // Same entry with a bogus `uiAmount` and no `amount` → unverifiable.
        let result = json!({
            "meta": {
                "preTokenBalances": [],
                "postTokenBalances": [{
                    "mint": MINT,
                    "owner": MERCHANT,
                    "uiTokenAmount": { "decimals": 6, "uiAmount": 90.0 }
                }]
            }
        });
        let client = tx_client(result);
        assert_eq!(client.get_transaction("Sig", MINT, MERCHANT).unwrap(), None);
    }

    #[test]
    fn get_transaction_without_decimals_is_unverifiable() {
        let result = json!({
            "meta": {
                "preTokenBalances": [],
                "postTokenBalances": [{
                    "mint": MINT,
                    "owner": MERCHANT,
                    "uiTokenAmount": { "amount": "90000000", "uiAmount": 90.0 }
                }]
            }
        });
        let client = tx_client(result);
        assert_eq!(client.get_transaction("Sig", MINT, MERCHANT).unwrap(), None);
    }

    #[test]
    fn get_transaction_conflicting_decimals_is_unverifiable() {
        let mut post = bal_units(MINT, MERCHANT, 90_000_000);
        post["uiTokenAmount"]["decimals"] = json!(9);
        let result = json!({
            "meta": {
                "preTokenBalances": [ bal_units(MINT, MERCHANT, 1_000_000) ],
                "postTokenBalances": [ post ]
            }
        });
        let client = tx_client(result);
        assert_eq!(client.get_transaction("Sig", MINT, MERCHANT).unwrap(), None);
    }

    #[test]
    fn get_transaction_non_usdc_decimals_are_respected() {
        let entry = json!({
            "mint": MINT,
            "owner": MERCHANT,
            "uiTokenAmount": { "amount": "1500000000", "decimals": 9 }
        });
        let result = json!({
            "meta": { "preTokenBalances": [], "postTokenBalances": [ entry ] }
        });
        let client = tx_client(result);
        let got = client
            .get_transaction("Sig", MINT, MERCHANT)
            .unwrap()
            .unwrap();
        assert_eq!(got.received_units, 1_500_000_000);
        assert_eq!(got.decimals, 9);
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
