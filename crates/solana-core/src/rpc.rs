//! JSON-RPC client for a Solana node, over a swappable transport.
//!
//! The transport is a trait with one method, so the pure client logic (request
//! shaping, envelope parsing, typed returns) is fully host-testable against
//! [`MockTransport`] with no network and no wasm toolchain. The real
//! `waki`-backed transport lives in `transport.rs`, compiled only for wasm.

use serde_json::{json, Value};

use crate::error::{CoreError, Result};
use crate::pubkey::Pubkey;

/// Anything that can POST a JSON body to an RPC endpoint and return the body.
///
/// The transport owns its endpoint URL and performs TLS host-side (the ZeroClaw
/// host does TLS for `wasi:http`); the client never sees a socket.
pub trait RpcTransport {
    fn post_json(&self, body: &str) -> Result<String>;
}

/// A decoded account, as returned by `getAccountInfo` (base64 data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub lamports: u64,
    pub owner: Pubkey,
    pub data: Vec<u8>,
    pub executable: bool,
}

/// A token amount as the RPC reports it: raw integer string + decimals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiTokenAmount {
    /// Raw amount in base units, as a decimal string (may exceed u64 for supply).
    pub amount: String,
    pub decimals: u8,
}

/// One entry of `getTokenLargestAccounts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAccountBalance {
    pub address: Pubkey,
    pub amount: u128,
    pub decimals: u8,
}

/// Result of `getLatestBlockhash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestBlockhash {
    pub blockhash: String,
    pub last_valid_block_height: u64,
}

/// The RPC client. Generic over the transport so tests inject a mock.
pub struct SolanaRpc<T: RpcTransport> {
    transport: T,
    commitment: String,
    next_id: std::cell::Cell<u64>,
}

impl<T: RpcTransport> SolanaRpc<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            commitment: "confirmed".to_string(),
            next_id: std::cell::Cell::new(1),
        }
    }

    /// Override the commitment level (default `confirmed`).
    pub fn with_commitment(mut self, commitment: impl Into<String>) -> Self {
        self.commitment = commitment.into();
        self
    }

    /// Low-level: issue a method call, return the `result` value.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let body = self.transport.post_json(&req.to_string())?;
        let parsed: Value = serde_json::from_str(&body)
            .map_err(|e| CoreError::UnexpectedResponse(format!("not JSON: {e}")))?;
        if let Some(err) = parsed.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            return Err(CoreError::Rpc { code, message });
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| CoreError::UnexpectedResponse("missing `result`".into()))
    }

    /// `getAccountInfo` with base64 encoding. `None` if the account does not exist.
    pub fn get_account_info(&self, pubkey: &Pubkey) -> Result<Option<AccountInfo>> {
        let result = self.call(
            "getAccountInfo",
            json!([pubkey.to_base58(), {"encoding": "base64", "commitment": self.commitment}]),
        )?;
        let value = &result["value"];
        if value.is_null() {
            return Ok(None);
        }
        Ok(Some(parse_account_info(value)?))
    }

    /// `getBalance` in lamports.
    pub fn get_balance(&self, pubkey: &Pubkey) -> Result<u64> {
        let result = self.call(
            "getBalance",
            json!([pubkey.to_base58(), {"commitment": self.commitment}]),
        )?;
        result["value"]
            .as_u64()
            .ok_or_else(|| CoreError::UnexpectedResponse("getBalance value not a u64".into()))
    }

    /// `getTokenSupply`: total supply and decimals of a mint.
    pub fn get_token_supply(&self, mint: &Pubkey) -> Result<UiTokenAmount> {
        let result = self.call(
            "getTokenSupply",
            json!([mint.to_base58(), {"commitment": self.commitment}]),
        )?;
        parse_ui_token_amount(&result["value"])
    }

    /// `getTokenLargestAccounts`: up to 20 largest holders of a mint.
    pub fn get_token_largest_accounts(&self, mint: &Pubkey) -> Result<Vec<TokenAccountBalance>> {
        let result = self.call(
            "getTokenLargestAccounts",
            json!([mint.to_base58(), {"commitment": self.commitment}]),
        )?;
        let arr = result["value"]
            .as_array()
            .ok_or_else(|| CoreError::UnexpectedResponse("largestAccounts not an array".into()))?;
        let mut out = Vec::with_capacity(arr.len());
        for entry in arr {
            let address = entry["address"]
                .as_str()
                .ok_or_else(|| CoreError::UnexpectedResponse("missing address".into()))?;
            let amount_str = entry["amount"]
                .as_str()
                .ok_or_else(|| CoreError::UnexpectedResponse("missing amount".into()))?;
            let amount = amount_str
                .parse::<u128>()
                .map_err(|_| CoreError::UnexpectedResponse("amount not an integer".into()))?;
            let decimals = entry["decimals"].as_u64().unwrap_or(0) as u8;
            out.push(TokenAccountBalance {
                address: Pubkey::from_base58(address)?,
                amount,
                decimals,
            });
        }
        Ok(out)
    }

    /// `getLatestBlockhash` with its last-valid block height.
    pub fn get_latest_blockhash(&self) -> Result<LatestBlockhash> {
        let result = self.call(
            "getLatestBlockhash",
            json!([{"commitment": self.commitment}]),
        )?;
        let value = &result["value"];
        let blockhash = value["blockhash"]
            .as_str()
            .ok_or_else(|| CoreError::UnexpectedResponse("missing blockhash".into()))?
            .to_string();
        let last_valid_block_height = value["lastValidBlockHeight"].as_u64().unwrap_or(0);
        Ok(LatestBlockhash {
            blockhash,
            last_valid_block_height,
        })
    }
}

fn parse_account_info(value: &Value) -> Result<AccountInfo> {
    let lamports = value["lamports"].as_u64().unwrap_or(0);
    let owner = Pubkey::from_base58(
        value["owner"]
            .as_str()
            .ok_or_else(|| CoreError::UnexpectedResponse("missing owner".into()))?,
    )?;
    let executable = value["executable"].as_bool().unwrap_or(false);
    // data is ["<base64>", "base64"]
    let data_field = &value["data"];
    let data = match data_field {
        Value::Array(a) => {
            let encoded = a
                .first()
                .and_then(Value::as_str)
                .ok_or_else(|| CoreError::UnexpectedResponse("missing account data".into()))?;
            crate::base64::decode(encoded)?
        }
        // A node configured for jsonParsed on an unknown program returns an
        // object; we only ask for base64, but be defensive.
        _ => Vec::new(),
    };
    Ok(AccountInfo {
        lamports,
        owner,
        data,
        executable,
    })
}

fn parse_ui_token_amount(value: &Value) -> Result<UiTokenAmount> {
    let amount = value["amount"]
        .as_str()
        .ok_or_else(|| CoreError::UnexpectedResponse("missing token amount".into()))?
        .to_string();
    let decimals = value["decimals"].as_u64().unwrap_or(0) as u8;
    Ok(UiTokenAmount { amount, decimals })
}

/// An in-memory transport for host tests: returns canned response bodies in
/// order and records every request body it was handed. Available on all
/// targets so downstream plugins can reuse it in their own `cargo test`.
pub struct MockTransport {
    responses: std::cell::RefCell<std::collections::VecDeque<String>>,
    /// Request bodies seen, in order — assert against these to prove the client
    /// sent the method and params you expect.
    pub sent: std::cell::RefCell<Vec<String>>,
}

impl MockTransport {
    /// Raw response bodies, returned one per `post_json` call, in order.
    pub fn new(raw_responses: Vec<String>) -> Self {
        Self {
            responses: std::cell::RefCell::new(raw_responses.into_iter().collect()),
            sent: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Convenience: wrap each `result` value in a JSON-RPC success envelope.
    pub fn with_results(results: Vec<Value>) -> Self {
        let raw = results
            .into_iter()
            .map(|r| json!({"jsonrpc": "2.0", "id": 1, "result": r}).to_string())
            .collect();
        Self::new(raw)
    }

    /// A single JSON-RPC error envelope.
    pub fn with_error(code: i64, message: &str) -> Self {
        let raw = json!({"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": message}})
            .to_string();
        Self::new(vec![raw])
    }
}

impl RpcTransport for MockTransport {
    fn post_json(&self, body: &str) -> Result<String> {
        self.sent.borrow_mut().push(body.to_string());
        self.responses
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| CoreError::Transport("mock: no more responses queued".into()))
    }
}

// Test-only accessor so tests can read captured requests without exposing
// transport internals in the public API.
#[cfg(test)]
impl SolanaRpc<MockTransport> {
    fn transport_sent(&self) -> Vec<String> {
        self.transport.sent.borrow().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_balance() {
        let mock = MockTransport::with_results(vec![json!({"context": {"slot": 1}, "value": 42})]);
        let rpc = SolanaRpc::new(mock);
        let key = Pubkey::zeroed();
        assert_eq!(rpc.get_balance(&key).unwrap(), 42);
    }

    #[test]
    fn call_surfaces_rpc_error() {
        let mock = MockTransport::with_error(-32602, "Invalid params");
        let rpc = SolanaRpc::new(mock);
        let err = rpc.get_balance(&Pubkey::zeroed()).unwrap_err();
        assert_eq!(
            err,
            CoreError::Rpc {
                code: -32602,
                message: "Invalid params".into()
            }
        );
    }

    #[test]
    fn get_account_info_none_when_null() {
        let mock = MockTransport::with_results(vec![json!({"context": {"slot": 1}, "value": null})]);
        let rpc = SolanaRpc::new(mock);
        assert_eq!(rpc.get_account_info(&Pubkey::zeroed()).unwrap(), None);
    }

    #[test]
    fn get_account_info_decodes_base64_data() {
        // owner = token program, data = base64("foo")
        let value = json!({
            "context": {"slot": 1},
            "value": {
                "lamports": 1000,
                "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "data": ["Zm9v", "base64"],
                "executable": false,
                "rentEpoch": 0
            }
        });
        let mock = MockTransport::with_results(vec![value]);
        let rpc = SolanaRpc::new(mock);
        let acct = rpc.get_account_info(&Pubkey::zeroed()).unwrap().unwrap();
        assert_eq!(acct.lamports, 1000);
        assert_eq!(acct.data, b"foo");
        assert_eq!(acct.owner, crate::pubkey::programs::token());
    }

    #[test]
    fn records_request_method() {
        let mock = MockTransport::with_results(vec![json!({"value": 0})]);
        let rpc = SolanaRpc::new(mock);
        let _ = rpc.get_balance(&Pubkey::zeroed());
        let sent = rpc.transport_sent();
        assert!(sent[0].contains("\"method\":\"getBalance\""));
    }

    #[test]
    fn largest_accounts_parsed() {
        let value = json!({
            "context": {"slot": 1},
            "value": [
                {"address": "11111111111111111111111111111111", "amount": "900", "decimals": 6, "uiAmount": 0.0009, "uiAmountString": "0.0009"},
                {"address": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "amount": "100", "decimals": 6, "uiAmount": 0.0001, "uiAmountString": "0.0001"}
            ]
        });
        let mock = MockTransport::with_results(vec![value]);
        let rpc = SolanaRpc::new(mock);
        let holders = rpc.get_token_largest_accounts(&Pubkey::zeroed()).unwrap();
        assert_eq!(holders.len(), 2);
        assert_eq!(holders[0].amount, 900);
    }
}
