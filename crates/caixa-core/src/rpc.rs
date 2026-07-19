//! JSON-RPC over a mockable transport. WASM uses `waki` (wasi:http).

use serde_json::{json, Value};

use crate::pubkey::Pubkey;

#[derive(Debug, Clone)]
pub struct RpcError(pub String);

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RpcError {}

/// One-method transport so the pure client is host-testable with `MockTransport`.
pub trait RpcTransport {
    fn post_json(&self, url: &str, body: &Value) -> Result<Value, RpcError>;
}

#[derive(Default)]
pub struct MockTransport {
    pub responses: Vec<Value>,
    pub calls: std::cell::RefCell<Vec<(String, Value)>>,
}

impl MockTransport {
    pub fn new(responses: Vec<Value>) -> Self {
        Self {
            responses,
            calls: std::cell::RefCell::new(Vec::new()),
        }
    }

    pub fn single(response: Value) -> Self {
        Self::new(vec![response])
    }
}

impl RpcTransport for MockTransport {
    fn post_json(&self, url: &str, body: &Value) -> Result<Value, RpcError> {
        self.calls.borrow_mut().push((url.to_string(), body.clone()));
        let idx = self.calls.borrow().len() - 1;
        self.responses
            .get(idx)
            .cloned()
            .ok_or_else(|| RpcError(format!("mock RPC has no response for call #{idx}")))
    }
}

#[cfg(target_family = "wasm")]
pub struct WakiTransport;

#[cfg(target_family = "wasm")]
impl RpcTransport for WakiTransport {
    fn post_json(&self, url: &str, body: &Value) -> Result<Value, RpcError> {
        waki::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .map_err(|e| RpcError(e.to_string()))?
            .json::<Value>()
            .map_err(|e| RpcError(e.to_string()))
    }
}

pub struct RpcClient<'a, T: RpcTransport> {
    pub url: String,
    pub transport: &'a T,
    next_id: std::cell::Cell<u64>,
}

impl<'a, T: RpcTransport> RpcClient<'a, T> {
    pub fn new(url: impl Into<String>, transport: &'a T) -> Self {
        Self {
            url: url.into(),
            transport,
            next_id: std::cell::Cell::new(1),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let resp = self.transport.post_json(&self.url, &body)?;
        if let Some(err) = resp.get("error") {
            return Err(RpcError(format!("RPC error: {err}")));
        }
        Ok(resp
            .get("result")
            .cloned()
            .unwrap_or(Value::Null))
    }

    pub fn get_latest_blockhash(&self) -> Result<[u8; 32], RpcError> {
        let result = self.call(
            "getLatestBlockhash",
            json!([{ "commitment": "confirmed" }]),
        )?;
        let hash = result
            .pointer("/value/blockhash")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError("missing blockhash".into()))?;
        let bytes = crate::base58::decode(hash).map_err(RpcError)?;
        if bytes.len() != 32 {
            return Err(RpcError("blockhash must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    pub fn get_account_data(&self, pubkey: &Pubkey) -> Result<Option<Vec<u8>>, RpcError> {
        let result = self.call(
            "getAccountInfo",
            json!([
                pubkey.to_base58(),
                { "encoding": "base64", "commitment": "confirmed" }
            ]),
        )?;
        if result.get("value").map(|v| v.is_null()).unwrap_or(true) {
            return Ok(None);
        }
        let data_b64 = result
            .pointer("/value/data/0")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError("missing account data".into()))?;
        let bytes = crate::base64::decode(data_b64).map_err(RpcError)?;
        Ok(Some(bytes))
    }

    /// Parse a durable nonce account (80 bytes: version + state + authority + nonce + fee_calculator).
    pub fn get_nonce_value(&self, nonce_account: &Pubkey) -> Result<[u8; 32], RpcError> {
        let data = self
            .get_account_data(nonce_account)?
            .ok_or_else(|| RpcError("nonce account not found".into()))?;
        if data.len() < 72 {
            return Err(RpcError(format!(
                "nonce account data too short: {} bytes",
                data.len()
            )));
        }
        // Layout: 4 version + 4 state + 32 authority + 32 durable nonce
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[40..72]);
        Ok(nonce)
    }

    pub fn get_signatures_for_address(
        &self,
        address: &Pubkey,
        limit: usize,
    ) -> Result<Vec<SignatureInfo>, RpcError> {
        let result = self.call(
            "getSignaturesForAddress",
            json!([
                address.to_base58(),
                { "limit": limit, "commitment": "confirmed" }
            ]),
        )?;
        let arr = result
            .as_array()
            .ok_or_else(|| RpcError("signatures result not an array".into()))?;
        let mut out = Vec::new();
        for item in arr {
            let sig = item
                .get("signature")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let err_null = item.get("err").map(|e| e.is_null()).unwrap_or(true);
            let memo = item
                .get("memo")
                .and_then(Value::as_str)
                .map(|s| s.to_string());
            out.push(SignatureInfo {
                signature: sig,
                ok: err_null,
                memo,
            });
        }
        Ok(out)
    }

    pub fn get_transaction_memo_and_pre_balances(
        &self,
        signature: &str,
    ) -> Result<TxMetaBrief, RpcError> {
        let result = self.call(
            "getTransaction",
            json!([
                signature,
                {
                    "encoding": "json",
                    "commitment": "confirmed",
                    "maxSupportedTransactionVersion": 0
                }
            ]),
        )?;
        if result.is_null() {
            return Err(RpcError("transaction not found".into()));
        }
        let mut memos = Vec::new();
        if let Some(log_messages) = result.pointer("/meta/logMessages").and_then(Value::as_array) {
            for line in log_messages {
                if let Some(s) = line.as_str() {
                    if let Some(rest) = s.strip_prefix("Program log: Memo (len ") {
                        // "Program log: Memo (len N): \"text\""
                        if let Some(idx) = rest.find("): \"") {
                            let text = &rest[idx + 4..];
                            let text = text.trim_end_matches('"');
                            memos.push(text.to_string());
                        }
                    }
                }
            }
        }
        // Also surface top-level memo field when present via parsed ix — keep simple.
        Ok(TxMetaBrief {
            signature: signature.to_string(),
            memos,
            fee_payer: result
                .pointer("/transaction/message/accountKeys/0")
                .and_then(|v| {
                    if let Some(s) = v.as_str() {
                        Some(s.to_string())
                    } else {
                        v.get("pubkey").and_then(Value::as_str).map(|s| s.to_string())
                    }
                }),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SignatureInfo {
    pub signature: String,
    pub ok: bool,
    pub memo: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TxMetaBrief {
    pub signature: String,
    pub memos: Vec<String>,
    pub fee_payer: Option<String>,
}

/// HTTP GET helper for FX quotes (CoinGecko JSON). Host tests inject via trait.
pub trait HttpGet {
    fn get_json(&self, url: &str) -> Result<Value, RpcError>;
}

#[derive(Default)]
pub struct MockHttpGet {
    pub body: Value,
}

impl HttpGet for MockHttpGet {
    fn get_json(&self, _url: &str) -> Result<Value, RpcError> {
        Ok(self.body.clone())
    }
}

#[cfg(target_family = "wasm")]
pub struct WakiHttpGet;

#[cfg(target_family = "wasm")]
impl HttpGet for WakiHttpGet {
    fn get_json(&self, url: &str) -> Result<Value, RpcError> {
        waki::Client::new()
            .get(url)
            .send()
            .map_err(|e| RpcError(e.to_string()))?
            .json::<Value>()
            .map_err(|e| RpcError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_blockhash() {
        let hash = "11111111111111111111111111111111";
        let mock = MockTransport::single(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "value": { "blockhash": hash, "lastValidBlockHeight": 1 } }
        }));
        let client = RpcClient::new("https://example.invalid", &mock);
        let bh = client.get_latest_blockhash().unwrap();
        assert_eq!(bh, [0u8; 32]);
    }

    #[test]
    fn parses_nonce_account() {
        let mut data = vec![0u8; 80];
        data[40..72].copy_from_slice(&[7u8; 32]);
        let b64 = crate::base64::encode(&data);
        let mock = MockTransport::single(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "value": { "data": [b64, "base64"] } }
        }));
        let client = RpcClient::new("https://example.invalid", &mock);
        let nonce = client
            .get_nonce_value(&Pubkey::from_base58("11111111111111111111111111111111").unwrap())
            .unwrap();
        assert_eq!(nonce, [7u8; 32]);
    }
}
