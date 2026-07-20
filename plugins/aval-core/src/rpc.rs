//! Minimal Solana JSON-RPC client behind an injectable HTTP trait.
//!
//! The trait is the seam that keeps the whole suite host-testable: `cargo
//! test` injects fixture responses, the wasm shim injects a `waki` client.
//! Only the five methods the suite needs exist, and every response is shaped
//! down to the fields used — a raw RPC payload never crosses the plugin
//! boundary toward the model.

use serde_json::{json, Value};

use crate::codec::{b58_decode, b64_decode};
use crate::pubkey::Pubkey;

/// One blocking JSON POST. Implementations must return the raw response body.
pub trait HttpPost {
    fn post_json(&self, url: &str, body: &str) -> Result<String, String>;
}

pub struct Rpc<'a, H: HttpPost> {
    http: &'a H,
    url: &'a str,
}

#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub lamports: u64,
    pub owner: Pubkey,
    pub data: Vec<u8>,
}

impl<'a, H: HttpPost> Rpc<'a, H> {
    pub fn new(http: &'a H, url: &'a str) -> Self {
        Self { http, url }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let raw = self.http.post_json(self.url, &body.to_string())?;
        let v: Value = serde_json::from_str(&raw)
            .map_err(|e| format!("rpc returned non-JSON response: {e}"))?;
        if let Some(err) = v.get("error") {
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(format!("rpc error from {method}: {msg}"));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| format!("rpc response for {method} has no result"))
    }

    /// `getAccountInfo` with base64 encoding; `Ok(None)` when the account
    /// does not exist.
    pub fn get_account(&self, pubkey: &Pubkey) -> Result<Option<AccountInfo>, String> {
        let result = self.call(
            "getAccountInfo",
            json!([pubkey.to_base58(), { "encoding": "base64", "commitment": "confirmed" }]),
        )?;
        let value = result.get("value").ok_or("getAccountInfo missing value")?;
        if value.is_null() {
            return Ok(None);
        }
        let lamports = value
            .get("lamports")
            .and_then(Value::as_u64)
            .ok_or("account has no lamports field")?;
        let owner = value
            .get("owner")
            .and_then(Value::as_str)
            .ok_or("account has no owner field")
            .and_then(|s| Pubkey::from_base58(s).map_err(|_| "account owner is not a pubkey"))?;
        let data_b64 = value
            .get("data")
            .and_then(|d| d.get(0))
            .and_then(Value::as_str)
            .ok_or("account data is not base64-encoded")?;
        let data = b64_decode(data_b64)?;
        Ok(Some(AccountInfo {
            lamports,
            owner,
            data,
        }))
    }

    pub fn get_balance(&self, pubkey: &Pubkey) -> Result<u64, String> {
        self.call(
            "getBalance",
            json!([pubkey.to_base58(), { "commitment": "confirmed" }]),
        )?
        .get("value")
        .and_then(Value::as_u64)
        .ok_or_else(|| "getBalance returned no value".into())
    }

    /// Only used by `nonce-vault-init`: the one transaction in this suite
    /// that necessarily uses a recent blockhash (the nonce does not exist yet).
    pub fn get_latest_blockhash(&self) -> Result<[u8; 32], String> {
        let result = self.call(
            "getLatestBlockhash",
            json!([{ "commitment": "confirmed" }]),
        )?;
        let s = result
            .get("value")
            .and_then(|v| v.get("blockhash"))
            .and_then(Value::as_str)
            .ok_or("getLatestBlockhash returned no blockhash")?;
        b58_decode(s)?
            .try_into()
            .map_err(|_| "blockhash is not 32 bytes".into())
    }

    pub fn get_minimum_balance_for_rent_exemption(&self, size: u64) -> Result<u64, String> {
        self.call("getMinimumBalanceForRentExemption", json!([size]))?
            .as_u64()
            .ok_or_else(|| "getMinimumBalanceForRentExemption returned no number".into())
    }
}

// --- token account layouts (SPL Token v1) ---

/// Decimals live at byte 44 of a mint account
/// (COption<Pubkey> mint_authority = 36, supply u64 = 8, then decimals).
pub fn parse_mint_decimals(data: &[u8]) -> Result<u8, String> {
    if data.len() < 45 {
        return Err("mint account data too short".into());
    }
    Ok(data[44])
}

/// A token account starts `mint[32] | owner[32] | amount u64 LE`.
pub fn parse_token_account_amount(data: &[u8]) -> Result<u64, String> {
    if data.len() < 72 {
        return Err("token account data too short".into());
    }
    Ok(u64::from_le_bytes(data[64..72].try_into().expect("8 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::b64_encode;
    use std::cell::RefCell;

    pub struct MockHttp {
        pub responses: RefCell<Vec<String>>,
        pub requests: RefCell<Vec<String>>,
    }

    impl MockHttp {
        pub fn new(responses: Vec<&str>) -> Self {
            Self {
                responses: RefCell::new(responses.iter().rev().map(|s| s.to_string()).collect()),
                requests: RefCell::new(vec![]),
            }
        }
    }

    impl HttpPost for MockHttp {
        fn post_json(&self, _url: &str, body: &str) -> Result<String, String> {
            self.requests.borrow_mut().push(body.to_string());
            self.responses
                .borrow_mut()
                .pop()
                .ok_or_else(|| "mock exhausted".to_string())
        }
    }

    #[test]
    fn get_account_shapes_existing_and_missing() {
        let data = b64_encode(&[1, 2, 3]);
        let ok = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"value":{{"lamports":5,"owner":"11111111111111111111111111111111","data":["{data}","base64"]}}}}}}"#
        );
        let missing = r#"{"jsonrpc":"2.0","id":1,"result":{"value":null}}"#;
        let http = MockHttp::new(vec![&ok, missing]);
        let rpc = Rpc::new(&http, "http://mock");

        let acct = rpc.get_account(&Pubkey([1; 32])).unwrap().unwrap();
        assert_eq!(acct.lamports, 5);
        assert_eq!(acct.data, vec![1, 2, 3]);
        assert_eq!(acct.owner, crate::pubkey::system_program());
        assert!(rpc.get_account(&Pubkey([1; 32])).unwrap().is_none());
    }

    #[test]
    fn surfaces_rpc_errors_and_garbage() {
        let http = MockHttp::new(vec![
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}"#,
            "not json at all",
        ]);
        let rpc = Rpc::new(&http, "http://mock");
        let err = rpc.get_balance(&Pubkey([1; 32])).unwrap_err();
        assert!(err.contains("invalid params"));
        assert!(rpc.get_balance(&Pubkey([1; 32])).is_err());
    }

    #[test]
    fn latest_blockhash_and_rent() {
        let http = MockHttp::new(vec![
            r#"{"jsonrpc":"2.0","id":1,"result":{"value":{"blockhash":"11111111111111111111111111111111"}}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":1447680}"#,
        ]);
        let rpc = Rpc::new(&http, "http://mock");
        assert_eq!(rpc.get_latest_blockhash().unwrap(), [0u8; 32]);
        assert_eq!(rpc.get_minimum_balance_for_rent_exemption(80).unwrap(), 1447680);
    }

    #[test]
    fn token_layout_parsers() {
        let mut mint = vec![0u8; 82];
        mint[44] = 6;
        assert_eq!(parse_mint_decimals(&mint).unwrap(), 6);
        assert!(parse_mint_decimals(&[0u8; 10]).is_err());

        let mut token = vec![0u8; 165];
        token[64..72].copy_from_slice(&123u64.to_le_bytes());
        assert_eq!(parse_token_account_amount(&token).unwrap(), 123);
        assert!(parse_token_account_amount(&[0u8; 20]).is_err());
    }
}
