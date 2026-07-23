//! Transport-agnostic Solana JSON-RPC plumbing.
//!
//! The pure core never talks to the network directly: it builds JSON-RPC
//! envelopes and interprets responses through the [`Transport`] trait. The
//! wasm shim implements `Transport` with `waki`; host tests implement it with
//! canned fixtures, so `cargo test` runs with no wasm toolchain and no live
//! network.

use serde_json::{json, Value};

/// Sends one JSON-RPC request body and returns the raw response body.
///
/// Implementations only do I/O. Envelope construction and error unwrapping
/// stay in [`RpcClient`] so they are covered by host tests.
pub trait Transport {
    fn send(&self, body: &Value) -> Result<Value, String>;
}

/// The two token programs a mint may belong to.
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// A mint account fetched via `getAccountInfo`.
pub struct AccountInfo {
    /// Program that owns the account, base58.
    pub owner: String,
    /// Present when the node parsed the account (`jsonParsed` encoding).
    pub parsed: Option<Value>,
    /// Raw account data, present when the node fell back to base64.
    pub raw: Option<Vec<u8>>,
    /// Slot the state was observed at, for honest reporting.
    pub slot: Option<u64>,
}

/// One row of `getTokenLargestAccounts`.
pub struct LargestAccount {
    pub address: String,
    /// Raw amount in base units, as u128 to survive u64-supply tokens.
    pub amount: u128,
}

pub struct RpcClient<'a> {
    pub transport: &'a dyn Transport,
}

impl<'a> RpcClient<'a> {
    pub fn new(transport: &'a dyn Transport) -> Self {
        Self { transport }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp = self.transport.send(&body)?;
        if let Some(err) = resp.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown RPC error");
            return Err(format!("RPC error {code}: {msg}"));
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| "malformed RPC response: no result".to_string())
    }

    /// Fetch the mint account. `Ok(None)` means the address has no account on
    /// this cluster.
    pub fn get_account_info(
        &self,
        mint: &str,
        commitment: &str,
    ) -> Result<Option<AccountInfo>, String> {
        let result = self.call(
            "getAccountInfo",
            json!([mint, {"encoding": "jsonParsed", "commitment": commitment}]),
        )?;
        let slot = result.pointer("/context/slot").and_then(Value::as_u64);
        let value = match result.get("value") {
            Some(v) if !v.is_null() => v.clone(),
            _ => return Ok(None),
        };
        let owner = value
            .get("owner")
            .and_then(Value::as_str)
            .ok_or("malformed account: no owner")?
            .to_string();

        let (parsed, raw) = match value.get("data") {
            // jsonParsed succeeded: {"program": "...", "parsed": {...}}
            Some(Value::Object(obj)) => (obj.get("parsed").cloned(), None),
            // node fell back to ["<base64>", "base64"]
            Some(Value::Array(arr)) => {
                let b64 = arr.first().and_then(Value::as_str).unwrap_or("");
                let bytes = crate::mint::decode_base64(b64)
                    .map_err(|e| format!("bad base64 account data: {e}"))?;
                (None, Some(bytes))
            }
            _ => (None, None),
        };

        Ok(Some(AccountInfo {
            owner,
            parsed,
            raw,
            slot,
        }))
    }

    /// Total supply in base units plus decimals.
    pub fn get_token_supply(&self, mint: &str, commitment: &str) -> Result<(u128, u8), String> {
        let result = self.call("getTokenSupply", json!([mint, {"commitment": commitment}]))?;
        let amount = result
            .pointer("/value/amount")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u128>().ok())
            .ok_or("malformed getTokenSupply response")?;
        let decimals = result
            .pointer("/value/decimals")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u8;
        Ok((amount, decimals))
    }

    /// Resolve token accounts to their wallet owners via `getMultipleAccounts`.
    /// Returns one entry per requested address; `None` where the owner could
    /// not be determined. Best-effort by design: callers degrade to
    /// per-token-account math when this errors.
    pub fn get_token_account_owners(
        &self,
        addresses: &[String],
        commitment: &str,
    ) -> Result<Vec<Option<String>>, String> {
        let result = self.call(
            "getMultipleAccounts",
            json!([addresses, {"encoding": "jsonParsed", "commitment": commitment}]),
        )?;
        let rows = result
            .get("value")
            .and_then(Value::as_array)
            .ok_or("malformed getMultipleAccounts response")?;
        if rows.len() != addresses.len() {
            return Err("getMultipleAccounts returned wrong row count".to_string());
        }
        Ok(rows.iter().map(token_account_owner).collect())
    }

    /// Up to 20 largest token accounts for the mint. Public RPCs sometimes
    /// disable this method; callers must treat failure as a degraded result,
    /// not a fatal one.
    pub fn get_token_largest_accounts(
        &self,
        mint: &str,
        commitment: &str,
    ) -> Result<Vec<LargestAccount>, String> {
        let result = self.call(
            "getTokenLargestAccounts",
            json!([mint, {"commitment": commitment}]),
        )?;
        let rows = result
            .get("value")
            .and_then(Value::as_array)
            .ok_or("malformed getTokenLargestAccounts response")?;
        Ok(rows
            .iter()
            .filter_map(|row| {
                let address = row.get("address")?.as_str()?.to_string();
                let amount = row.get("amount")?.as_str()?.parse::<u128>().ok()?;
                Some(LargestAccount { address, amount })
            })
            .collect())
    }
}

/// Extract the wallet owner from one `getMultipleAccounts` row for an SPL
/// token account: `parsed.info.owner` when the node parsed it, else bytes
/// 32..64 of the raw account data (SPL token-account layout: mint, owner, …).
fn token_account_owner(row: &Value) -> Option<String> {
    if row.is_null() {
        return None;
    }
    if let Some(owner) = row
        .pointer("/data/parsed/info/owner")
        .and_then(Value::as_str)
    {
        return Some(owner.to_string());
    }
    let b64 = row
        .get("data")
        .and_then(Value::as_array)?
        .first()
        .and_then(Value::as_str)?;
    let bytes = crate::mint::decode_base64(b64).ok()?;
    let owner = bytes.get(32..64)?;
    Some(bs58::encode(owner).into_string())
}
