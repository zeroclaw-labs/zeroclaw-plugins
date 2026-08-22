//! Minimal Solana JSON-RPC layer over an injectable transport.
//!
//! No solana-client, no sockets: the component talks JSON-RPC over the host's
//! `wasi:http`, and the host tests talk to a mock. The trait is the seam.

use serde_json::{json, Value};

/// One JSON-RPC call. The wasm shim implements this with `waki`; host tests
/// implement it with canned fixtures. No live network is ever required here.
pub trait RpcTransport {
    fn call(&self, method: &str, params: &Value) -> Result<Value, String>;
}

/// Raw account info as returned by `getAccountInfo` (base64 encoding).
pub struct AccountInfo {
    /// Base64-decoded account data.
    pub data: Vec<u8>,
    /// Owner program id, base58.
    pub owner: String,
}

/// `getAccountInfo` with base64 encoding; errors if the account is missing.
pub fn get_account_info(rpc: &dyn RpcTransport, pubkey: &str) -> Result<AccountInfo, String> {
    let params = json!([pubkey, {"encoding": "base64"}]);
    let result = rpc.call("getAccountInfo", &params)?;
    let value = result
        .get("value")
        .filter(|v| !v.is_null())
        .ok_or_else(|| format!("account not found: {pubkey}"))?;
    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or("malformed getAccountInfo response: missing owner")?
        .to_string();
    let data_b64 = value
        .get("data")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .ok_or("malformed getAccountInfo response: missing data")?;
    let data = b64_decode(data_b64)?;
    Ok(AccountInfo { data, owner })
}

/// `getTokenLargestAccounts`: raw amounts (u64 as string) of the up-to-20
/// largest token accounts for a mint.
pub fn get_token_largest_accounts(rpc: &dyn RpcTransport, mint: &str) -> Result<Vec<u64>, String> {
    let params = json!([mint]);
    let result = rpc.call("getTokenLargestAccounts", &params)?;
    let accounts = result
        .get("value")
        .and_then(Value::as_array)
        .ok_or("malformed getTokenLargestAccounts response")?;
    let mut amounts = Vec::with_capacity(accounts.len());
    for acc in accounts {
        let amount = acc
            .get("amount")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or("malformed amount in getTokenLargestAccounts response")?;
        amounts.push(amount);
    }
    Ok(amounts)
}

/// Base64 decode without pulling in a crate: standard alphabet, padding
/// required or absent, no line breaks (matches what the RPC emits).
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    const REJECT: u8 = 0xFF;
    fn val(c: u8) -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => REJECT,
        }
    }
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u8;
    for &c in s.as_bytes() {
        let v = val(c);
        if v == REJECT {
            return Err(format!("invalid base64 character: {}", c as char));
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}
