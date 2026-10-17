//! Pure JSON-RPC request building and response parsing for the two Solana
//! calls this tool makes. No transport here — the wasm shim owns HTTP, and
//! host tests feed canned JSON straight into the parsers.

use serde_json::{json, Value};

/// getSignaturesForAddress carries each transaction's memo string, which is
/// how we recover the previous attestation without a second RPC call.
pub fn build_get_signatures(device: &str, limit: u16) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "getSignaturesForAddress",
        "params": [device, {"limit": limit, "commitment": "confirmed"}]
    })
}

pub fn build_get_latest_blockhash() -> Value {
    json!({
        "jsonrpc": "2.0", "id": 2, "method": "getLatestBlockhash",
        "params": [{"commitment": "confirmed"}]
    })
}

fn unwrap_envelope(resp: &str) -> Result<Value, String> {
    let v: Value =
        serde_json::from_str(resp).map_err(|e| format!("RPC response is not JSON: {e}"))?;
    if let Some(err) = v.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown RPC error");
        return Err(format!("RPC error {code}: {msg}"));
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| "RPC response has neither result nor error".into())
}

/// One prior transaction on the device address: its signature and memo (the
/// RPC prefixes memos with "[len] " — stripped here).
#[derive(Debug)]
pub struct PriorTx {
    pub signature: String,
    pub memo: Option<String>,
}

pub fn parse_signatures(resp: &str) -> Result<Vec<PriorTx>, String> {
    let result = unwrap_envelope(resp)?;
    let list = result
        .as_array()
        .ok_or("getSignaturesForAddress result is not a list")?;
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        // Failed transactions can't carry a landed attestation.
        if !entry.get("err").map(Value::is_null).unwrap_or(false) {
            continue;
        }
        let signature = entry
            .get("signature")
            .and_then(Value::as_str)
            .ok_or("signature entry missing signature")?
            .to_string();
        let memo = entry
            .get("memo")
            .and_then(Value::as_str)
            .map(strip_len_prefix)
            .map(str::to_string);
        out.push(PriorTx { signature, memo });
    }
    Ok(out)
}

/// `"[42] {...}"` → `"{...}"`. Memos without the prefix pass through.
fn strip_len_prefix(memo: &str) -> &str {
    if let Some(rest) = memo.strip_prefix('[') {
        if let Some((len, body)) = rest.split_once("] ") {
            if len.chars().all(|c| c.is_ascii_digit()) {
                return body;
            }
        }
    }
    memo
}

/// getLatestBlockhash → (base58 blockhash, last valid block height).
pub fn parse_latest_blockhash(resp: &str) -> Result<(String, u64), String> {
    let result = unwrap_envelope(resp)?;
    let value = result.get("value").ok_or("getLatestBlockhash missing value")?;
    let hash = value
        .get("blockhash")
        .and_then(Value::as_str)
        .ok_or("missing blockhash")?
        .to_string();
    let height = value
        .get("lastValidBlockHeight")
        .and_then(Value::as_u64)
        .ok_or("missing lastValidBlockHeight")?;
    Ok((hash, height))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memo_len_prefix_is_stripped() {
        assert_eq!(strip_len_prefix("[5] hello"), "hello");
        assert_eq!(strip_len_prefix(r#"[12] {"v":1}"#), r#"{"v":1}"#);
        assert_eq!(strip_len_prefix("no prefix"), "no prefix");
        assert_eq!(strip_len_prefix("[not-a-len] x"), "[not-a-len] x");
    }

    #[test]
    fn failed_txs_are_skipped() {
        let resp = r#"{"jsonrpc":"2.0","id":1,"result":[
            {"signature":"sigA","err":{"InstructionError":[0,"Custom"]},"memo":"[3] bad"},
            {"signature":"sigB","err":null,"memo":"[4] good"}
        ]}"#;
        let txs = parse_signatures(resp).unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].signature, "sigB");
        assert_eq!(txs[0].memo.as_deref(), Some("good"));
    }

    #[test]
    fn rpc_errors_surface() {
        let resp = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"node is behind"}}"#;
        assert!(parse_signatures(resp).unwrap_err().contains("-32005"));
    }

    #[test]
    fn blockhash_parses() {
        let resp = r#"{"jsonrpc":"2.0","id":2,"result":{"context":{"slot":1},
            "value":{"blockhash":"9sHcv6xwn9YkB8nxTUGKDwPwNnmqVp5oAXxU8Fdkm4J6","lastValidBlockHeight":3090}}}"#;
        let (h, lvbh) = parse_latest_blockhash(resp).unwrap();
        assert_eq!(h, "9sHcv6xwn9YkB8nxTUGKDwPwNnmqVp5oAXxU8Fdkm4J6");
        assert_eq!(lvbh, 3090);
    }
}
