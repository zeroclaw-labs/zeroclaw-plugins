//! Pure payment-matching logic for `payment-watch`. No wasm imports here —
//! everything is host-testable with plain `cargo test`. The I/O shim in
//! `lib.rs` fetches signatures + transactions from a Solana JSON-RPC endpoint
//! and hands the parsed JSON to these functions.
//!
//! Custody tier: T0 (read-only). The plugin never builds, signs, or submits
//! anything. The only secret it can ever hold is an RPC API key embedded in
//! the configured endpoint URL.

use serde_json::Value;

pub const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;

#[derive(Debug, Clone)]
pub struct WatchSpec {
    /// Address to watch (base58). Receiving account.
    pub address: String,
    /// Expected amount in token units (SOL lamports -> SOL, or SPL ui amount).
    pub expected_amount: f64,
    /// SPL mint to match; None or "SOL" = native SOL.
    pub mint: Option<String>,
    /// Optional memo/reference substring that must appear in the transaction
    /// (invoice reconciliation: "Invoice #412", a Solana Pay reference key...).
    pub reference: Option<String>,
    /// Only consider signatures at least this recent (unix seconds). 0 = all.
    pub since_unix: u64,
    /// Relative tolerance for amount match (0.005 = 0.5%).
    pub tolerance: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PaymentHit {
    pub signature: String,
    pub amount: f64,
    pub is_spl: bool,
    pub memo: Option<String>,
    pub block_time: Option<u64>,
}

/// Decide whether a single parsed transaction (getTransaction jsonParsed
/// result) satisfies the watch spec.
pub fn match_transaction(tx: &Value, spec: &WatchSpec) -> Option<PaymentHit> {
    let meta = tx.get("meta")?;
    if meta.get("err")?.is_object() || meta.get("err")?.is_string() {
        return None; // failed tx
    }

    // Memo check first (cheap reject). Reference matches against any Memo
    // program instruction data or the raw log messages.
    let memo = extract_memo(tx);
    if let Some(reference) = &spec.reference {
        let found = memo
            .as_deref()
            .map(|m| m.contains(reference.as_str()))
            .unwrap_or(false)
            || tx
                .get("transaction")
                .and_then(|t| t.get("message"))
                .and_then(|m| m.get("accountKeys"))
                .map(|k| k.to_string().contains(reference.as_str()))
                .unwrap_or(false);
        if !found {
            return None;
        }
    }

    // Recency check.
    let block_time = tx.get("blockTime").and_then(|b| b.as_u64());
    if spec.since_unix > 0 {
        match block_time {
            Some(bt) if bt >= spec.since_unix => {}
            _ => return None,
        }
    }

    let is_spl = spec
        .mint
        .as_deref()
        .map(|m| m != "SOL" && !m.is_empty())
        .unwrap_or(false);

    let amount = if is_spl {
        spl_delta(meta, &spec.address, spec.mint.as_deref().unwrap_or(""))?
    } else {
        sol_delta(meta, tx, &spec.address)?
    };

    let lo = spec.expected_amount * (1.0 - spec.tolerance);
    let hi = spec.expected_amount * (1.0 + spec.tolerance);
    if amount >= lo && amount <= hi {
        Some(PaymentHit {
            signature: tx
                .get("transaction")
                .and_then(|t| t.get("signatures"))
                .and_then(|s| s.get(0))
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            amount,
            is_spl,
            memo,
            block_time,
        })
    } else {
        None
    }
}

/// Native SOL received by `address`: pre/post balance delta in SOL.
fn sol_delta(meta: &Value, tx: &Value, address: &str) -> Option<f64> {
    let keys = tx
        .get("transaction")?
        .get("message")?
        .get("accountKeys")?
        .as_array()?;
    let idx = keys.iter().position(|k| {
        k.as_str() == Some(address)
            || k.get("pubkey").and_then(|p| p.as_str()) == Some(address)
    })?;
    let pre = meta.get("preBalances")?.as_array()?.get(idx)?.as_u64()?;
    let post = meta.get("postBalances")?.as_array()?.get(idx)?.as_u64()?;
    let delta = post as i128 - pre as i128;
    if delta <= 0 {
        return None;
    }
    Some(delta as f64 / LAMPORTS_PER_SOL)
}

/// SPL token delta for `mint` credited to token accounts owned by `address`,
/// in UI amount. Uses postTokenBalances minus preTokenBalances.
fn spl_delta(meta: &Value, owner: &str, mint: &str) -> Option<f64> {
    let sum = |key: &str| -> f64 {
        meta.get(key)
            .and_then(|b| b.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|b| {
                        b.get("mint").and_then(|m| m.as_str()) == Some(mint)
                            && b.get("owner").and_then(|o| o.as_str()) == Some(owner)
                    })
                    .filter_map(|b| {
                        b.get("uiTokenAmount")
                            .and_then(|u| u.get("uiAmount"))
                            .and_then(|a| a.as_f64())
                    })
                    .sum()
            })
            .unwrap_or(0.0)
    };
    let delta = sum("postTokenBalances") - sum("preTokenBalances");
    if delta > 0.0 {
        Some(delta)
    } else {
        None
    }
}

/// Pull the first Memo-program instruction data (base58/base64 decoded to
/// UTF-8 when possible) out of a parsed transaction.
pub fn extract_memo(tx: &Value) -> Option<String> {
    const MEMO_PROGRAMS: [&str; 2] = [
        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
        "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",
    ];
    let ixs = tx
        .get("transaction")?
        .get("message")?
        .get("instructions")?
        .as_array()?;
    for ix in ixs {
        let pid = ix
            .get("programId")
            .and_then(|p| p.as_str())
            .or_else(|| ix.get("programIdIndex").map(|_| ""));
        if let Some(pid) = pid {
            if MEMO_PROGRAMS.contains(&pid) {
                if let Some(data) = ix.get("data").and_then(|d| d.as_str()) {
                    return Some(data.to_string());
                }
                if let Some(parsed) = ix.get("parsed").and_then(|p| p.as_str()) {
                    return Some(parsed.to_string());
                }
            }
        }
    }
    None
}

/// Build the JSON-RPC request body for getSignaturesForAddress.
pub fn signatures_request(address: &str, limit: u32) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "getSignaturesForAddress",
        "params": [address, {"limit": limit}]
    })
}

/// Build the JSON-RPC request body for getTransaction (jsonParsed).
pub fn transaction_request(signature: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "getTransaction",
        "params": [signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}]
    })
}

/// Extract the recent signature list from a getSignaturesForAddress response.
pub fn signatures_from_response(resp: &Value) -> Vec<String> {
    resp.get("result")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.get("signature").and_then(|s| s.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec_sol() -> WatchSpec {
        WatchSpec {
            address: "recv111".into(),
            expected_amount: 0.025,
            mint: None,
            reference: None,
            since_unix: 0,
            tolerance: 0.005,
        }
    }

    fn sol_tx(pre: u64, post: u64, block_time: u64) -> Value {
        json!({
            "blockTime": block_time,
            "meta": {"err": null, "preBalances": [pre], "postBalances": [post]},
            "transaction": {
                "signatures": ["sig_abc"],
                "message": {"accountKeys": ["recv111"], "instructions": []}
            }
        })
    }

    #[test]
    fn matches_sol_payment_within_tolerance() {
        let tx = sol_tx(1_000_000_000, 1_025_000_000, 1_800_000_000); // +0.025 SOL
        let hit = match_transaction(&tx, &spec_sol()).unwrap();
        assert_eq!(hit.signature, "sig_abc");
        assert!((hit.amount - 0.025).abs() < 1e-9);
        assert!(!hit.is_spl);
    }

    #[test]
    fn rejects_wrong_amount() {
        let tx = sol_tx(1_000_000_000, 1_050_000_000, 1_800_000_000); // +0.05 SOL
        assert!(match_transaction(&tx, &spec_sol()).is_none());
    }

    #[test]
    fn rejects_outgoing() {
        let tx = sol_tx(1_025_000_000, 1_000_000_000, 1_800_000_000); // -0.025 SOL
        assert!(match_transaction(&tx, &spec_sol()).is_none());
    }

    #[test]
    fn rejects_failed_tx() {
        let mut tx = sol_tx(1_000_000_000, 1_025_000_000, 1_800_000_000);
        tx["meta"]["err"] = json!({"InstructionError": [0, "Custom"]});
        assert!(match_transaction(&tx, &spec_sol()).is_none());
    }

    #[test]
    fn enforces_since_unix() {
        let mut s = spec_sol();
        s.since_unix = 1_800_000_001;
        let tx = sol_tx(1_000_000_000, 1_025_000_000, 1_800_000_000);
        assert!(match_transaction(&tx, &s).is_none());
    }

    #[test]
    fn matches_memo_reference() {
        let mut s = spec_sol();
        s.reference = Some("Invoice #412".into());
        let mut tx = sol_tx(1_000_000_000, 1_025_000_000, 1_800_000_000);
        tx["transaction"]["message"]["instructions"] = json!([{
            "programId": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
            "data": "Invoice #412 paid"
        }]);
        let hit = match_transaction(&tx, &s).unwrap();
        assert_eq!(hit.memo.as_deref(), Some("Invoice #412 paid"));
    }

    #[test]
    fn rejects_missing_reference() {
        let mut s = spec_sol();
        s.reference = Some("Invoice #413".into());
        let mut tx = sol_tx(1_000_000_000, 1_025_000_000, 1_800_000_000);
        tx["transaction"]["message"]["instructions"] = json!([{
            "programId": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
            "data": "Invoice #412 paid"
        }]);
        assert!(match_transaction(&tx, &s).is_none());
    }

    #[test]
    fn matches_spl_payment() {
        let s = WatchSpec {
            address: "owner1".into(),
            expected_amount: 25.0,
            mint: Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into()), // USDC
            reference: None,
            since_unix: 0,
            tolerance: 0.001,
        };
        let tx = json!({
            "blockTime": 1_800_000_000,
            "meta": {
                "err": null,
                "preBalances": [0], "postBalances": [0],
                "preTokenBalances": [{
                    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                    "owner": "owner1",
                    "uiTokenAmount": {"uiAmount": 100.0}
                }],
                "postTokenBalances": [{
                    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                    "owner": "owner1",
                    "uiTokenAmount": {"uiAmount": 125.0}
                }]
            },
            "transaction": {
                "signatures": ["sig_usdc"],
                "message": {"accountKeys": ["owner1"], "instructions": []}
            }
        });
        let hit = match_transaction(&tx, &s).unwrap();
        assert!(hit.is_spl);
        assert!((hit.amount - 25.0).abs() < 1e-9);
    }

    #[test]
    fn spl_ignores_other_mints_and_owners() {
        let s = WatchSpec {
            address: "owner1".into(),
            expected_amount: 25.0,
            mint: Some("mintA".into()),
            reference: None, since_unix: 0, tolerance: 0.001,
        };
        let tx = json!({
            "blockTime": 1,
            "meta": {
                "err": null, "preBalances": [0], "postBalances": [0],
                "preTokenBalances": [],
                "postTokenBalances": [
                    {"mint": "mintB", "owner": "owner1", "uiTokenAmount": {"uiAmount": 25.0}},
                    {"mint": "mintA", "owner": "owner2", "uiTokenAmount": {"uiAmount": 25.0}}
                ]
            },
            "transaction": {"signatures": ["s"], "message": {"accountKeys": [], "instructions": []}}
        });
        assert!(match_transaction(&tx, &s).is_none());
    }

    #[test]
    fn request_builders_are_well_formed() {
        let r = signatures_request("addr", 25);
        assert_eq!(r["method"], "getSignaturesForAddress");
        let t = transaction_request("sig");
        assert_eq!(t["params"][1]["encoding"], "jsonParsed");
    }
}
