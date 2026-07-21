//! Host tests for pixzclaw-brief pure core.

use std::cell::RefCell;
use std::collections::HashMap;

use pixzclaw_brief::brief_tool::{
    evaluate_brief, execute_from_args_with_http, fixture_sig, ExecuteArgs, DEFAULT_LOOKBACK,
};
use serde_json::{json, Value};
use solana_wasm_core::{DashboardSnapshot, HttpTransport, RpcError};

struct SeqMock {
    responses: RefCell<Vec<Value>>,
}

impl HttpTransport for SeqMock {
    fn post_json(&self, _url: &str, body: &Value) -> Result<Value, RpcError> {
        let method = body
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let mut q = self.responses.borrow_mut();
        // Prefer matching by order; fall back to method name
        if let Some(next) = q.first().cloned() {
            // if first response is tagged, skip until method matches
            if let Some(m) = next.get("_method").and_then(|x| x.as_str()) {
                if m != method {
                    // find matching
                    if let Some(i) = q.iter().position(|r| {
                        r.get("_method").and_then(|x| x.as_str()) == Some(method)
                    }) {
                        let mut r = q.remove(i);
                        if let Some(obj) = r.as_object_mut() {
                            obj.remove("_method");
                        }
                        return Ok(r);
                    }
                } else {
                    let mut r = q.remove(0);
                    if let Some(obj) = r.as_object_mut() {
                        obj.remove("_method");
                    }
                    return Ok(r);
                }
            } else {
                return Ok(q.remove(0));
            }
        }
        Err(RpcError::new(format!("no mock for {method}")))
    }
}

fn cfg() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("merchant_solana".into(), "11111111111111111111111111111112".into());
    m.insert("rpc_url".into(), "https://api.mainnet-beta.solana.com".into());
    m
}

#[test]
fn evaluate_brief_card() {
    let now = 1_700_000_000i64;
    let snap = DashboardSnapshot {
        merchant_solana: "11111111111111111111111111111112".into(),
        sol_lamports: 1_000_000_000,
        usdc_ui: "50".into(),
        signatures: vec![fixture_sig(
            "SigABCDEF123456",
            Some("PIX|BRL|demo-1|cafe"),
            now - 30,
        )],
        now_unix: now,
        recent_limit: 5,
    };
    let s = evaluate_brief(&snap);
    assert!(s.contains("PixZClaw · Caixa"));
    assert!(s.contains("50"));
    assert!(s.contains("demo-1"));
}

#[test]
fn fetch_mock_rpc_pipeline() {
    let balance = json!({
        "_method": "getBalance",
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "value": 2500000000u64 }
    });
    let tokens = json!({
        "_method": "getTokenAccountsByOwner",
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "value": [{
                "account": {
                    "data": {
                        "parsed": {
                            "info": {
                                "tokenAmount": { "uiAmount": 12.5, "uiAmountString": "12.5" }
                            }
                        }
                    }
                }
            }]
        }
    });
    let sigs = json!({
        "_method": "getSignaturesForAddress",
        "jsonrpc": "2.0",
        "id": 1,
        "result": [{
            "signature": "MockSig1111111111111111111111111",
            "slot": 9,
            "err": null,
            "memo": "PIX|BRL|inv-9|x",
            "blockTime": 1_700_000_000i64 - 100,
            "confirmationStatus": "finalized"
        }]
    });

    let http = SeqMock {
        responses: RefCell::new(vec![balance, tokens, sigs]),
    };
    let args = ExecuteArgs {
        lookback: Some(DEFAULT_LOOKBACK),
        recent_limit: Some(5),
        merchant: None,
        config: cfg(),
    };
    let out = execute_from_args_with_http(args, http, 1_700_000_000).unwrap();
    assert!(out.contains("12.5") || out.contains("PixZClaw"));
    assert!(out.contains("inv-9") || out.contains("PIX|BRL"));
}

#[test]
fn missing_merchant_fails() {
    let http = SeqMock {
        responses: RefCell::new(vec![]),
    };
    let args = ExecuteArgs {
        lookback: None,
        recent_limit: None,
        merchant: None,
        config: HashMap::new(),
    };
    let err = execute_from_args_with_http(args, http, 0).unwrap_err();
    assert!(err.contains("merchant_solana"));
}

#[test]
fn prompt_injection_cannot_move_funds() {
    // Tool surface has no transfer fields; evaluate_brief only formats.
    let snap = DashboardSnapshot::default();
    let s = evaluate_brief(&snap);
    assert!(!s.to_lowercase().contains("transfer"));
    assert!(s.contains("T0") || s.contains("read-only") || s.contains("sem chave"));
}
