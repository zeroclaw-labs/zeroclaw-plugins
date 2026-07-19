//! End-to-end host tests over the pure core: the full `att::run` flow with a
//! canned transport — no network, no wasm toolchain.

use std::collections::HashMap;

use depin_attest::att;
use serde_json::{json, Value};

const DEVICE: &str = "11111111111111111111111111111111";
const BLOCKHASH: &str = "9sHcv6xwn9YkB8nxTUGKDwPwNnmqVp5oAXxU8Fdkm4J6";

fn canned_transport(
    sigs_result: Value,
) -> impl FnMut(&str, &Value) -> Result<String, String> {
    move |_url, body| {
        let method = body.get("method").and_then(Value::as_str).unwrap_or("");
        let resp = match method {
            "getSignaturesForAddress" => json!({"jsonrpc":"2.0","id":1,"result": sigs_result}),
            "getLatestBlockhash" => json!({"jsonrpc":"2.0","id":2,"result":{
                "context":{"slot":1},
                "value":{"blockhash": BLOCKHASH, "lastValidBlockHeight": 3090}}}),
            other => return Err(format!("unexpected RPC method {other}")),
        };
        Ok(resp.to_string())
    }
}

fn base_args() -> Value {
    json!({
        "metric": "temp_c",
        "value": 23.5,
        "__config": {
            "device_pubkey": DEVICE,
            "metrics": "temp_c:-40:85:C, humidity_pct:0:100:%"
        }
    })
}

#[test]
fn first_attestation_is_genesis_seq_1() {
    let mut post = canned_transport(json!([]));
    let out = att::run(&base_args().to_string(), &mut post, 1789000000).unwrap();
    assert!(out.contains("ATTESTATION #1"), "{out}");
    assert!(out.contains(r#""prev":"genesis""#), "{out}");
    assert!(out.contains("unsigned_tx_base64:"), "{out}");
    // Output shaping: judges count tokens. Whole reply stays small.
    assert!(out.len() < 1200, "output too large: {} bytes", out.len());
}

#[test]
fn sequence_continues_from_newest_prior_attestation() {
    let prior_memo = format!(
        r#"{{"v":1,"dev":"{DEVICE}","seq":41,"ts":1788990000,"metric":"temp_c","val":"22","unit":"C","prev":"aabbccdd00112233"}}"#
    );
    let mut post = canned_transport(json!([
        {"signature":"gmSig","err":null,"memo":"[2] gm"},
        {"signature":"PriorSig111","err":null,"memo": format!("[{}] {}", prior_memo.len(), prior_memo)},
    ]));
    let out = att::run(&base_args().to_string(), &mut post, 1789000000).unwrap();
    assert!(out.contains("ATTESTATION #42"), "{out}");
    // prev committed to the prior tx's signature (8-byte sha256 prefix, hex).
    let prev = out
        .split(r#""prev":""#)
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap();
    assert_eq!(prev.len(), 16);
    assert!(prev.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn unsigned_tx_decodes_and_carries_the_memo() {
    use base64::Engine;
    let mut post = canned_transport(json!([]));
    let out = att::run(&base_args().to_string(), &mut post, 1789000000).unwrap();
    let b64 = out
        .split("unsigned_tx_base64: ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .expect("output carries the tx");
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    // Unsigned: exactly one all-zero signature slot.
    assert_eq!(bytes[0], 1);
    assert!(bytes[1..65].iter().all(|&b| b == 0));
    // The memo payload rides in the transaction verbatim.
    let memo = out.split("memo: ").nth(1).unwrap().lines().next().unwrap();
    let hay = String::from_utf8_lossy(&bytes);
    assert!(hay.contains(memo), "tx bytes must embed the canonical payload");
}

#[test]
fn rpc_failure_fails_closed_with_no_transaction() {
    let mut post = |_url: &str, _body: &Value| Err("connection refused".to_string());
    let err = att::run(&base_args().to_string(), &mut post, 1789000000).unwrap_err();
    assert!(err.contains("connection refused"));
}

#[test]
fn unknown_argument_keys_are_rejected() {
    // A prompt-injected attempt to smuggle extra instructions or override
    // config must die at deserialization, before any RPC traffic.
    let mut called = false;
    let mut post = |_url: &str, _body: &Value| {
        called = true;
        Err("must not be reached".to_string())
    };
    let mut args = base_args();
    args["recipient"] = json!("AttackerAddress111111111111111111");
    let err = att::run(&args.to_string(), &mut post, 0).unwrap_err();
    assert!(err.contains("arguments rejected"), "{err}");
    assert!(!called, "no RPC call may happen on rejected args");
}

#[test]
fn config_spoofing_via_args_is_impossible_by_host_contract_but_still_validated() {
    // The host strips caller-supplied __config before injection; even if one
    // slipped through, an invalid device key must fail closed.
    let mut post = |_url: &str, _body: &Value| Err("must not be reached".to_string());
    let mut cfg = HashMap::new();
    cfg.insert("device_pubkey".to_string(), "not-a-key".to_string());
    cfg.insert("metrics".to_string(), "temp_c:-40:85:C".to_string());
    let args = json!({"metric":"temp_c","value":1,"__config": cfg});
    let err = att::run(&args.to_string(), &mut post, 0).unwrap_err();
    assert!(err.contains("device_pubkey is invalid"), "{err}");
}
