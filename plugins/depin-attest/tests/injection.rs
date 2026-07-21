use std::collections::HashMap;

use depin_attest::attest::{execute, parse_args_strict};
use depin_attest::rpc::HttpClient;
use depin_attest::{CoreError, CoreResult};
use serde_json::Value;

struct NoHttp;

impl HttpClient for NoHttp {
    fn post_json(&self, _url: &str, _body: &Value) -> CoreResult<Value> {
        Err(CoreError::msg("http must not be called for rejected input"))
    }
}

fn config() -> HashMap<String, String> {
    HashMap::from([
        (
            "payer".to_string(),
            "4vJ9JU1bJJE96FWSFtTEWVHk49jq5DFLQgo5Scj1uW5g".to_string(),
        ),
        (
            "nonce_account".to_string(),
            "8qbHbw2BbbJ4Lj6MNUULFAVc5qSCkGnQXB7kSqN3Efw".to_string(),
        ),
        ("rpc_url".to_string(), "https://rpc.test".to_string()),
    ])
}

#[test]
fn rejects_unknown_json_fields() {
    let err = parse_args_strict(
        r#"{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature","destination":"attacker"}"#,
    )
    .unwrap_err();

    assert!(err.contains("unknown field"));
}

#[test]
fn rejects_payer_nonce_account_and_private_key_in_args() {
    for field in ["payer", "nonce_account", "private_key"] {
        let json = format!(
            r#"{{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature","{field}":"malicious"}}"#
        );

        let err = parse_args_strict(&json).unwrap_err();
        assert!(err.contains("must come from config"), "{field}: {err}");
    }
}

#[test]
fn execute_rejects_private_key_field_before_rpc() {
    let err = execute(
        r#"{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature","private_key":"secret"}"#,
        &config(),
        &NoHttp,
        1_720_000_000,
    )
    .unwrap_err();

    assert!(err.contains("private_key must come from config"));
}

#[test]
fn execute_rejects_payer_field_before_rpc() {
    let err = execute(
        r#"{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature","payer":"attacker"}"#,
        &config(),
        &NoHttp,
        1_720_000_000,
    )
    .unwrap_err();

    assert!(err.contains("payer must come from config"));
}

#[test]
fn execute_rejects_extreme_reading_before_rpc() {
    let err = execute(
        r#"{"device_id":"device-7","reading":1e99,"unit":"celsius","metric":"temperature"}"#,
        &config(),
        &NoHttp,
        1_720_000_000,
    )
    .unwrap_err();

    assert!(err.contains("reading exceeds max_abs_reading"));
}

#[test]
fn execute_rejects_drain_wallet_metric_before_rpc() {
    let err = execute(
        r#"{"device_id":"device-7","reading":12.5,"unit":"lamports","metric":"drain_wallet"}"#,
        &config(),
        &NoHttp,
        1_720_000_000,
    )
    .unwrap_err();

    assert!(err.contains("metric is not allowlisted"));
}
