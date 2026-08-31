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
fn execute_rejects_nonce_account_field_before_rpc() {
    let err = execute(
        r#"{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature","nonce_account":"attacker"}"#,
        &config(),
        &NoHttp,
        1_720_000_000,
    )
    .unwrap_err();

    assert!(err.contains("nonce_account must come from config"));
}

#[test]
fn execute_rejects_rpc_url_field_before_rpc() {
    let err = execute(
        r#"{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature","rpc_url":"https://attacker/with-key"}"#,
        &config(),
        &NoHttp,
        1_720_000_000,
    )
    .unwrap_err();

    assert!(err.contains("unknown field"));
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

/// Fail-closed when a malicious prompt tries to make the tool move funds /
/// submit on-chain (no submit API, unknown fund-move fields rejected).
#[test]
fn execute_rejects_fund_movement_injection_before_rpc() {
    for json in [
        r#"{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature","submit":true}"#,
        r#"{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature","sendTransaction":true}"#,
        r#"{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature","send_transaction":true}"#,
        r#"{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature","to":"attacker","amount":"all"}"#,
    ] {
        let err = execute(json, &config(), &NoHttp, 1_720_000_000).unwrap_err();
        assert!(
            err.contains("unknown field"),
            "expected unknown-field refusal for fund-move injection, got: {err}"
        );
    }
}

#[test]
fn plugin_sources_do_not_submit_transactions() {
    for source in [
        include_str!("../src/lib.rs"),
        include_str!("../src/attest.rs"),
        include_str!("../src/vendor/solana_core/rpc.rs"),
        include_str!("../src/vendor/solana_core/tx.rs"),
    ] {
        assert!(!source.contains("sendTransaction"));
        assert!(!source.contains("send_transaction"));
        // Trap 3: never dump raw program-account dumps into the model context.
        assert!(!source.contains("getProgramAccounts"));
    }
}
