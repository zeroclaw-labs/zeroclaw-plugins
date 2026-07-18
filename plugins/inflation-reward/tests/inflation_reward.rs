use std::collections::HashMap;

use inflation_reward::inflation_reward::{
    build_report, parse_rpc_response, render_report, rpc_request, validate_identifier,
    validate_rpc_url, RpcConfig,
};
use serde_json::json;

#[allow(dead_code)]
fn base58_value(bytes: usize) -> String {
    bs58::encode(vec![7_u8; bytes]).into_string()
}

#[test]
fn validates_endpoint_and_config() {
    assert!(validate_rpc_url("https://api.mainnet-beta.solana.com").is_ok());
    assert!(validate_rpc_url("http://127.0.0.1:8899").is_ok());
    assert!(validate_rpc_url("http://rpc.example.com").is_err());
    assert!(validate_rpc_url("https://user@example.com").is_err());
    let mut config = HashMap::new();
    config.insert("commitment".into(), "eventual".into());
    assert!(RpcConfig::from_section(&config).is_err());
    assert!(validate_identifier(&base58_value(32), "identifier", 32).is_ok());
    assert!(validate_identifier("not-base58-0", "identifier", 32).is_err());
}

#[test]
fn builds_the_bounded_read_only_request() {
    let value = base58_value(32);
    let request = rpc_request(&value, 9, "finalized");
    assert_eq!(request["jsonrpc"], "2.0");
    assert_eq!(request["id"], 9);
    assert_eq!(request["method"], "getInflationReward");
    let first = &request["params"][0];
    let expected = serde_json::to_value(value).unwrap();
    assert!(first == &expected || first.get(0) == Some(&expected));
}

#[test]
fn parses_success_and_fails_closed_on_rpc_errors() {
    let result = parse_rpc_response(&json!({"result":{"ok":true}})).unwrap();
    assert_eq!(result["ok"], true);
    assert!(parse_rpc_response(&json!({"result":null})).is_err());
    assert!(
        parse_rpc_response(&json!({"error":{"code":-32000,"message":"rate limited"}})).is_err()
    );
}

#[test]
fn renders_a_bounded_json_report() {
    let report = build_report(
        "Vote111111111111111111111111111111111111111".to_string(),
        json!({"value":42}),
    );
    let output = render_report(&report).unwrap();
    assert!(output.contains("inflation-reward"));
    assert!(output.contains("getInflationReward"));
    let oversized = build_report("x".into(), json!({"blob":"x".repeat(9000)}));
    assert!(render_report(&oversized).is_err());
}
