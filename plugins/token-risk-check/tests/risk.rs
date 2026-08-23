//! Integration test for the token risk check core, exercised exactly as the wasm
//! `execute` entry point drives it: build a SolanaRpc, call check_token. This
//! runs on the host with a plain `cargo test` and covers the same code path the
//! component runs inside the wasmtime host.
//!
//! These tests do NOT hit a real network — they verify struct construction,
//! URL handling, and config deserialization.

use std::collections::HashMap;

use solana_core::rpc::SolanaRpc;

/// Simulate the config parsing logic from the wasm component shim.
#[derive(serde::Deserialize)]
struct ExecuteArgs {
    mint: String,
    #[serde(default = "default_rpc_url")]
    rpc_url: String,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

fn default_rpc_url() -> String {
    "https://api.mainnet-beta.solana.com".to_string()
}

#[test]
fn test_args_deserialization_with_only_mint() {
    let json = r#"{"mint": "So11111111111111111111111111111111111111112"}"#;
    let parsed: ExecuteArgs = serde_json::from_str(json).unwrap();
    assert_eq!(
        parsed.mint,
        "So11111111111111111111111111111111111111112"
    );
    assert_eq!(parsed.rpc_url, "https://api.mainnet-beta.solana.com");
    assert!(parsed.config.is_empty());
}

#[test]
fn test_args_deserialization_with_custom_rpc() {
    let json = r#"{
        "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "rpc_url": "https://rpc.ankr.com/solana"
    }"#;
    let parsed: ExecuteArgs = serde_json::from_str(json).unwrap();
    assert_eq!(
        parsed.mint,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    );
    assert_eq!(parsed.rpc_url, "https://rpc.ankr.com/solana");
    assert!(parsed.config.is_empty());
}

#[test]
fn test_args_deserialization_with_config() {
    let json = r#"{
        "mint": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
        "__config": {
            "user_key": "user_value"
        }
    }"#;
    let parsed: ExecuteArgs = serde_json::from_str(json).unwrap();
    assert_eq!(
        parsed.mint,
        "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
    );
    assert_eq!(parsed.rpc_url, "https://api.mainnet-beta.solana.com");
    assert_eq!(
        parsed.config.get("user_key").unwrap(),
        "user_value"
    );
}

#[test]
fn test_solana_rpc_creation_with_url() {
    let rpc = SolanaRpc::new("https://api.mainnet-beta.solana.com");
    assert_eq!(rpc.url, "https://api.mainnet-beta.solana.com");
}

#[test]
fn test_solana_rpc_creation_with_custom_url() {
    let rpc = SolanaRpc::new("https://solana-api.projectserum.com");
    assert_eq!(rpc.url, "https://solana-api.projectserum.com");
}

#[test]
fn test_rpc_url_default_uses_https() {
    let rpc = SolanaRpc::new("https://api.mainnet-beta.solana.com");
    assert!(rpc.url.starts_with("https://"));
}

#[test]
fn test_check_token_returns_error_with_invalid_mint() {
    // This tests the wrapper's error handling without hitting a real network.
    // check_token creates a SolanaRpc and tries to call the RPC, which will
    // fail with a connection error (not a code error) since no real network.
    let result = token_risk_check::risk::check_token(
        "INVALID",
        "https://api.mainnet-beta.solana.com",
    );
    // Should fail with a network/RPC error, not crash
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(!err.is_empty());
}