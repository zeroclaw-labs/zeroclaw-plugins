//! Integration tests for the Jupiter swap core, exercised exactly as the wasm
//! `execute` entry point drives it: build a `SwapConfig` from a flat config
//! section, then run. This runs on the host — no wasm, no network.

use jupiter_swap_execute::jupiter::*;
use std::collections::HashMap;

fn default_config() -> HashMap<String, String> {
    HashMap::new()
}

fn config_with(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ── Price V3 tests ──

#[test]
fn price_v3_shaping() {
    let raw = serde_json::json!({
        "So11111111111111111111111111111111111111112": {
            "usdPrice": 147.48,
            "decimals": 9,
            "priceChange24h": 1.29
        },
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": {
            "usdPrice": 0.9998,
            "decimals": 6,
            "priceChange24h": -0.15
        }
    });
    let out = shape_price_response(&raw);
    assert!(out.contains("147.48"));
    assert!(out.contains("+1.29%"));
    assert!(out.contains("-0.15%"));
}

#[test]
fn price_v3_empty() {
    let raw = serde_json::json!({});
    assert_eq!(shape_price_response(&raw), "No prices found.");
}

// ── Order V2 tests ──

#[test]
fn order_v2_shaping_with_tx() {
    let raw = serde_json::json!({
        "requestId": "req_abc123",
        "outAmount": "14285714300",
        "router": "jupiterz",
        "mode": "ultra",
        "feeBps": 30,
        "feeMint": "So11111111111111111111111111111111111111112",
        "transaction": "base64txdatahere"
    });
    let out = shape_order_response(&raw);
    assert!(out.contains("14285714300"));
    assert!(out.contains("jupiterz"));
    assert!(out.contains("ready to sign"));
}

#[test]
fn order_v2_shaping_quote_only() {
    let raw = serde_json::json!({
        "requestId": "req_xyz",
        "outAmount": "50000",
        "router": "metis",
        "mode": "manual",
        "feeBps": 0,
        "transaction": ""
    });
    let out = shape_order_response(&raw);
    assert!(out.contains("quote-only"));
    assert!(out.contains("metis"));
}

#[test]
fn order_v2_extract_transaction() {
    let raw = serde_json::json!({
        "transaction": "aGVsbG8gd29ybGQ=",
        "requestId": "req_1"
    });
    assert_eq!(extract_order_transaction(&raw).unwrap(), "aGVsbG8gd29ybGQ=");
}

#[test]
fn order_v2_extract_transaction_error_code() {
    let raw = serde_json::json!({
        "transaction": null,
        "errorCode": 42,
        "errorMessage": "Insufficient liquidity"
    });
    let err = extract_order_transaction(&raw).unwrap_err();
    assert!(err.contains("42"));
    assert!(err.contains("Insufficient liquidity"));
}

#[test]
fn order_v2_extract_request_id() {
    let raw = serde_json::json!({ "requestId": "req_abc" });
    assert_eq!(extract_request_id(&raw).unwrap(), "req_abc");
}

// ── Execute V2 tests ──

#[test]
fn execute_v2_success_shaping() {
    let raw = serde_json::json!({
        "status": "Success",
        "signature": "5Kt8...abc",
        "totalInputAmount": "100000000",
        "totalOutputAmount": "14285714300"
    });
    let out = shape_execute_response(&raw);
    assert!(out.contains("Swap executed"));
    assert!(out.contains("100000000"));
}

#[test]
fn execute_v2_failed_shaping() {
    let raw = serde_json::json!({
        "status": "Failed",
        "signature": "",
        "error": "Slippage exceeded"
    });
    let out = shape_execute_response(&raw);
    assert!(out.contains("failed"));
}

// ── URL builder tests ──

#[test]
fn price_url_uses_v3() {
    let cfg = SwapConfig::from_section(&default_config());
    let url = build_price_url(&cfg, &[SOL_MINT, USDC_MINT]);
    assert!(url.contains("price/v3"));
}

#[test]
fn order_url_uses_v2() {
    let cfg = SwapConfig::from_section(&default_config());
    let url = build_order_url(&cfg, SOL_MINT, USDC_MINT, 100000000, 50, "wallet123");
    assert!(url.contains("swap/v2/order"));
    assert!(url.contains("inputMint=So1111"));
    assert!(url.contains("outputMint=EPjFWdd"));
    assert!(url.contains("amount=100000000"));
    assert!(url.contains("slippageBps=50"));
    assert!(url.contains("taker=wallet123"));
}

#[test]
fn order_url_clamps_slippage_to_config_max() {
    let cfg = SwapConfig::from_section(&config_with(&[("max_slippage_bps", "30")]));
    let url = build_order_url(&cfg, SOL_MINT, USDC_MINT, 1000000, 500, "");
    assert!(url.contains("slippageBps=30"));
}

#[test]
fn order_url_no_taker_when_empty() {
    let cfg = SwapConfig::from_section(&default_config());
    let url = build_order_url(&cfg, SOL_MINT, USDC_MINT, 100000000, 50, "");
    assert!(!url.contains("taker="));
}

// ── Execute body tests ──

#[test]
fn execute_body_structure() {
    let body = build_execute_body("signed_tx", "req_123");
    assert_eq!(body["signedTransaction"], "signed_tx");
    assert_eq!(body["requestId"], "req_123");
}

// ── Mint allowlist tests ──

#[test]
fn allowlist_blocks_injection() {
    let cfg = SwapConfig::from_section(&config_with(&[(
        "allowed_mints",
        "So11111111111111111111111111111111111111112,EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    )]));
    let evil = "9xyzSCAMtokenFakeMintAddress123456";
    let result = enforce_mint_allowlist(&cfg, SOL_MINT, evil);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not in allowlist"));
}

#[test]
fn allowlist_allows_both_mints() {
    let cfg = SwapConfig::from_section(&config_with(&[(
        "allowed_mints",
        "So11111111111111111111111111111111111111112,EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    )]));
    assert!(enforce_mint_allowlist(&cfg, SOL_MINT, USDC_MINT).is_ok());
}

// ── Config defaults ──

#[test]
fn config_defaults_to_v2_apis() {
    let cfg = SwapConfig::from_section(&default_config());
    assert_eq!(cfg.swap_api, "https://api.jup.ag/swap/v2");
    assert_eq!(cfg.price_api, "https://api.jup.ag/price/v3");
}

#[test]
fn config_custom_swap_api() {
    let cfg = SwapConfig::from_section(&config_with(&[("swap_api", "https://my-proxy.com")]));
    assert_eq!(cfg.swap_api, "https://my-proxy.com");
}
