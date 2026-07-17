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

// ── Quote V1 tests ──

#[test]
fn quote_v1_shaping() {
    let raw = serde_json::json!({
        "inAmount": "100000000",
        "outAmount": "14285714300",
        "priceImpactPct": 0.001,
        "swapMode": "ExactIn"
    });
    let out = shape_quote_response(&raw);
    assert!(out.contains("100000000"));
    assert!(out.contains("14285714300"));
    assert!(out.contains("0.001"));
    assert!(out.contains("ExactIn"));
}

// ── Swap V1 tests ──

#[test]
fn swap_body_structure() {
    let quote = serde_json::json!({ "inAmount": "100000", "outAmount": "50000" });
    let cfg = SwapConfig::from_section(&default_config());
    let body = build_swap_body(&cfg, &quote, "my_wallet");
    assert_eq!(body["quoteResponse"]["inAmount"], "100000");
    assert_eq!(body["userPublicKey"], "my_wallet");
    assert_eq!(body["wrapAndUnwrapSol"], true);
    assert_eq!(body["asLegacyTransaction"], true);
}

#[test]
fn extract_swap_transaction_success() {
    let raw = serde_json::json!({
        "swapTransaction": "aGVsbG8gd29ybGQ="
    });
    assert_eq!(extract_swap_transaction(&raw).unwrap(), "aGVsbG8gd29ybGQ=");
}

#[test]
fn extract_swap_transaction_null_fails() {
    let raw = serde_json::json!({
        "swapTransaction": null,
        "error": "insufficient liquidity"
    });
    assert!(extract_swap_transaction(&raw).is_err());
}

// ── Wire format tests ──

#[test]
fn extract_message_from_legacy_tx() {
    // Legacy tx: [0x00 prefix][0x01 num_sigs][64 zero bytes][message bytes...]
    let mut tx = vec![0x00, 0x01]; // prefix + compact_u32(1)
    tx.extend_from_slice(&[0u8; 64]); // zero signature
    tx.extend_from_slice(b"HELLO_MESSAGE"); // message
    let msg = extract_message_from_tx(&tx).unwrap();
    assert_eq!(msg, b"HELLO_MESSAGE");
}

#[test]
fn extract_message_rejects_v0_tx() {
    let tx = vec![0x01, 0x01, 0x00]; // V0 prefix
    let err = extract_message_from_tx(&tx).unwrap_err();
    assert!(err.contains("address lookup tables"));
}

#[test]
fn assemble_signed_tx_inserts_sig() {
    let mut tx = vec![0x00, 0x01]; // legacy prefix + num_sigs
    tx.extend_from_slice(&[0u8; 64]); // zero sig
    tx.extend_from_slice(b"MSG");
    // Use a valid 64-byte base58 signature (just 64 'a' bytes in base58)
    let sig_bytes = [0xAAu8; 64];
    let sig_b58 = bs58::encode(sig_bytes).into_string();
    let signed = assemble_signed_tx(&tx, &sig_b58).unwrap();
    assert_eq!(&signed[2..66], &sig_bytes[..]);
    assert_eq!(&signed[66..], b"MSG");
}

#[test]
fn base64_roundtrip() {
    let data = b"hello world";
    let encoded = encode_base64(data);
    assert_eq!(decode_base64(&encoded).unwrap(), data);
}

// ── URL builder tests ──

#[test]
fn price_url_uses_v3() {
    let cfg = SwapConfig::from_section(&default_config());
    let url = build_price_url(&cfg, &[SOL_MINT, USDC_MINT]);
    assert!(url.contains("price/v3"));
}

#[test]
fn quote_url_uses_v1() {
    let cfg = SwapConfig::from_section(&default_config());
    let url = build_quote_url(&cfg, SOL_MINT, USDC_MINT, 100000000, 50);
    assert!(url.contains("/quote"));
    assert!(url.contains("inputMint=So1111"));
    assert!(url.contains("outputMint=EPjFWdd"));
    assert!(url.contains("amount=100000000"));
    assert!(url.contains("slippageBps=50"));
    assert!(url.contains("asLegacyTransaction=true"));
}

#[test]
fn quote_url_clamps_slippage_to_config_max() {
    let cfg = SwapConfig::from_section(&config_with(&[("max_slippage_bps", "30")]));
    let url = build_quote_url(&cfg, SOL_MINT, USDC_MINT, 1000000, 500);
    assert!(url.contains("slippageBps=30"));
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
fn config_defaults_to_v1_apis() {
    let cfg = SwapConfig::from_section(&default_config());
    assert_eq!(cfg.swap_api, "https://public.jupiterapi.com");
    assert_eq!(cfg.price_api, "https://api.jup.ag/price/v3");
    assert_eq!(cfg.outlayer_api, "https://api.outlayer.fastnear.com");
}

#[test]
fn config_custom_swap_api() {
    let cfg = SwapConfig::from_section(&config_with(&[("swap_api", "https://my-proxy.com")]));
    assert_eq!(cfg.swap_api, "https://my-proxy.com");
}

#[test]
fn config_custom_solana_rpc() {
    let cfg = SwapConfig::from_section(&config_with(&[(
        "solana_rpc",
        "https://my-rpc.com",
    )]));
    assert_eq!(cfg.solana_rpc, "https://my-rpc.com");
}
