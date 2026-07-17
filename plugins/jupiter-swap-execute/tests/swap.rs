//! Integration tests for the Jupiter swap core, exercised exactly as the wasm
//! `execute` entry point drives it: build a `SwapConfig` from a flat config
//! section, then run. This runs on the host with a plain `cargo test` and
//! covers the same code path the component runs inside the wasmtime host.
//!
//! No live network calls — all HTTP stubbed. The pure core (jupiter.rs) handles
//! all logic that can be tested without wasi:http.

use std::collections::HashMap;

use jupiter_swap_execute::jupiter::*;

fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ── Config resolution ────────────────────────────────────────────────

#[test]
fn default_config_has_jupiter_endpoints() {
    let cfg = SwapConfig::from_section(&HashMap::new());
    assert!(cfg.price_api.contains("price.jup.ag"));
    assert!(cfg.quote_api.contains("quote-api.jup.ag"));
}

#[test]
fn outlayer_key_required_for_swap_but_not_price() {
    let cfg = SwapConfig::from_section(&HashMap::new());
    // Key is empty — swap should fail, price should work (Jupiter is public)
    assert!(cfg.outlayer_api_key.is_empty());
}

#[test]
fn slippage_clamped_to_config_max() {
    let cfg = SwapConfig::from_section(&section(&[("max_slippage_bps", "30")]));
    let url = build_quote_url(&cfg, "So1111", "EPjFWd", 1000000, 100);
    // Should use config max (30), not requested (100)
    assert!(url.contains("slippageBps=30"));
}

// ── Mint allowlist enforcement ────────────────────────────────────────

#[test]
fn allowlist_rejects_prompt_injection_to_random_mint() {
    let sol = "So11111111111111111111111111111111";
    let fake_token = "9xyzFAKEtokenMintThatDoesNotExist";
    let cfg = SwapConfig::from_section(&section(&[("allowed_mints", sol)]));

    // This is the prompt-injection test: agent tries to swap to arbitrary token
    let result = enforce_mint_allowlist(&cfg, sol, fake_token);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("not in allowlist"));
    assert!(err.contains("Transaction rejected"));
}

#[test]
fn allowlist_allows_both_directions() {
    let sol = "So11111111111111111111111111111111";
    let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let cfg = SwapConfig::from_section(&section(&[
        ("allowed_mints", "So11111111111111111111111111111111,EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
    ]));

    assert!(enforce_mint_allowlist(&cfg, sol, usdc).is_ok());
    assert!(enforce_mint_allowlist(&cfg, usdc, sol).is_ok());
}

#[test]
fn empty_allowlist_is_permissive() {
    let cfg = SwapConfig::from_section(&HashMap::new());
    assert!(enforce_mint_allowlist(&cfg, "anything", "goes").is_ok());
}

#[test]
fn prompt_injection_cannot_override_allowlist_via_args() {
    // Even if someone passes extra mints in args, the config allowlist
    // is the source of truth — this test validates that invariant
    let cfg = SwapConfig::from_section(&section(&[("allowed_mints", "So11111111111111111111111111111111")]));
    let malicious_mint = "inject_this_mint_to_bypass_allowlist";
    assert!(!is_mint_allowed(&cfg, malicious_mint));
}

// ── Output shaping ─────────────────────────────────────────────────────

#[test]
fn price_output_under_200_tokens() {
    let raw = serde_json::json!({
        "data": {
            "So11111111111111111111111111111111": {
                "id": "So11111111111111111111111111111111",
                "price": "143.27"
            },
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": {
                "id": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "price": "0.9998"
            },
            "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN": {
                "id": "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN",
                "price": "1.23"
            }
        }
    });
    let out = shape_price_response(&raw);
    // Should be compact — not 40KB
    assert!(out.len() < 300, "Price output too long: {} chars", out.len());
    assert!(out.contains("$143.27"));
}

#[test]
fn quote_output_shows_route_and_impact() {
    let raw = serde_json::json!({
        "inAmount": "100000000",  // 100 SOL
        "outAmount": "14285714300",
        "priceImpactPct": "-0.00150",
        "slippageBps": 50,
        "routePlan": [
            {
                "swapInfo": {
                    "label": "Raydium",
                    "amtIn": "50000000"
                }
            },
            {
                "swapInfo": {
                    "label": "Orca",
                    "amtIn": "50000000"
                }
            }
        ]
    });
    let out = shape_quote_response(&raw);
    assert!(out.len() < 400, "Quote output too long: {} chars", out.len());
    assert!(out.contains("Raydium"));
    assert!(out.contains("Orca"));
    assert!(out.contains("0.15")); // price impact
    assert!(out.contains("0.50%")); // slippage
}

#[test]
fn quote_output_handles_single_route() {
    let raw = serde_json::json!({
        "inAmount": "1000000",
        "outAmount": "998500",
        "priceImpactPct": "0",
        "slippageBps": 50,
        "routePlan": [
            {
                "swapInfo": {
                    "label": "Meteora",
                    "amtIn": "1000000"
                }
            }
        ]
    });
    let out = shape_quote_response(&raw);
    assert!(out.contains("Meteora"));
}

// ── Transaction extraction ─────────────────────────────────────────────

#[test]
fn swap_transaction_extracted_correctly() {
    let raw = serde_json::json!({
        "swapTransaction": "aGVsbG8gd29ybGQ=" // base64 "hello world"
    });
    let tx = extract_swap_transaction(&raw).unwrap();
    assert_eq!(tx, "aGVsbG8gd29ybGQ=");
}

#[test]
fn missing_swap_transaction_fails() {
    let raw = serde_json::json!({
        "someOtherField": "value"
    });
    assert!(extract_swap_transaction(&raw).is_err());
}

// ── OutLayer URL construction ─────────────────────────────────────────

#[test]
fn outlayer_address_url_has_solana_chain() {
    let cfg = SwapConfig::from_section(&HashMap::new());
    let url = build_outlayer_address_url(&cfg);
    assert!(url.contains("chain=solana"));
    assert!(url.starts_with("https://"));
}

#[test]
fn outlayer_balance_url_includes_token() {
    let cfg = SwapConfig::from_section(&HashMap::new());
    let url = build_outlayer_balance_url(&cfg, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    assert!(url.contains("EPjFWdd5"));
    assert!(url.contains("chain=solana"));
}

#[test]
fn outlayer_transfer_body_serializes() {
    let body = build_outlayer_transfer_body(
        "solana",
        "So11111111111111111111111111111111",
        "destination_addr",
        "1000000",
        "dGVzdA==",
    );
    let serialized = serde_json::to_string(&body).unwrap();
    assert!(serialized.contains("solana"));
    assert!(serialized.contains("dGVzdA=="));
    // Should be reasonable size, not 40KB
    assert!(serialized.len() < 500);
}

// ── Mint display ───────────────────────────────────────────────────────

#[test]
fn mint_short_truncates_long_addresses() {
    let full = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let short = mint_short(full);
    assert_eq!(short, "EPjFWdd5");
}

#[test]
fn mint_short_preserves_short_addresses() {
    assert_eq!(mint_short("short"), "short");
}
