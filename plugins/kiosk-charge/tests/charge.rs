//! Host-run tests for the kiosk-charge core, driven exactly as the wasm shim
//! drives it: config from a flat section, strict args, deterministic reference.
//! Plain `cargo test` — no wasm toolchain, no network (this plugin HAS no
//! network), RPC not involved at all.

use std::collections::HashMap;

use kiosk_charge::charge::{
    execute_charge, ChargeArgs, ChargeConfig, ChargeError, DEFAULT_USDC_MINT,
};

const MERCHANT: &str = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T"; // arbitrary valid pk
const REF32: [u8; 32] = [7u8; 32];

fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn base_cfg() -> ChargeConfig {
    ChargeConfig::from_section(&section(&[
        ("merchant_address", MERCHANT),
        ("price_list", "cold_drink:1.5, snack:0.75"),
        ("max_amount_usdc", "10"),
        ("label", "Kiosk 01"),
    ]))
    .unwrap()
}

#[test]
fn item_charge_builds_solana_pay_url() {
    let out = execute_charge(
        &ChargeArgs {
            item_id: Some("cold_drink".into()),
            ..Default::default()
        },
        &base_cfg(),
        REF32,
        0,
    )
    .unwrap();
    assert!(out
        .url
        .starts_with(&format!("solana:{MERCHANT}?amount=1.5")));
    assert!(out.url.contains(&format!("spl-token={DEFAULT_USDC_MINT}")));
    assert!(out.url.contains(&format!("reference={}", out.reference)));
    assert!(out.url.contains("label=Kiosk%2001"));
    assert!(out.url.contains("memo=cold_drink"));
    assert_eq!(out.amount, "1.5");
}

#[test]
fn generalizes_to_any_spl_mint_not_just_usdc() {
    // BROADLY-USABLE: the mint is operator config, so any stablecoin/token works.
    let other_mint = "So11111111111111111111111111111111111111112";
    let cfg = ChargeConfig::from_section(&section(&[
        ("merchant_address", MERCHANT),
        ("usdc_mint", other_mint),
        ("price_list", "cold_drink:1.5"),
    ]))
    .unwrap();
    let out = execute_charge(
        &ChargeArgs {
            item_id: Some("cold_drink".into()),
            ..Default::default()
        },
        &cfg,
        REF32,
        0,
    )
    .unwrap();
    assert!(out.url.contains(&format!("spl-token={other_mint}")));
}

#[test]
fn optional_fiat_display_is_cosmetic_only() {
    // display_currency + static rate → a "≈ BRL x.xx" hint in the summary.
    // The on-chain amount stays the USDC figure.
    let cfg = ChargeConfig::from_section(&section(&[
        ("merchant_address", MERCHANT),
        ("price_list", "cold_drink:1.5"),
        ("display_currency", "BRL"),
        ("display_rate", "5.00"),
    ]))
    .unwrap();
    let out = execute_charge(
        &ChargeArgs {
            item_id: Some("cold_drink".into()),
            ..Default::default()
        },
        &cfg,
        REF32,
        0,
    )
    .unwrap();
    assert!(
        out.summary.contains("≈ BRL 7.50"),
        "summary: {}",
        out.summary
    );
    assert!(out.url.contains("amount=1.5"), "on-chain amount stays USDC");
    // Off by default: base_cfg has no display currency.
    let plain = execute_charge(
        &ChargeArgs {
            item_id: Some("cold_drink".into()),
            ..Default::default()
        },
        &base_cfg(),
        REF32,
        0,
    )
    .unwrap();
    assert!(
        !plain.summary.contains("≈"),
        "no fiat hint unless configured"
    );
}

#[test]
fn free_amount_within_cap_ok() {
    let out = execute_charge(
        &ChargeArgs {
            amount_usdc: Some("2.25".into()),
            ..Default::default()
        },
        &base_cfg(),
        REF32,
        0,
    )
    .unwrap();
    assert!(out.url.contains("amount=2.25"));
    assert!(out.item.is_none());
}

#[test]
fn output_stays_within_token_budget() {
    let out = execute_charge(
        &ChargeArgs {
            amount_usdc: Some("2.25".into()),
            note: Some("x".repeat(500)),
            ..Default::default()
        },
        &base_cfg(),
        REF32,
        0,
    )
    .unwrap();
    assert!(
        kiosk_core::shape::approx_tokens(&out.summary) <= kiosk_core::shape::DEFAULT_BUDGET_TOKENS
    );
}

// ── Fail-closed drill ────────────────────────────────────────────────────────

#[test]
fn injection_unknown_item_rejected() {
    let err = execute_charge(
        &ChargeArgs {
            item_id: Some("free_everything".into()),
            ..Default::default()
        },
        &base_cfg(),
        REF32,
        0,
    )
    .unwrap_err();
    assert!(matches!(err, ChargeError::Args(_)));
}

#[test]
fn injection_amount_over_cap_rejected() {
    for bad in ["11", "9999", "10.000001"] {
        let err = execute_charge(
            &ChargeArgs {
                amount_usdc: Some(bad.into()),
                ..Default::default()
            },
            &base_cfg(),
            REF32,
            0,
        )
        .unwrap_err();
        assert!(
            matches!(err, ChargeError::Args(_)),
            "{bad} must be rejected"
        );
    }
}

#[test]
fn injection_smuggled_recipient_key_is_a_serde_error() {
    // The model-facing args struct denies unknown fields: a smuggled
    // `recipient` never reaches charge logic.
    let raw = r#"{"item_id":"cold_drink","recipient":"EvilPubkey111111111111111111111111"}"#;
    let parsed: Result<ChargeArgs, _> = serde_json::from_str(raw);
    assert!(
        parsed.is_err(),
        "unknown `recipient` field must fail deserialization"
    );
}

#[test]
fn injection_note_cannot_forge_url_params() {
    let out = execute_charge(
        &ChargeArgs {
            amount_usdc: Some("1".into()),
            note: Some("&amount=999&recipient=EVIL".into()),
            ..Default::default()
        },
        &base_cfg(),
        REF32,
        0,
    )
    .unwrap();
    assert_eq!(out.url.matches("amount=").count(), 1);
    assert!(!out.url.contains("&recipient="));
}

#[test]
fn missing_merchant_config_fails_closed() {
    let err = ChargeConfig::from_section(&section(&[("price_list", "a:1")])).unwrap_err();
    assert!(matches!(err, ChargeError::Config(_)));
}

#[test]
fn invalid_merchant_pubkey_fails_closed() {
    let err =
        ChargeConfig::from_section(&section(&[("merchant_address", "not-a-key")])).unwrap_err();
    assert!(matches!(err, ChargeError::Config(_)));
}

#[test]
fn no_item_and_no_amount_rejected() {
    let err = execute_charge(&ChargeArgs::default(), &base_cfg(), REF32, 0).unwrap_err();
    assert!(matches!(err, ChargeError::Args(_)));
}
