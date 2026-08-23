//! Host tests for the Solana Pay request URL builder.
//!
//! These tests run on the host with a plain `cargo test` and exercise the
//! same `create_pay_request` function that the wasm component calls inside
//! its `execute` entry point.

use solana_pay_request::pay::create_pay_request;

#[test]
fn generates_valid_solana_url_basic() {
    let result = create_pay_request(
        "7EcDhSYGxXyscszYEp35KHN8vvw3svAuEt8JaVipkGCf",
        1.5,
        None,
        Some("invoice-42"),
        None,
    );
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let url = parsed["url"].as_str().unwrap();
    assert!(url.starts_with("solana:"));
    assert!(url.contains("amount=1.5"));
    assert!(url.contains("memo=invoice-42"));
    assert!(url.contains("label=ZeroClaw+Agent"));
    assert!(!url.contains("spl-token="), "native SOL should not have spl-token param");
}

#[test]
fn generates_url_with_spl_mint() {
    let result = create_pay_request(
        "7EcDhSYGxXyscszYEp35KHN8vvw3svAuEt8JaVipkGCf",
        25.0,
        Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
        Some("table-4"),
        Some("ref123"),
    );
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let url = parsed["url"].as_str().unwrap();
    assert!(url.contains("spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"));
    assert!(url.contains("amount=25"));
    assert!(url.contains("reference=ref123"));
    assert!(url.contains("memo=table-4"));
}

#[test]
fn minimal_url_no_optionals() {
    let result = create_pay_request(
        "7EcDhSYGxXyscszYEp35KHN8vvw3svAuEt8JaVipkGCf",
        0.01,
        None,
        None,
        None,
    );
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let url = parsed["url"].as_str().unwrap();
    assert!(url.starts_with("solana:"));
    assert!(url.contains("amount=0.01"));
    assert!(url.contains("label=ZeroClaw+Agent"));
    assert!(!url.contains("spl-token="));
    assert!(!url.contains("memo="));
    assert!(!url.contains("reference="));
}

#[test]
fn qr_payload_equals_url() {
    let result = create_pay_request(
        "7EcDhSYGxXyscszYEp35KHN8vvw3svAuEt8JaVipkGCf",
        10.0,
        Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
        None,
        None,
    );
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["url"], parsed["qr_payload"]);
}

#[test]
fn recipient_address_encoded_in_url() {
    let recipient = "7EcDhSYGxXyscszYEp35KHN8vvw3svAuEt8JaVipkGCf";
    let result = create_pay_request(recipient, 5.0, None, None, None);
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let url = parsed["url"].as_str().unwrap();
    assert!(url.starts_with(&format!("solana:{}", recipient)));
}

#[test]
fn reference_parameter_included_when_present() {
    let result = create_pay_request(
        "7EcDhSYGxXyscszYEp35KHN8vvw3svAuEt8JaVipkGCf",
        100.0,
        None,
        None,
        Some("order-abc-123"),
    );
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let url = parsed["url"].as_str().unwrap();
    assert!(url.contains("reference=order-abc-123"));
}

#[test]
fn mint_and_reference_together() {
    let result = create_pay_request(
        "7EcDhSYGxXyscszYEp35KHN8vvw3svAuEt8JaVipkGCf",
        50.0,
        Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
        None,
        Some("track-99"),
    );
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let url = parsed["url"].as_str().unwrap();
    assert!(url.contains("spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"));
    assert!(url.contains("reference=track-99"));
    assert!(url.contains("amount=50"));
    assert!(url.contains("label=ZeroClaw+Agent"));
}