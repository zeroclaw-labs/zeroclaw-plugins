//! Pure logic for building Solana Pay transfer request URLs.
//!
//! This module is wasm-free and host-testable via `cargo test`.
//! It wraps `solana_core::tx::build_solana_pay_url()` and adds
//! JSON-shaped output suitable for QR code generation.

/// Create a Solana Pay transfer request URL and return it as a JSON string
/// containing both the `url` and a `qr_payload` field.
///
/// # Arguments
///
/// * `recipient` - The recipient's Solana address (base58).
/// * `amount`    - The amount to request (as a decimal f64; e.g. 1.5 for 1.5 SOL/USDC).
/// * `mint`      - Optional SPL token mint address. Omitted / `None` for native SOL.
/// * `memo`      - Optional invoice memo string.
/// * `reference` - Optional reference key for payment tracking.
///
/// # Returns
///
/// A JSON-encoded string with keys `url` and `qr_payload`. The `qr_payload`
/// is identical to the URL — it's the same `solana:` URL that should be encoded
/// as a QR code by the caller.
pub fn create_pay_request(
    recipient: &str,
    amount: f64,
    mint: Option<&str>,
    memo: Option<&str>,
    reference: Option<&str>,
) -> String {
    let url = solana_core::tx::build_solana_pay_url(recipient, amount, mint, memo, reference);

    serde_json::json!({
        "url": url,
        "qr_payload": url,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pay_request_basic_sol() {
        let result = create_pay_request(
            "7EcDhSYGxXyscszYEp35KHN8vvw3svAuEt8JaVipkGCf",
            1.5,
            None,
            Some("invoice-42"),
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed["url"].as_str().unwrap().starts_with("solana:"));
        assert!(parsed["qr_payload"].as_str().unwrap().starts_with("solana:"));
        assert_eq!(parsed["url"], parsed["qr_payload"]);
        let url = parsed["url"].as_str().unwrap();
        assert!(url.contains("amount=1.5"));
        assert!(url.contains("memo=invoice-42"));
        assert!(!url.contains("spl-token="));
    }

    #[test]
    fn test_create_pay_request_with_usdc() {
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
        assert!(url.contains("label=ZeroClaw+Agent"));
    }

    #[test]
    fn test_create_pay_request_minimal() {
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
    fn test_qr_payload_shape() {
        // The qr_payload must be the exact same string as url so that
        // rendering the QR code from either field works identically.
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
}