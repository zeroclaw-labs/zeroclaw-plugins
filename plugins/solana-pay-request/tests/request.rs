use std::{collections::HashMap, str::FromStr};

use nanosol::pubkey::Pubkey;
use solana_pay_request::pay_request::{
    build_request, derive_reference, parameters_schema, RequestArgs, RequestConfig,
};

const RECIPIENT: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const REFERENCE: &str = "ECvLKMSgRzVdJjZsdiGAPcRSjwVjS9f7HxizfC256Kei";

fn config(pairs: &[(&str, &str)]) -> RequestConfig {
    let section = pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    RequestConfig::from_section(&section).expect("valid config fixture")
}

fn request(spl_token: Option<&str>) -> RequestArgs {
    RequestArgs {
        recipient: RECIPIENT.to_string(),
        amount: "25.010000".to_string(),
        spl_token: spl_token.map(str::to_string),
        invoice_id: "412".to_string(),
        label: Some("Café & Co".to_string()),
        message: Some("Table 4 / lunch?".to_string()),
        memo: Some("Order #412".to_string()),
    }
}

#[test]
fn token_request_matches_official_url_encoding_and_golden_reference() {
    let config = config(&[
        ("mint_aliases", &format!("USDC={USDC}")),
        ("mint_decimals", "USDC=6"),
        ("allowed_recipients", RECIPIENT),
    ]);
    let output = build_request(request(Some("USDC")), &config).expect("build request");

    // Query escaping and field order match @solana/pay 1.0.22 encodeURL at
    // solana-foundation/solana-pay commit 9b0f8ec70c509c946c387633ae4f1e3115ea4958.
    let expected = format!(
        "solana:{RECIPIENT}?amount=25.01&spl-token={USDC}&reference={REFERENCE}\
         &label=Caf%C3%A9+%26+Co&message=Table+4+%2F+lunch%3F&memo=Order+%23412"
    );
    assert_eq!(output.url, expected);
    assert_eq!(output.qr_payload, output.url);
    assert_eq!(output.reference, REFERENCE);
    assert_eq!(
        output.summary,
        "Request: 25.01 USDC to 7xKX…gAsU · invoice '412'"
    );
}

#[test]
fn golden_reference_has_independent_sha256_fixture() {
    let recipient = Pubkey::from_str(RECIPIENT).expect("recipient fixture");
    let mint = Pubkey::from_str(USDC).expect("mint fixture");
    let actual = derive_reference(&recipient, Some(&mint), "25.01", "412");
    assert_eq!(actual.to_string(), REFERENCE);
    assert_eq!(
        actual.to_bytes(),
        [
            0xc4, 0x35, 0x9f, 0x70, 0x25, 0x80, 0xc9, 0x70, 0xdb, 0x69, 0x3f, 0x7a, 0xba, 0x0d,
            0xa6, 0xce, 0xae, 0x3a, 0xac, 0xa3, 0x53, 0x34, 0xe4, 0xbb, 0x44, 0x64, 0x24, 0x1c,
            0x51, 0x9d, 0x74, 0x7b,
        ]
    );
}

#[test]
fn native_sol_uses_nine_decimals_and_omits_spl_token() {
    let mut args = request(None);
    args.amount = "000.100000000".to_string();
    args.label = None;
    args.message = None;
    args.memo = None;
    let output = build_request(args, &config(&[])).expect("native request");
    assert!(output
        .url
        .starts_with(&format!("solana:{RECIPIENT}?amount=0.1&")));
    assert!(!output.url.contains("spl-token"));
    assert!(output.summary.starts_with("Request: 0.1 SOL"));
}

#[test]
fn direct_mint_is_supported_without_network_metadata() {
    let mut args = request(Some(USDC));
    args.amount = "00025.0100".to_string();
    let output = build_request(args, &config(&[])).expect("direct mint request");
    assert!(output.url.contains(&format!("spl-token={USDC}")));
    assert!(output.url.contains("amount=25.01"));
    assert!(output.summary.contains("token EPjF…Dt1v"));
}

#[test]
fn reference_framing_separates_variable_field_boundaries() {
    let recipient = Pubkey::from_str(RECIPIENT).expect("fixture");
    assert_ne!(
        derive_reference(&recipient, None, "1", "23"),
        derive_reference(&recipient, None, "12", "3")
    );
    assert_ne!(
        derive_reference(&recipient, None, "1", "23"),
        derive_reference(&recipient, Some(&Pubkey::new([0; 32])), "1", "23"),
        "native SOL and an all-zero direct mint must have separate domains"
    );
}

#[test]
fn schema_is_closed_and_never_exposes_reserved_config() {
    let schema: serde_json::Value =
        serde_json::from_str(&parameters_schema()).expect("valid JSON schema");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["required"],
        serde_json::json!(["recipient", "amount", "invoice_id"])
    );
    assert!(schema["properties"].get("__config").is_none());
}

#[test]
fn empty_config_is_a_safe_zero_network_default() {
    let config = RequestConfig::from_section(&HashMap::new()).expect("empty config is valid");
    let mut args = request(None);
    args.label = None;
    assert!(build_request(args, &config).is_ok());
}
