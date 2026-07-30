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

// These three vectors were executed against @solana/pay 1.0.22 built from
// solana-foundation/solana-pay commit
// 9b0f8ec70c509c946c387633ae4f1e3115ea4958. The version exists in that
// commit's package metadata but was not published to the npm registry.

#[test]
fn official_encoder_vector_native_sol_with_minimal_optional_fields() {
    let args = RequestArgs {
        recipient: RECIPIENT.to_string(),
        amount: "0.000000001".to_string(),
        spl_token: None,
        invoice_id: "native-minimal".to_string(),
        label: None,
        message: None,
        memo: None,
    };
    let output = build_request(args, &config(&[])).expect("native request");
    assert_eq!(
        output.reference,
        "DHCFLQhCbvgeTcEyT3W1dHsWUs5CBctiFVcGKeM8uvfF"
    );
    assert_eq!(
        output.url,
        format!(
            "solana:{RECIPIENT}?amount=0.000000001&reference=DHCFLQhCbvgeTcEyT3W1dHsWUs5CBctiFVcGKeM8uvfF"
        )
    );
}

#[test]
fn official_encoder_vector_spl_token_without_display_text() {
    let args = RequestArgs {
        recipient: RECIPIENT.to_string(),
        amount: "1".to_string(),
        spl_token: Some(USDC.to_string()),
        invoice_id: "spl-no-display".to_string(),
        label: None,
        message: None,
        memo: None,
    };
    let output = build_request(args, &config(&[])).expect("SPL request");
    assert_eq!(
        output.reference,
        "3j5zDAAzj2JyFd5acUoebBzUPhQfVoFLf4pcDyYJcJZ6"
    );
    assert_eq!(
        output.url,
        format!(
            "solana:{RECIPIENT}?amount=1&spl-token={USDC}&reference=3j5zDAAzj2JyFd5acUoebBzUPhQfVoFLf4pcDyYJcJZ6"
        )
    );
}

#[test]
fn official_encoder_vector_reserved_and_unicode_display_text() {
    let args = RequestArgs {
        recipient: RECIPIENT.to_string(),
        amount: "2.5".to_string(),
        spl_token: Some(USDC.to_string()),
        invoice_id: "unicode-reserved".to_string(),
        label: Some("零售 & Café/東京?".to_string()),
        message: Some("Lunch + tea = 5€ #42".to_string()),
        memo: Some("订单/№42 & paid?".to_string()),
    };
    let output = build_request(args, &config(&[])).expect("Unicode request");
    assert_eq!(
        output.reference,
        "321DJEUiLJ2sYEqqdimnbzYvMFxgQ9sheyTtPdv5oQs1"
    );
    assert_eq!(
        output.url,
        format!(
            "solana:{RECIPIENT}?amount=2.5&spl-token={USDC}\
             &reference=321DJEUiLJ2sYEqqdimnbzYvMFxgQ9sheyTtPdv5oQs1\
             &label=%E9%9B%B6%E5%94%AE+%26+Caf%C3%A9%2F%E6%9D%B1%E4%BA%AC%3F\
             &message=Lunch+%2B+tea+%3D+5%E2%82%AC+%2342\
             &memo=%E8%AE%A2%E5%8D%95%2F%E2%84%9642+%26+paid%3F"
        )
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

/// The cross-plugin contract with `solana-pay-confirm`.
///
/// That plugin never accepts a reference: it re-derives one from the same four
/// invoice fields and scans the cluster for it. The frozen vector below is
/// asserted from both sides — see
/// `plugins/solana-pay-confirm/tests/golden_reference.rs`,
/// `the_derived_reference_matches_the_frozen_cross_plugin_vector` — so a change
/// to the derivation, the canonical amount, or the framing fails a test in both
/// plugins rather than silently making every request unconfirmable.
#[test]
fn golden_reference_vector_is_shared_with_solana_pay_confirm() {
    const CONFIRM_RECIPIENT: &str = "FnHyam9w4NZoWR6mKN1CuGBritdsEWZQa4Z4oawLZGxa";
    const GOLDEN_REFERENCE: &str = "3FrMXf9ucXff2biCaz5ehKYr1yguHjWvwLcy8ALDVEnw";

    let config = config(&[
        ("mint_aliases", &format!("USDC={USDC}")),
        ("mint_decimals", "USDC=6"),
        ("allowed_recipients", CONFIRM_RECIPIENT),
    ]);
    let args = RequestArgs {
        recipient: CONFIRM_RECIPIENT.to_string(),
        amount: "1.5".to_string(),
        spl_token: Some("USDC".to_string()),
        invoice_id: "412".to_string(),
        label: None,
        message: None,
        memo: None,
    };
    let output = build_request(args, &config).expect("build request");

    assert_eq!(output.reference, GOLDEN_REFERENCE);
    assert_eq!(
        output.url,
        format!(
            "solana:{CONFIRM_RECIPIENT}?amount=1.5&spl-token={USDC}&reference={GOLDEN_REFERENCE}"
        )
    );

    // A wallet reads the reference out of the URL; that is the exact value the
    // confirm plugin derives from the invoice alone.
    let from_url = output
        .url
        .split("reference=")
        .nth(1)
        .expect("reference query parameter")
        .split('&')
        .next()
        .expect("reference value");
    assert_eq!(from_url, GOLDEN_REFERENCE);

    // Trailing-zero and leading-zero spellings of the same amount canonicalise
    // to the same reference, so "1.50" and "1.5" are one invoice, not two.
    for spelling in ["1.50", "1.500000", "01.5"] {
        let args = RequestArgs {
            recipient: CONFIRM_RECIPIENT.to_string(),
            amount: spelling.to_string(),
            spl_token: Some("USDC".to_string()),
            invoice_id: "412".to_string(),
            label: None,
            message: None,
            memo: None,
        };
        assert_eq!(
            build_request(args, &config)
                .expect("build request")
                .reference,
            GOLDEN_REFERENCE,
            "amount spelling {spelling} derived a different reference"
        );
    }
}
