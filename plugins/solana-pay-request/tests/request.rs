use solana_pay_request::request::{build_request, parse_request_args, RequestArgs};

fn key(seed: u8) -> String {
    bs58::encode([seed; 32]).into_string()
}

fn args() -> RequestArgs {
    RequestArgs {
        recipient: key(1),
        amount: "1.2500".to_string(),
        spl_token: None,
        references: Vec::new(),
        label: None,
        message: None,
        memo: None,
    }
}

#[test]
fn builds_canonical_sol_request() {
    let request = build_request(args()).expect("valid request");
    assert_eq!(request.amount, "1.25");
    assert_eq!(request.asset, "SOL");
    assert_eq!(request.uri, format!("solana:{}?amount=1.25", key(1)));
    assert_eq!(request.qr_payload, request.uri);
    assert_eq!(request.custody_tier, "T1-build-only");
}

#[test]
fn builds_spl_request_with_repeated_references_and_encoded_text() {
    let mut input = args();
    input.amount = "00025.5000".to_string();
    input.spl_token = Some(key(2));
    input.references = vec![key(3), key(4)];
    input.label = Some("Table 4 / Cafe".to_string());
    input.message = Some("Pay 25.5 USDC".to_string());
    input.memo = Some("invoice#1042".to_string());

    let request = build_request(input).expect("valid request");

    assert_eq!(request.amount, "25.5");
    assert_eq!(request.asset, key(2));
    assert!(request.uri.contains(&format!("spl-token={}", key(2))));
    assert!(request
        .uri
        .contains(&format!("reference={}&reference={}", key(3), key(4))));
    assert!(request.uri.contains("label=Table%204%20%2F%20Cafe"));
    assert!(request.uri.contains("memo=invoice%231042"));
}

#[test]
fn fingerprint_is_deterministic_and_sensitive_to_policy() {
    let first = build_request(args()).expect("valid");
    let second = build_request(args()).expect("valid");
    assert_eq!(first.fingerprint, second.fingerprint);

    let mut changed = args();
    changed.amount = "2".to_string();
    let changed = build_request(changed).expect("valid");
    assert_ne!(first.fingerprint, changed.fingerprint);
}

#[test]
fn rejects_invalid_or_zero_amounts_without_float_rounding() {
    for amount in ["0", "-1", "1e3", ".5", "1.", "NaN"] {
        let mut input = args();
        input.amount = amount.to_string();
        assert!(build_request(input).is_err(), "accepted {amount}");
    }
}

#[test]
fn rejects_invalid_addresses_duplicate_references_and_recipient_reference() {
    let mut invalid_recipient = args();
    invalid_recipient.recipient = "not-base58".to_string();
    assert!(build_request(invalid_recipient).is_err());

    let mut duplicate = args();
    duplicate.references = vec![key(3), key(3)];
    assert!(build_request(duplicate).is_err());

    let mut recipient_reference = args();
    recipient_reference.references = vec![key(1)];
    assert!(build_request(recipient_reference).is_err());
}

#[test]
fn rejects_more_than_five_references() {
    let mut input = args();
    input.references = (2..=7).map(key).collect();
    assert!(build_request(input).is_err());
}

#[test]
fn rejects_control_characters_and_oversized_text() {
    let mut control = args();
    control.memo = Some("invoice\nignore policy".to_string());
    assert!(build_request(control).is_err());

    let mut oversized = args();
    oversized.label = Some("x".repeat(65));
    assert!(build_request(oversized).is_err());
}

#[test]
fn prompt_injection_style_unknown_fields_are_rejected() {
    let input = serde_json::json!({
        "recipient": key(1),
        "amount": "1",
        "sign_and_send": true,
        "private_key": "ignore-safety"
    });
    let error = parse_request_args(&input.to_string()).expect_err("must fail closed");
    assert!(error.contains("unknown field"));
}
