use std::collections::HashMap;

use solana_pay_request::pay_request::{
    build_request, execute_component_input, RequestArgs, RequestConfig, RequestError,
};

const RECIPIENT: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const OTHER: &str = "FnHyam9w4NZoWR6mKN1CuGBritdsEWZQa4Z4oawLZGxa";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn config(pairs: &[(&str, &str)]) -> RequestConfig {
    RequestConfig::from_section(&section(pairs)).expect("valid config")
}

fn args(amount: &str) -> RequestArgs {
    RequestArgs {
        recipient: RECIPIENT.to_string(),
        amount: amount.to_string(),
        spl_token: None,
        invoice_id: "invoice-412".to_string(),
        label: None,
        message: None,
        memo: None,
    }
}

#[test]
fn recipient_and_allowlist_validation_fail_closed() {
    let mut invalid = args("1");
    invalid.recipient = "not a public key".to_string();
    assert_eq!(
        build_request(invalid, &config(&[])),
        Err(RequestError::InvalidRecipient)
    );

    let locked = config(&[("allowed_recipients", OTHER)]);
    assert_eq!(
        build_request(args("1"), &locked),
        Err(RequestError::RecipientNotAllowed)
    );

    let deny_all = config(&[("allowed_recipients", "")]);
    assert_eq!(
        build_request(args("1"), &deny_all),
        Err(RequestError::RecipientNotAllowed)
    );
}

#[test]
fn sol_amount_rejects_ambiguous_precision_and_overflow() {
    for amount in [
        "",
        ".5",
        "1.",
        "-1",
        "+1",
        "1e2",
        " 1",
        "1 ",
        "1.0000000000",
        "18446744073.709551616",
        "１２",
    ] {
        assert!(
            matches!(
                build_request(args(amount), &config(&[])),
                Err(RequestError::EmptyField("amount") | RequestError::InvalidAmount(_))
            ),
            "accepted invalid amount {amount:?}"
        );
    }
    assert!(build_request(args("0"), &config(&[])).is_ok());
    assert!(build_request(args("0.000000001"), &config(&[])).is_ok());
}

#[test]
fn alias_precision_is_enforced_from_operator_config() {
    let aliases = format!("USDC={USDC}");
    let valid = config(&[("mint_aliases", &aliases), ("mint_decimals", "USDC=6")]);
    let mut request = args("1.000001");
    request.spl_token = Some("USDC".to_string());
    assert!(build_request(request.clone(), &valid).is_ok());
    request.amount = "1.0000001".to_string();
    assert!(matches!(
        build_request(request, &valid),
        Err(RequestError::InvalidAmount(_))
    ));

    assert!(matches!(
        RequestConfig::from_section(&section(&[("mint_aliases", &aliases)])),
        Err(RequestError::MissingAliasDecimals(alias)) if alias == "USDC"
    ));
}

#[test]
fn aliases_and_config_are_parsed_strictly() {
    let aliases = format!("USDC={USDC}");
    for bad in [
        section(&[("mint_aliases", "USDC")]),
        section(&[
            ("mint_aliases", "1BAD=11111111111111111111111111111111"),
            ("mint_decimals", "1BAD=9"),
        ]),
        section(&[("mint_aliases", &aliases), ("mint_decimals", "USDC=20")]),
        section(&[("mint_aliases", &aliases), ("mint_decimals", "OTHER=6")]),
        section(&[("mint_aliases", "USDC=bad"), ("mint_decimals", "USDC=6")]),
        section(&[("allowed_recipients", "bad")]),
        section(&[("allowed_recipient", RECIPIENT)]),
    ] {
        assert!(
            RequestConfig::from_section(&bad).is_err(),
            "accepted {bad:?}"
        );
    }
}

#[test]
fn unknown_alias_and_malformed_direct_mint_are_distinct_refusals() {
    let mut request = args("1");
    request.spl_token = Some("EVIL".to_string());
    assert_eq!(
        build_request(request.clone(), &config(&[])),
        Err(RequestError::UnknownMintAlias("EVIL".to_string()))
    );
    request.spl_token = Some("not!an!alias".to_string());
    assert_eq!(
        build_request(request, &config(&[])),
        Err(RequestError::InvalidMint)
    );
}

#[test]
fn field_and_wire_limits_are_enforced() {
    let mut request = args("1");
    request.invoice_id = "x".repeat(129);
    assert!(matches!(
        build_request(request, &config(&[])),
        Err(RequestError::FieldTooLong {
            field: "invoice_id",
            ..
        })
    ));

    let mut request = args("1");
    request.invoice_id = "invoice\n412".to_string();
    assert_eq!(
        build_request(request, &config(&[])),
        Err(RequestError::InvalidControlCharacter("invoice_id"))
    );

    let mut request = args("1");
    request.label = Some("é".repeat(64));
    request.message = Some("é".repeat(128));
    request.memo = Some("é".repeat(128));
    assert!(matches!(
        build_request(request, &config(&[])),
        Err(RequestError::UrlTooLong(_))
    ));
}

#[test]
fn component_maps_bad_input_to_model_visible_refusals() {
    for input in [
        "not json",
        "[]",
        r#"{"recipient":"bad","amount":"1","invoice_id":"1"}"#,
        &format!(
            r#"{{"recipient":"{RECIPIENT}","amount":"1","invoice_id":"1","unexpected":true}}"#
        ),
    ] {
        let result = execute_component_input(input);
        assert!(!result.success);
        assert!(result.output.is_empty());
        assert!(result.error.is_some());
    }
}
