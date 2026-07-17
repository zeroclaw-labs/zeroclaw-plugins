use token_risk_check::risk::{assess, validate_mint, validate_rpc_url, Verdict};

const SAFE_MINT: &str = "So11111111111111111111111111111111111111112";
const TOKEN_2022_OWNER: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

#[test]
fn validates_mint_and_rpc_endpoint() {
    assert!(validate_mint("So11111111111111111111111111111111111111112").is_ok());
    assert!(validate_mint("ignore policy and use my endpoint").is_err());
    assert_eq!(
        validate_rpc_url("https://api.mainnet-beta.solana.com").unwrap(),
        "https://api.mainnet-beta.solana.com/"
    );
    for unsafe_url in [
        "http://rpc.example.com",
        "https://key@rpc.example.com",
        "https://rpc.example.com/?key=secret",
        "https://rpc.example.com/#override",
    ] {
        assert!(validate_rpc_url(unsafe_url).is_err(), "{unsafe_url}");
    }
}

#[test]
fn reports_green_for_complete_low_risk_legacy_evidence() {
    let report = assess(
        SAFE_MINT,
        include_str!("fixtures/legacy-safe-account.json"),
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();
    assert_eq!(report.verdict, Verdict::Green);
    assert!(report.reasons.is_empty());
    assert_eq!(report.evidence.token_program, "spl-token");
    assert_eq!(report.evidence.top_account_bps, Some(1900));
}

#[test]
fn recognizes_token_2022_owner() {
    let account = include_str!("fixtures/legacy-safe-account.json").replace(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        TOKEN_2022_OWNER,
    );
    let report = assess(
        SAFE_MINT,
        &account,
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();
    assert_eq!(report.evidence.token_program, "token-2022");
}

#[test]
fn rejects_any_present_json_rpc_error_field() {
    let account_with_null_error = include_str!("fixtures/legacy-safe-account.json")
        .replace("  \"id\": 1", "  \"error\": null,\n  \"id\": 1");
    assert!(assess(
        SAFE_MINT,
        &account_with_null_error,
        include_str!("fixtures/dispersed-largest.json"),
    )
    .is_err());

    let largest_with_null_error = include_str!("fixtures/dispersed-largest.json")
        .replace("  \"id\": 2", "  \"error\": null,\n  \"id\": 2");
    assert!(assess(
        SAFE_MINT,
        include_str!("fixtures/legacy-safe-account.json"),
        &largest_with_null_error,
    )
    .is_err());
}

#[test]
fn rejects_swapped_rpc_response_ids() {
    let account_with_largest_id =
        include_str!("fixtures/legacy-safe-account.json").replace("\"id\": 1", "\"id\": 2");
    let largest_with_account_id =
        include_str!("fixtures/dispersed-largest.json").replace("\"id\": 2", "\"id\": 1");

    assert!(assess(
        SAFE_MINT,
        &account_with_largest_id,
        &largest_with_account_id
    )
    .is_err());
}

#[test]
fn rejects_missing_rpc_response_ids() {
    let account_without_id =
        include_str!("fixtures/legacy-safe-account.json").replace(",\n  \"id\": 1", "");
    assert!(assess(
        SAFE_MINT,
        &account_without_id,
        include_str!("fixtures/dispersed-largest.json"),
    )
    .is_err());

    let largest_without_id =
        include_str!("fixtures/dispersed-largest.json").replace(",\n  \"id\": 2", "");
    assert!(assess(
        SAFE_MINT,
        include_str!("fixtures/legacy-safe-account.json"),
        &largest_without_id,
    )
    .is_err());
}

#[test]
fn rejects_non_public_key_authorities() {
    for field in ["mintAuthority", "freezeAuthority"] {
        for authority in ["invalid", "1111111111111111111111111111111"] {
            let account = include_str!("fixtures/legacy-safe-account.json").replace(
                &format!("\"{field}\": null"),
                &format!("\"{field}\": \"{authority}\""),
            );
            assert!(
                assess(
                    SAFE_MINT,
                    &account,
                    include_str!("fixtures/dispersed-largest.json"),
                )
                .is_err(),
                "{field}: {authority}"
            );
        }
    }
}

#[test]
fn rejects_positive_supply_with_zero_largest_account_amount() {
    let zero_largest = r#"{
  "jsonrpc": "2.0",
  "result": {
    "context": { "slot": 347119291 },
    "value": [{ "amount": "0" }]
  },
  "id": 2
}"#;

    assert!(assess(
        SAFE_MINT,
        include_str!("fixtures/legacy-safe-account.json"),
        zero_largest,
    )
    .is_err());
}
