use token_risk_check::risk::{assess, validate_mint, validate_rpc_url, Verdict};

const SAFE_MINT: &str = "So11111111111111111111111111111111111111112";
const TOKEN_2022_MINT: &str = "So11111111111111111111111111111111111111112";
const TOKEN_2022_OWNER: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

fn reason_codes(report: &token_risk_check::risk::RiskReport) -> Vec<&str> {
    report
        .reasons
        .iter()
        .map(|reason| reason.code.as_str())
        .collect()
}

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

#[test]
fn marks_active_authorities_amber() {
    let report = assess(
        SAFE_MINT,
        include_str!("fixtures/legacy-authorities.json"),
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Amber);
    assert_eq!(
        reason_codes(&report),
        vec!["FREEZE_AUTHORITY_ACTIVE", "MINT_AUTHORITY_ACTIVE"]
    );
}

#[test]
fn marks_concentration_boundary_amber() {
    let report = assess(
        SAFE_MINT,
        include_str!("fixtures/legacy-safe-account.json"),
        include_str!("fixtures/concentrated-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Amber);
    assert_eq!(report.evidence.top_account_bps, Some(5_000));
    assert_eq!(reason_codes(&report), vec!["TOP_ACCOUNT_CONCENTRATED"]);
}

#[test]
fn marks_high_risk_token_2022_extensions_red() {
    let report = assess(
        TOKEN_2022_MINT,
        include_str!("fixtures/token-2022-extensions.json"),
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Red);
    assert_eq!(
        reason_codes(&report),
        vec![
            "CONFIDENTIAL_TRANSFER",
            "NON_TRANSFERABLE",
            "PERMANENT_DELEGATE",
            "TRANSFER_HOOK",
        ]
    );
}

#[test]
fn marks_fee_and_default_frozen_extensions_amber() {
    let report = assess(
        TOKEN_2022_MINT,
        include_str!("fixtures/token-2022-amber-extensions.json"),
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Amber);
    assert_eq!(
        reason_codes(&report),
        vec!["DEFAULT_FROZEN", "TRANSFER_FEE"]
    );
}

#[test]
fn marks_unknown_extensions_amber_and_truncates_reasons() {
    let report = assess(
        TOKEN_2022_MINT,
        include_str!("fixtures/token-2022-unknown-extensions.json"),
        include_str!("fixtures/dispersed-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Amber);
    assert_eq!(report.reasons.len(), 12);
    assert!(report
        .reasons
        .iter()
        .all(|reason| reason.code == "UNKNOWN_EXTENSION"));
    assert!(report
        .limitations
        .iter()
        .any(|limitation| limitation == "REASONS_TRUNCATED"));
}

#[test]
fn orders_red_reasons_before_amber_reasons_by_code() {
    let account = include_str!("fixtures/token-2022-extensions.json")
        .replace(
            "\"freezeAuthority\": null",
            "\"freezeAuthority\": \"So11111111111111111111111111111111111111112\"",
        )
        .replace(
            "\"mintAuthority\": null",
            "\"mintAuthority\": \"So11111111111111111111111111111111111111112\"",
        );
    let report = assess(
        TOKEN_2022_MINT,
        &account,
        include_str!("fixtures/concentrated-largest.json"),
    )
    .unwrap();

    assert_eq!(report.verdict, Verdict::Red);
    assert_eq!(
        reason_codes(&report),
        vec![
            "CONFIDENTIAL_TRANSFER",
            "NON_TRANSFERABLE",
            "PERMANENT_DELEGATE",
            "TRANSFER_HOOK",
            "FREEZE_AUTHORITY_ACTIVE",
            "MINT_AUTHORITY_ACTIVE",
            "TOP_ACCOUNT_CONCENTRATED",
        ]
    );
}
