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
