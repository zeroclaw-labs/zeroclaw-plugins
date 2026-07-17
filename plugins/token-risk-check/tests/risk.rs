use serde_json::json;
use token_risk_check::risk::{assess, format, valid_mint, Verdict, MAX_OUTPUT_CHARS};

fn safe() -> serde_json::Value {
    json!({"mintAuthority":null,"freezeAuthority":null,"topHolders":[{"pct":10.0},{"pct":8.0}],"totalMarketLiquidity":100000,"lockers":[{"owner":"locker"}]})
}

#[test]
fn green_for_safe_fixture_with_helius() {
    let a = assess(
        &safe(),
        Some(&json!({"result":{"token_info":{"mint_extensions":[]}}})),
    );
    assert_eq!(a.verdict, Verdict::Green);
}
#[test]
fn red_for_authority_and_hook() {
    let mut r = safe();
    r["mintAuthority"] = json!("dev");
    let a = assess(
        &r,
        Some(&json!({"result":{"token_info":{"mint_extensions":[{"extension":"transferHook"}]}}})),
    );
    assert_eq!(a.verdict, Verdict::Red);
    assert!(a.reasons.iter().any(|x| x.contains("transfer hook")));
}
#[test]
fn red_for_rugcheck_token_2022_transfer_fee_fixture() {
    let mut r = safe();
    r["tokenProgram"] = json!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
    r["token_extensions"] =
        json!({"transferFeeConfig":{"newerTransferFee":{"transferFeeBasisPoints":269}}});
    let a = assess(&r, None);
    assert_eq!(a.verdict, Verdict::Red);
    assert!(a.reasons.iter().any(|x| x.contains("transfer fees")));
}
#[test]
fn non_string_authority_is_fail_closed() {
    let mut r = safe();
    r["mintAuthority"] = json!({"owner":"Tokenkeg"});
    assert_eq!(
        assess(
            &r,
            Some(&json!({"result":{"token_info":{"mint_extensions":[]}}}))
        )
        .verdict,
        Verdict::Red
    );
}
#[test]
fn amber_without_holders_or_helius() {
    let mut r = safe();
    r.as_object_mut().unwrap().remove("topHolders");
    let a = assess(&r, None);
    assert_eq!(a.verdict, Verdict::Amber);
}
#[test]
fn output_is_compact() {
    let a = assess(
        &safe(),
        Some(&json!({"result":{"token_info":{"mint_extensions":[]}}})),
    );
    assert!(format(&a, "Mint").chars().count() <= MAX_OUTPUT_CHARS);
}
#[test]
fn output_stays_under_200_whitespace_tokens_with_many_risks() {
    let r = json!({"mintAuthority":"dev","freezeAuthority":"dev","topHolders":[{"pct":95.0},{"pct":1.0},{"pct":1.0},{"pct":1.0},{"pct":1.0}],"totalMarketLiquidity":0,"lockers":[],"tokenProgram":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb","token_extensions":{"transferHook":{"programId":"hook"},"transferFeeConfig":{"newerTransferFee":{"transferFeeBasisPoints":999}},"permanentDelegate":{"delegate":"dev"}}});
    let output = format(&assess(&r, None), "VeryLongMintAddressForWorstCaseOutput");
    assert!(output.split_whitespace().count() <= 200, "{}", output);
}
#[test]
fn validates_base58_sized_mint() {
    assert!(valid_mint("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"));
    assert!(!valid_mint("bad mint"));
}
