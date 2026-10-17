//! Golden-vector tests for the risk scorer, over `getAccountInfo` /
//! `getTokenLargestAccounts` JSON shaped exactly like live mainnet responses.
//! Runs on the host with a plain `cargo test`, no network — the same scoring the
//! component runs inside the wasmtime host.

use serde_json::{json, Value};
use token_risk_check::risk::{assess, Verdict};

const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// A `getAccountInfo` (jsonParsed) `result` for a mint.
fn mint_acct(owner: &str, mint_auth: Value, freeze_auth: Value, supply: &str) -> Value {
    json!({
        "value": {
            "owner": owner,
            "data": { "parsed": { "type": "mint", "info": {
                "mintAuthority": mint_auth,
                "freezeAuthority": freeze_auth,
                "decimals": 6,
                "supply": supply,
                "isInitialized": true
            }}}
        }
    })
}

/// A `getTokenLargestAccounts` `result` from a list of raw amounts.
fn largest(amounts: &[&str]) -> Value {
    json!({ "value": amounts.iter().map(|a| json!({ "amount": a })).collect::<Vec<_>>() })
}

#[test]
fn clean_token_is_green() {
    let acct = mint_acct(SPL_TOKEN, Value::Null, Value::Null, "1000000");
    let r = assess("Mint1", &acct, Some(&largest(&["100", "90", "80"])));
    assert_eq!(r.verdict, Verdict::Green);
    assert!(r.mint_authority.is_none() && r.freeze_authority.is_none());
}

#[test]
fn centralized_stablecoin_is_amber() {
    // USDC-shaped: both authorities present.
    let acct = mint_acct(
        SPL_TOKEN,
        json!("BJE5MMbqXjVwjAF7oxwPYXnTXDyspzZyt4vwenNw5ruG"),
        json!("7dGbd2QZcCKcTndnHcTL8q7SMVXAkp688NTQYwrRCrar"),
        "8016240821544265",
    );
    let r = assess("EPjF...", &acct, None);
    assert_eq!(r.verdict, Verdict::Amber);
    assert!(r.mint_authority.is_some());
    assert!(r.freeze_authority.is_some());
    assert!(r.signals.iter().any(|s| s.contains("mint authority")));
    assert!(r.signals.iter().any(|s| s.contains("freeze authority")));
}

#[test]
fn severe_concentration_is_red() {
    // No authorities, but one wallet holds 60% of a 1000-supply token.
    let acct = mint_acct(SPL_TOKEN, Value::Null, Value::Null, "1000");
    let r = assess("Rug1", &acct, Some(&largest(&["600", "50", "10"])));
    assert_eq!(r.verdict, Verdict::Red);
    assert!(r.top_holder_pct.unwrap() >= 50.0);
}

#[test]
fn token_2022_is_at_least_amber() {
    let acct = mint_acct(TOKEN_2022, Value::Null, Value::Null, "1000000");
    let r = assess("T22", &acct, None);
    assert_eq!(r.verdict, Verdict::Amber);
    assert_eq!(r.token_program, "token-2022");
    assert!(r.signals.iter().any(|s| s.contains("Token-2022")));
}

#[test]
fn missing_account_fails_closed_red() {
    let acct = json!({ "value": Value::Null });
    let r = assess("Ghost", &acct, None);
    assert_eq!(r.verdict, Verdict::Red);
    assert!(r.signals[0].contains("could not verify"));
}

#[test]
fn non_mint_account_fails_closed_red() {
    let acct = json!({ "value": { "owner": SPL_TOKEN,
        "data": { "parsed": { "type": "account", "info": {} } } } });
    let r = assess("NotAMint", &acct, None);
    assert_eq!(r.verdict, Verdict::Red);
}

#[test]
fn unknown_token_program_fails_closed_red() {
    let acct = mint_acct(
        "11111111111111111111111111111111",
        Value::Null,
        Value::Null,
        "1000000",
    );
    let r = assess("WrongOwner", &acct, Some(&largest(&["10"])));
    assert_eq!(r.verdict, Verdict::Red);
    assert_eq!(r.token_program, "unknown");
    assert!(r.signals[0].contains("unknown token program owner"));
}

#[test]
fn concentration_skipped_without_largest() {
    let acct = mint_acct(SPL_TOKEN, Value::Null, Value::Null, "1000");
    let r = assess("Mint2", &acct, None);
    assert!(r.top_holder_pct.is_none() && r.top10_pct.is_none());
    assert_eq!(r.verdict, Verdict::Green); // clean token, no concentration data
}

#[test]
fn to_json_shape_is_stable() {
    let acct = mint_acct(SPL_TOKEN, Value::Null, Value::Null, "1000000");
    let r = assess("MintJ", &acct, Some(&largest(&["10"])));
    let j = r.to_json();
    assert_eq!(j["verdict"], "green");
    assert_eq!(j["token_program"], "spl-token");
    assert!(j["signals"].is_array());
}
