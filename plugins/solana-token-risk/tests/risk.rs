use serde_json::json;
use solana_token_risk::risk::{
    parse_largest_accounts, parse_mint_account, render_summary, validate_mint,
};

const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

fn mint_result(
    mint_authority: serde_json::Value,
    freeze_authority: serde_json::Value,
) -> serde_json::Value {
    json!({
        "value": {
            "owner": TOKEN_PROGRAM,
            "data": {
                "parsed": {
                    "info": {
                        "supply": "1000000000",
                        "decimals": 6,
                        "mintAuthority": mint_authority,
                        "freezeAuthority": freeze_authority
                    }
                }
            }
        }
    })
}

#[test]
fn accepts_a_32_byte_base58_mint() {
    assert_eq!(validate_mint(USDC_MINT).unwrap(), USDC_MINT);
}

#[test]
fn rejects_non_public_key_input() {
    assert!(validate_mint("not-a-mint").is_err());
    assert!(validate_mint("1111111111111111111111111111111").is_err());
}

#[test]
fn parses_fixed_supply_mint_and_account_concentration() {
    let mint = parse_mint_account(&mint_result(
        serde_json::Value::Null,
        serde_json::Value::Null,
    ))
    .unwrap();
    assert_eq!(mint.supply, 1_000_000_000);
    assert_eq!(mint.decimals, 6);
    assert!(mint.mint_authority.is_none());
    assert!(mint.freeze_authority.is_none());

    let largest = json!({
        "value": [
            {"amount": "600000000"},
            {"amount": "200000000"},
            {"amount": "100000000"},
            {"amount": "30000000"},
            {"amount": "20000000"}
        ]
    });
    let concentration = parse_largest_accounts(&largest, mint.supply).unwrap();
    assert_eq!(concentration.top_one_bps, 6_000);
    assert_eq!(concentration.top_five_bps, 9_500);
    assert_eq!(concentration.returned_accounts, 5);

    let output = render_summary(USDC_MINT, &mint, &concentration);
    assert!(output.contains("Mint authority: absent."));
    assert!(output.contains("top 5 95.00%"));
    assert!(output.contains("not unique-holder concentration"));
    assert!(output.contains("No transaction, signature, private key, or wallet access"));
}

#[test]
fn renders_authority_controls_without_calling_them_safe() {
    let mint = parse_mint_account(&mint_result(
        json!("7YttLkHDoNjQ89XxK4DNVEt4uZVRKjNeyToNwEj7Cgdy"),
        json!("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"),
    ))
    .unwrap();
    let concentration = parse_largest_accounts(&json!({"value": []}), mint.supply).unwrap();
    let output = render_summary(USDC_MINT, &mint, &concentration);
    assert!(output.contains("Mint authority: present"));
    assert!(output.contains("Freeze authority: present"));
    assert!(output.contains("mint authority is present; freeze authority is present"));
}

#[test]
fn rejects_unparsed_or_malformed_rpc_results() {
    assert!(parse_mint_account(&json!({"value": null})).is_err());
    assert!(parse_mint_account(&json!({"value": {"owner": TOKEN_PROGRAM}})).is_err());
    assert!(parse_largest_accounts(&json!({"value": [{"amount": "not-a-number"}]}), 1).is_err());
}
