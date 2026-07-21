use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::json;
use solana_token_risk::risk::{
    parse_largest_accounts, parse_mint_account, render_summary, validate_mint,
};

const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

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

fn raw_mint_result(data: Vec<u8>) -> serde_json::Value {
    json!({
        "value": {
            "owner": TOKEN_2022_PROGRAM,
            "data": [BASE64.encode(data), "base64"]
        }
    })
}

fn tlv_entry(extension_type: u16, value: &[u8]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(4 + value.len());
    entry.extend_from_slice(&extension_type.to_le_bytes());
    entry.extend_from_slice(&(value.len() as u16).to_le_bytes());
    entry.extend_from_slice(value);
    entry
}

fn token_2022_mint_with_risk_extensions() -> Vec<u8> {
    // A valid initialized base mint, padded to the Token-2022 extension layout:
    // 165 bytes of base/padding, one Mint account-type byte, then TLV entries.
    let mut data = vec![0_u8; 166];
    data[36..44].copy_from_slice(&1_000_000_000_u64.to_le_bytes());
    data[44] = 6;
    data[45] = 1;
    data[165] = 1; // AccountType::Mint

    let mut transfer_fee = vec![0_u8; 108];
    transfer_fee[98..106].copy_from_slice(&1_000_000_u64.to_le_bytes());
    transfer_fee[106..108].copy_from_slice(&150_u16.to_le_bytes());
    data.extend_from_slice(&tlv_entry(1, &transfer_fee)); // TransferFeeConfig
    data.extend_from_slice(&tlv_entry(12, &[7_u8; 32])); // PermanentDelegate

    let mut transfer_hook = vec![0_u8; 64];
    transfer_hook[..32].fill(8);
    transfer_hook[32..].fill(9);
    data.extend_from_slice(&tlv_entry(14, &transfer_hook)); // TransferHook
    data.extend_from_slice(&tlv_entry(9, &[])); // NonTransferable
    data
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

#[test]
fn parses_token_2022_extensions_from_canonical_base64_account_data() {
    let mint = parse_mint_account(&raw_mint_result(token_2022_mint_with_risk_extensions()))
        .expect("Token-2022 fixture must parse");

    assert_eq!(mint.owner_program, TOKEN_2022_PROGRAM);
    assert_eq!(mint.supply, 1_000_000_000);
    assert!(mint.token_2022_extensions.is_some());

    let summary = render_summary(
        USDC_MINT,
        &mint,
        &parse_largest_accounts(&json!({"value": []}), mint.supply).unwrap(),
    );
    assert!(summary.contains("TransferFeeConfig"));
    assert!(summary.contains("1.50%"));
    assert!(summary.contains("Permanent delegate: present"));
    assert!(summary.contains("Transfer hook: present"));
    assert!(summary.contains("NonTransferable"));
}

#[test]
fn rejects_malformed_token_2022_extension_tlv() {
    let mut malformed = token_2022_mint_with_risk_extensions();
    malformed.truncate(166 + 4 + 4);
    assert!(parse_mint_account(&raw_mint_result(malformed)).is_err());
}
