//! Extra host vectors to harden encoding / policy edges.

use caixa_core::base58;
use caixa_core::base64;
use caixa_core::memo::{build_invoice_memo, memo_contains_invoice};
use caixa_core::output::{shape_output, MAX_OUTPUT_CHARS};
use caixa_core::pay::{build_solana_pay_url, PayRequest};
use caixa_core::pubkey::{
    get_associated_token_address, usdc_mint_mainnet, Pubkey, SYSTEM_PROGRAM_ID,
};
use caixa_core::quote::{format_usdc, usdc_to_base_units};
use caixa_core::shortvec::encode_len;
use caixa_core::spl::{
    advance_nonce_instruction, create_associated_token_account_idempotent, memo_instruction,
    spl_transfer_checked,
};

#[test]
fn base58_empty_and_ones() {
    assert_eq!(base58::encode(&[]), "");
    assert_eq!(base58::decode("").unwrap(), Vec::<u8>::new());
    assert!(base58::decode("0").is_err()); // invalid alphabet
}

#[test]
fn base64_whitespace_tolerant() {
    assert_eq!(base64::decode("Zm9 v\n").unwrap(), b"foo");
}

#[test]
fn shortvec_large() {
    assert_eq!(encode_len(16383).len(), 2);
}

#[test]
fn format_usdc_rounding() {
    assert_eq!(format_usdc(1.2345674), "1.234567");
    assert_eq!(format_usdc(1.2345675), "1.234568");
}

#[test]
fn usdc_units_reject_letters() {
    assert!(usdc_to_base_units("12a").is_err());
}

#[test]
fn memo_rejects_whitespace_invoice() {
    assert!(build_invoice_memo("bad id", None, None).is_err());
}

#[test]
fn memo_match_is_token_aware() {
    assert!(memo_contains_invoice("INV=412 BRL=1", "412"));
    assert!(!memo_contains_invoice("INV=4120", "412")); // substring trap
}

#[test]
fn pay_url_rejects_empty_amount() {
    assert!(build_solana_pay_url(&PayRequest {
        recipient: SYSTEM_PROGRAM_ID,
        amount: "".into(),
        spl_token: None,
        memo: None,
        reference: None,
        label: None,
        message: None,
    })
    .is_err());
}

#[test]
fn ata_differs_by_mint() {
    let wallet = Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let a = get_associated_token_address(&wallet, &usdc_mint_mainnet()).unwrap();
    let b = get_associated_token_address(&wallet, &SYSTEM_PROGRAM_ID).unwrap();
    assert_ne!(a, b);
}

#[test]
fn instruction_bytes_nonempty() {
    let owner = Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    let mint = usdc_mint_mainnet();
    let ata = get_associated_token_address(&owner, &mint).unwrap();
    let ix = spl_transfer_checked(&ata, &mint, &ata, &owner, 1, 6);
    assert_eq!(ix.data[0], 12);
    let memo = memo_instruction("hi", &[&owner]);
    assert_eq!(memo.data, b"hi");
    let create = create_associated_token_account_idempotent(&owner, &owner, &mint);
    assert_eq!(create.data, vec![1]);
    let nonce = Pubkey::from_base58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
    let adv = advance_nonce_instruction(&nonce, &owner);
    assert_eq!(adv.data, 4u32.to_le_bytes());
}

#[test]
fn shape_preserves_short() {
    assert_eq!(shape_output("  ok  "), "ok");
    assert!(shape_output(&"a".repeat(MAX_OUTPUT_CHARS + 50)).ends_with('…'));
}

#[test]
fn pubkey_short_format() {
    let p = usdc_mint_mainnet();
    let s = p.short();
    assert!(s.contains('…'));
    assert!(s.len() < p.to_base58().len());
}
