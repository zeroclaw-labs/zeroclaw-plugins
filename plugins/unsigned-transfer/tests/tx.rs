//! Tests for the unsigned-transaction assembly, over the public API the wasm
//! `execute` path uses. Offline: assembles + serializes, then decodes the wire
//! bytes back with bincode to check the structure (no network, no keys).

use base64::{engine::general_purpose::STANDARD, Engine};
use solana_transaction::Transaction;
use unsigned_transfer::tx::{build_sol_transfer, build_spl_transfer, ui_to_base_units};

const FROM: &str = "GDDMwNyyx8uB6zrqwBFHjLLG3TBYk2F8Az4yrQC5RzMp";
const TO: &str = "So11111111111111111111111111111111111111112";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const BLOCKHASH: &str = "11111111111111111111111111111111";

fn decode(b64: &str) -> Transaction {
    let wire = STANDARD.decode(b64).unwrap();
    bincode::deserialize(&wire).unwrap()
}

#[test]
fn ui_amount_conversion_is_integer_exact() {
    assert_eq!(ui_to_base_units("1.5", 9).unwrap(), 1_500_000_000);
    assert_eq!(ui_to_base_units("10", 9).unwrap(), 10_000_000_000);
    assert_eq!(ui_to_base_units("0.000000001", 9).unwrap(), 1);
    assert_eq!(ui_to_base_units("25", 6).unwrap(), 25_000_000);
    assert_eq!(ui_to_base_units("0.5", 6).unwrap(), 500_000);
}

#[test]
fn ui_amount_rejects_bad_input() {
    assert!(ui_to_base_units("1.2.3", 9).is_err());
    assert!(ui_to_base_units("-1", 9).is_err());
    assert!(ui_to_base_units("abc", 9).is_err());
    assert!(ui_to_base_units("0.0000000001", 9).is_err()); // over-precision (10 dp > 9)
    assert!(ui_to_base_units("", 9).is_err());
}

#[test]
fn sol_transfer_assembles_unsigned() {
    let b64 = build_sol_transfer(FROM, TO, 1_000_000, BLOCKHASH).unwrap();
    let tx = decode(&b64);
    // Unsigned: exactly one (empty) signature slot for the single signer/payer.
    assert_eq!(tx.signatures.len(), 1);
    assert_eq!(tx.signatures[0], solana_signature::Signature::default());
    // One instruction, and the payer (from) is the first account key.
    assert_eq!(tx.message.instructions.len(), 1);
    assert_eq!(tx.message.account_keys[0].to_string(), FROM);
}

#[test]
fn sol_transfer_rejects_bad_pubkeys() {
    assert!(build_sol_transfer("not-a-key", TO, 1, BLOCKHASH).is_err());
    assert!(build_sol_transfer(FROM, "nope", 1, BLOCKHASH).is_err());
    assert!(build_sol_transfer(FROM, TO, 1, "bad blockhash!").is_err());
}

#[test]
fn spl_transfer_assembles_with_ata_creation() {
    // create_dest_ata = true -> 2 instructions (create ATA + transfer_checked).
    let b64 = build_spl_transfer(FROM, TO, USDC, 25_000_000, 6, true, BLOCKHASH).unwrap();
    let tx = decode(&b64);
    assert_eq!(tx.signatures.len(), 1);
    assert_eq!(tx.message.instructions.len(), 2);
    assert_eq!(tx.message.account_keys[0].to_string(), FROM);
}

#[test]
fn spl_transfer_without_ata_creation_is_single_ix() {
    let b64 = build_spl_transfer(FROM, TO, USDC, 25_000_000, 6, false, BLOCKHASH).unwrap();
    let tx = decode(&b64);
    assert_eq!(tx.message.instructions.len(), 1);
}
