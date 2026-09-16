//! Verification run against a real, finalized mainnet payment.
//!
//! `tests/fixtures/mainnet_usdc_payment.json` is a verbatim capture of a public
//! mainnet-beta `getSignaturesForAddress` entry and `getTransaction` response for
//! signature
//! `3yrMvnqXgMaukWqBi7heAn1ZqsoWmWhmivWwU1AbKhX7cRWCL5PBn3krUPvkpQrKoUL6dpUCbibUvX7CYqBLGuik`
//! (slot 436144302): a v0 message carrying a single SPL Token `Transfer` of
//! 5 202 USDC base units into the canonical associated token account of
//! `9TFHAowAEo1Xf2qD9KBBEzNuoaYNGjD2AhV8iYEdrkpc`.
//!
//! The capture script derived that ATA with an independent Python implementation
//! of Solana's PDA derivation, including the Ed25519 off-curve check, so the
//! agreement asserted below is a cross-check rather than a self-consistency
//! check. The transaction carries no Solana Pay reference — it is an ordinary
//! payment, not one made against a request from `solana-pay-request` — which is
//! exactly why it must be refused, and refused for that one reason.
//!
//! Everything here is offline: the bytes were fetched once and committed.

use std::str::FromStr;

use nanosol::{
    inspect::{decode_signed_transaction, find_token_transfers, TokenTransferKind},
    instruction::TokenProgram,
    message::MessageVersion,
    pubkey::{derive_associated_token_address, Pubkey},
    reference::derive_payment_reference,
    rpc::{
        parse_signatures_for_address_response, parse_transaction_response, CommitmentLevel,
        TransactionRecord,
    },
};
use serde_json::Value;
use solana_pay_confirm::confirm::{verify_record, ExpectedPayment, Rejection};

const FIXTURE: &str = include_str!("fixtures/mainnet_usdc_payment.json");
const SIGNATURE: &str =
    "3yrMvnqXgMaukWqBi7heAn1ZqsoWmWhmivWwU1AbKhX7cRWCL5PBn3krUPvkpQrKoUL6dpUCbibUvX7CYqBLGuik";
const RECIPIENT_OWNER: &str = "9TFHAowAEo1Xf2qD9KBBEzNuoaYNGjD2AhV8iYEdrkpc";
const DESTINATION_ATA: &str = "5RZHGLtc1TLGgX5fuNFKnmhZvBFtN6uFjBTUGP1JRTFM";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const RAW_AMOUNT: u64 = 5_202;
const SLOT: u64 = 436_144_302;
const DECIMALS: u8 = 6;

fn key(value: &str) -> Pubkey {
    Pubkey::from_str(value).expect("public key")
}

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture JSON")
}

fn records() -> (nanosol::rpc::SignatureRecord, TransactionRecord) {
    let fixture = fixture();
    let listed = parse_signatures_for_address_response(
        &serde_json::to_string(&fixture["signatures_response"]).expect("signature envelope"),
        1,
    )
    .expect("real signature list");
    let record = parse_transaction_response(
        &serde_json::to_string(&fixture["transaction_response"]).expect("transaction envelope"),
        100,
    )
    .expect("real transaction");
    (listed.into_iter().next().expect("one entry"), record)
}

fn expected(reference: Pubkey) -> ExpectedPayment {
    let (destination_ata, _) = derive_associated_token_address(
        &key(RECIPIENT_OWNER),
        &key(USDC),
        &TokenProgram::Legacy.id(),
    )
    .expect("ATA derivation");
    // The locally derived ATA must equal the account the real payment actually
    // credited, and the address the independent Python oracle derived.
    assert_eq!(destination_ata, key(DESTINATION_ATA));
    ExpectedPayment {
        recipient: key(RECIPIENT_OWNER),
        mint: key(USDC),
        destination_ata,
        token_program: TokenProgram::Legacy,
        decimals: DECIMALS,
        raw_amount: RAW_AMOUNT,
        reference,
        min_commitment: CommitmentLevel::Finalized,
    }
}

#[test]
fn the_real_mainnet_response_parses_into_exactly_the_fields_verification_needs() {
    let (listed, record) = records();
    assert_eq!(listed.signature.to_string(), SIGNATURE);
    assert_eq!(listed.slot, SLOT);
    assert!(!listed.failed);
    assert_eq!(listed.confirmation_status, Some(CommitmentLevel::Finalized));

    assert_eq!(record.slot, SLOT);
    assert!(!record.failed);
    assert!(!record.transaction.is_empty());

    // Endpoint prose is dropped: the parsed record has no logs, inner
    // instructions, fee, or status fields to leak.
    let raw = serde_json::to_string(&fixture()["transaction_response"]).expect("envelope");
    assert!(raw.contains("logMessages"));
    assert!(raw.contains("innerInstructions"));
    assert!(!format!("{record:?}").contains("Program log"));
}

#[test]
fn the_real_mainnet_transfer_decodes_and_its_balance_delta_reconciles() {
    let (_, record) = records();
    let transaction = decode_signed_transaction(&record.transaction).expect("real wire bytes");
    assert_eq!(transaction.message.version, MessageVersion::V0);
    assert_eq!(transaction.signatures.len(), 1);

    let transfers = find_token_transfers(&transaction.message).expect("transfer scan");
    assert_eq!(transfers.len(), 1);
    let transfer = &transfers[0].1;
    // A real wallet used the plain `Transfer` encoding, which names no mint and
    // asserts no decimals: the shape the decoder had to support to avoid
    // refusing real payments.
    assert_eq!(transfer.kind, TokenTransferKind::Transfer);
    assert_eq!(transfer.mint, None);
    assert_eq!(transfer.decimals, None);
    assert_eq!(transfer.token_program, TokenProgram::Legacy);
    assert_eq!(transfer.amount, RAW_AMOUNT);
    assert_eq!(transfer.destination, key(DESTINATION_ATA));
    assert!(transfer.extra_accounts.is_empty());

    // The balance delta reconciles against the instruction amount, computed from
    // the real pre/post token balances at the destination's account index.
    let index = transaction
        .message
        .account_keys
        .iter()
        .position(|account| account == &key(DESTINATION_ATA))
        .expect("destination in account keys");
    let post = record
        .post_token_balances
        .iter()
        .find(|balance| balance.account_index == index)
        .expect("post balance");
    let pre = record
        .pre_token_balances
        .iter()
        .find(|balance| balance.account_index == index)
        .expect("pre balance");
    assert_eq!(post.mint, key(USDC));
    assert_eq!(post.owner, Some(key(RECIPIENT_OWNER)));
    assert_eq!(post.decimals, DECIMALS);
    assert_eq!(post.raw_amount - pre.raw_amount, RAW_AMOUNT);
}

#[test]
fn a_real_payment_without_the_invoice_reference_is_refused_for_exactly_that_reason() {
    let (listed, record) = records();
    // An invoice whose terms match this real payment exactly: same recipient,
    // same mint, same amount. Only the binding is missing, because this payment
    // was not made against a request from `solana-pay-request`.
    let reference = derive_payment_reference(
        &key(RECIPIENT_OWNER),
        Some(&key(USDC)),
        "0.005202",
        "m5-mainnet-unbound-payment",
    );
    let verdict = verify_record(&listed, &record, &expected(reference));

    // Reaching the reference gate proves the token program, destination ATA,
    // mint, decimals, and amount checks all passed on real mainnet bytes: every
    // one of them is evaluated before it.
    assert_eq!(
        verdict,
        Err(Rejection::ReferenceNotInTransferInstruction),
        "a real unbound payment was refused for the wrong reason"
    );
}

#[test]
fn real_bytes_are_still_refused_when_the_invoice_terms_differ() {
    let (listed, record) = records();
    let reference = derive_payment_reference(
        &key(RECIPIENT_OWNER),
        Some(&key(USDC)),
        "0.005202",
        "m5-mainnet-unbound-payment",
    );

    let mut wrong_amount = expected(reference);
    wrong_amount.raw_amount = RAW_AMOUNT + 1;
    assert_eq!(
        verify_record(&listed, &record, &wrong_amount),
        Err(Rejection::WrongInstructionAmount)
    );

    let mut wrong_recipient = expected(reference);
    wrong_recipient.destination_ata = key("5RZHGLtc1TLGgX5fuNFKnmhZvBFtN6uFjBTUGP1JRTFN");
    assert_eq!(
        verify_record(&listed, &record, &wrong_recipient),
        Err(Rejection::WrongDestination)
    );

    let mut wrong_program = expected(reference);
    wrong_program.token_program = TokenProgram::Token2022;
    assert_eq!(
        verify_record(&listed, &record, &wrong_program),
        Err(Rejection::WrongTokenProgram)
    );
}
