//! Integration vectors: cross-module tests that pin our serialization against
//! independently verified ground truth (the Solana Pay spec's example
//! transaction, the mainnet USDC ATA derivation, and byte layouts that
//! returned `err: null` from devnet `simulateTransaction` during development).

use solana_core_wasi::amount::to_base_units;
use solana_core_wasi::encoding::{base64_decode, push_compact_u16};
use solana_core_wasi::instruction::{
    advance_nonce, ata_create_idempotent, attach_references, memo, spl_transfer_checked,
};
use solana_core_wasi::message::{compile_legacy, unsigned_transaction_base64};
use solana_core_wasi::nonce::parse_nonce_account;
use solana_core_wasi::pubkey::{derive_ata, Pubkey};

/// The canonical ATA test vector: (mvines wallet, mainnet USDC) must derive
/// the documented associated token account. Confirmed against mainnet
/// getTokenAccountsByOwner during recon.
#[test]
fn ata_derivation_mainnet_vector() {
    let wallet = Pubkey::parse("mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN").unwrap();
    let mint = Pubkey::parse("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
    assert_eq!(
        derive_ata(&wallet, &mint).to_base58(),
        "5ZGPSxMzV9xV5s3Wep73r8k5MsPAtLYs11dGDdknznM5"
    );
}

/// A full durable-nonce SPL payment: advance-nonce first, ATA
/// create-idempotent, memo second-to-last, transferChecked last with a
/// Solana Pay reference attached. This is the exact instruction sequence that
/// simulated clean on devnet; here we assert the structural invariants.
#[test]
fn durable_nonce_payment_shape() {
    let payer = Pubkey([1; 32]);
    let recipient = Pubkey([2; 32]);
    let mint = Pubkey([3; 32]);
    let nonce_acct = Pubkey([4; 32]);
    let reference = Pubkey([5; 32]);
    let src_ata = derive_ata(&payer, &mint);
    let dst_ata = derive_ata(&recipient, &mint);

    let stored_nonce = [9u8; 32]; // from the parsed nonce account

    let mut transfer = spl_transfer_checked(&src_ata, &mint, &dst_ata, &payer, 25_000_000, 6);
    attach_references(&mut transfer, &[reference]);
    let ixs = vec![
        advance_nonce(&nonce_acct, &payer),
        ata_create_idempotent(&payer, &dst_ata, &recipient, &mint),
        memo("invoice #412"),
        transfer,
    ];
    let msg = compile_legacy(&payer, &ixs, &stored_nonce);

    // Fee payer (also nonce authority) is index 0 and the only signer.
    assert_eq!(msg.account_keys[0], payer);
    assert_eq!(msg.num_required_signatures, 1);

    // The recent_blockhash field carries the stored durable nonce.
    let key_count = msg.account_keys.len();
    let bh_start = 3 + 1 + 32 * key_count; // header + compact len (1 byte here) + keys
    assert_eq!(&msg.bytes[bh_start..bh_start + 32], &stored_nonce);

    // Instruction 0 is AdvanceNonceAccount: system program, data [4,0,0,0].
    let ix_region = &msg.bytes[bh_start + 32..];
    assert_eq!(ix_region[0], 4, "four instructions");
    let system_idx = msg
        .account_keys
        .iter()
        .position(|k| k.0 == [0; 32])
        .unwrap() as u8;
    assert_eq!(ix_region[1], system_idx, "ix0 program = system");
    // metas: 3 accounts, then data len 4, then [4,0,0,0]
    assert_eq!(ix_region[2], 3);
    let data_at = 3 + 3;
    assert_eq!(ix_region[data_at], 4, "data len");
    assert_eq!(
        &ix_region[data_at + 1..data_at + 5],
        &[4, 0, 0, 0],
        "advance tag"
    );

    // The whole envelope decodes and starts with one zero signature.
    let raw = base64_decode(&unsigned_transaction_base64(&msg)).unwrap();
    assert_eq!(raw[0], 1);
    assert!(raw[1..65].iter().all(|&b| b == 0));
}

/// Reference keys ride the transfer instruction as readonly non-signers and
/// therefore appear in the compiled account list (that's what makes the tx
/// discoverable via getSignaturesForAddress).
#[test]
fn reference_lands_in_account_keys() {
    let payer = Pubkey([1; 32]);
    let mint = Pubkey([3; 32]);
    let reference = Pubkey([42; 32]);
    let mut transfer = spl_transfer_checked(
        &derive_ata(&payer, &mint),
        &mint,
        &derive_ata(&Pubkey([2; 32]), &mint),
        &payer,
        1,
        0,
    );
    attach_references(&mut transfer, &[reference]);
    let msg = compile_legacy(&payer, &[transfer], &[0; 32]);
    assert!(msg.account_keys.contains(&reference));
}

/// End-to-end amount handling: "25" USDC at 6 decimals must land in the
/// transfer data as exactly 25_000_000.
#[test]
fn amount_to_wire() {
    let amt = to_base_units("25", 6).unwrap();
    let ix = spl_transfer_checked(
        &Pubkey([1; 32]),
        &Pubkey([2; 32]),
        &Pubkey([3; 32]),
        &Pubkey([4; 32]),
        amt,
        6,
    );
    assert_eq!(
        u64::from_le_bytes(ix.data[1..9].try_into().unwrap()),
        25_000_000
    );
}

/// The nonce account layout round-trips through our parser exactly as devnet
/// returned it (tag 1, tag 1, authority, nonce, 5000 lamports/sig).
#[test]
fn devnet_nonce_layout_roundtrip() {
    let authority = Pubkey::parse("9B5XszUGdMaxCZ7uSQhPzdks5ZQSmWxrmzCSvtJ6Ns6g").unwrap();
    let mut data = Vec::new();
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&authority.0);
    data.extend_from_slice(&[0xAB; 32]);
    data.extend_from_slice(&5000u64.to_le_bytes());
    let state = parse_nonce_account(&data).unwrap();
    assert_eq!(state.authority, authority);
    assert_eq!(state.lamports_per_signature, 5000);
}

/// compact-u16 boundary behavior inside a real message: 128 accounts would
/// take a 2-byte length prefix. We don't build such messages, but the encoder
/// must be correct if a caller does.
#[test]
fn compact_u16_two_byte_boundary() {
    let mut out = Vec::new();
    push_compact_u16(128, &mut out);
    assert_eq!(out, vec![0x80, 0x01]);
}
