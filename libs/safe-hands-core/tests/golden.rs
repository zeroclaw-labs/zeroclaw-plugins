//! Golden-vector integration tests: our serialization must match an
//! independent implementation (@solana/web3.js v1, scratch/golden-gen/gen.js).

use safe_hands_core::crypto::parse_pubkey;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_pubkey::Pubkey;

const GOLDEN_TRANSFER_HEX: &str = "010001038a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940000000000000000000000000000000000000000000000000000000000000000070707070707070707070707070707070707070707070707070707070707070701020200010c0200000000ca9a3b00000000";

/// The canonical 1-SOL legacy transfer: same from/to/blockhash as the web3.js
/// fixture, built with Agave micro-crates. Bytes must be identical.
#[test]
fn one_sol_legacy_transfer_matches_web3js_byte_for_byte() {
    let from = parse_pubkey("AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9").expect("from");
    let to = parse_pubkey("9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu").expect("to");
    let system = Pubkey::default(); // 11111111111111111111111111111111 = [0u8;32]

    // SystemProgram::Transfer = discriminator u32 LE 2, then lamports u64 LE.
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1_000_000_000u64.to_le_bytes());

    let ix = Instruction {
        program_id: system,
        accounts: vec![AccountMeta::new(from, true), AccountMeta::new(to, false)],
        data,
    };

    let mut msg = Message::new(&[ix], Some(&from));
    msg.recent_blockhash = Hash::new_from_array([7u8; 32]);

    let ours = bincode::serialize(&msg).expect("serialize");
    let golden = hex::decode(GOLDEN_TRANSFER_HEX).expect("golden hex");

    assert_eq!(ours, golden, "legacy 1-SOL transfer must match web3.js bytes");
}

/// Message account ordering: signer-writable first, then writable non-signers,
/// then readonly programs — exactly as the golden bytes lay out.
#[test]
fn account_ordering_matches_golden_layout() {
    let from = parse_pubkey("AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9").expect("from");
    let to = parse_pubkey("9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu").expect("to");

    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1_000_000_000u64.to_le_bytes());
    let ix = Instruction {
        program_id: Pubkey::default(),
        accounts: vec![AccountMeta::new(from, true), AccountMeta::new(to, false)],
        data,
    };
    let msg = Message::new(&[ix], Some(&from));

    assert!(msg.is_signer(0), "index 0 must be the fee-payer signer");
    assert_eq!(msg.account_keys[0], from);
    assert_eq!(msg.account_keys[1], to);
    assert_eq!(msg.account_keys[2], Pubkey::default());
}
