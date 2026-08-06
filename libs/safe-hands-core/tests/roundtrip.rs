//! Round-trip tests: build with our instruction builders → serialize → decode
//! → the facts must come back exactly. This is the suite-coherence invariant.

use proptest::prelude::*;
use safe_hands_core::codec::{base64_decode, base64_encode, shortvec_encode};
use safe_hands_core::crypto::{ata_address, parse_pubkey};
use safe_hands_core::decode::{decode, TxVersion};
use safe_hands_core::ix;
use solana_hash::Hash;
use solana_message::Message;
use solana_pubkey::Pubkey;

const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

fn payer() -> Pubkey {
    parse_pubkey("AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9").expect("payer")
}
fn dest() -> Pubkey {
    parse_pubkey("9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu").expect("dest")
}

fn usdc_transfer_message() -> Vec<u8> {
    let payer = payer();
    let dest = dest();
    let mint = parse_pubkey(USDC).expect("mint");
    let token_program = ix::spl_token_program();
    let ata = ata_address(&dest, &token_program, &mint);
    let source = Pubkey::new_from_array([7u8; 32]);

    let ixs = vec![
        ix::ata_create_idempotent(&payer, &ata, &dest, &mint, &token_program),
        ix::transfer_checked(&token_program, &source, &mint, &ata, &payer, 25_000_000, 6),
        ix::memo("invoice-412"),
    ];
    let mut msg = Message::new(&ixs, Some(&payer));
    msg.recent_blockhash = Hash::new_from_array([7u8; 32]);
    bincode::serialize(&msg).expect("serialize")
}

#[test]
fn legacy_roundtrip_classifies_everything() {
    let bytes = usdc_transfer_message();
    let d = decode(&bytes).expect("decode");

    assert_eq!(d.version, TxVersion::Legacy);
    assert!(!d.facts.signed);
    assert_eq!(d.facts.instructions.len(), 3);
    assert_eq!(d.facts.instructions[0].program, "associated_token");
    assert_eq!(
        d.facts.instructions[0].name.as_deref(),
        Some("create_idempotent")
    );
    assert_eq!(d.facts.instructions[1].program, "spl_token");
    assert_eq!(
        d.facts.instructions[1].name.as_deref(),
        Some("transfer_checked")
    );
    assert_eq!(d.facts.instructions[2].program, "memo");
    assert_eq!(d.facts.memos, vec!["invoice-412"]);

    assert_eq!(d.facts.transfers.len(), 1);
    let tr = &d.facts.transfers[0];
    assert_eq!(tr.mint.as_deref(), Some(USDC));
    assert_eq!(tr.amount_raw, 25_000_000);
    assert_eq!(
        tr.recipient,
        ata_address(
            &dest(),
            &ix::spl_token_program(),
            &parse_pubkey(USDC).unwrap()
        )
        .to_string()
    );
}

#[test]
fn ata_create_classifier_fails_closed() {
    let payer = payer();
    let recipient = dest();
    let mint = parse_pubkey(USDC).expect("mint");
    let token_program = ix::spl_token_program();
    let ata = ata_address(&recipient, &token_program, &mint);
    let source = Pubkey::new_from_array([7u8; 32]);
    let transfer = ix::transfer_checked(&token_program, &source, &mint, &ata, &payer, 1, 6);
    let serialize = |instructions: &[solana_instruction::Instruction]| {
        let mut message = Message::new(instructions, Some(&payer));
        message.recent_blockhash = Hash::new_from_array([7u8; 32]);
        bincode::serialize(&message).expect("serialize")
    };

    let valid = ix::ata_create_idempotent(&payer, &ata, &recipient, &mint, &token_program);
    assert!(decode(&serialize(&[valid.clone(), transfer.clone()])).is_ok());

    let mut legacy_empty = valid.clone();
    legacy_empty.data.clear();
    assert!(decode(&serialize(&[legacy_empty, transfer.clone()])).is_err());

    let mut wrong_derivation = valid.clone();
    wrong_derivation.accounts[1].pubkey = Pubkey::new_from_array([44u8; 32]);
    assert!(decode(&serialize(&[wrong_derivation, transfer.clone()])).is_err());

    assert!(decode(&serialize(std::slice::from_ref(&valid))).is_err());
    assert!(decode(&serialize(&[valid.clone(), valid, transfer])).is_err());
}

#[test]
fn base64_wrapper_roundtrip() {
    let bytes = usdc_transfer_message();
    let b64 = base64_encode(&bytes);
    let back = base64_decode(&b64, 10_000).expect("decode b64");
    assert_eq!(back, bytes);
    let d = decode(&back).expect("decode tx");
    assert_eq!(d.facts.transfers.len(), 1);
}

#[test]
fn signature_strip_and_signed_detection() {
    let mut tx = shortvec_encode(1);
    tx.extend_from_slice(&[0u8; 64]); // zeroed signature slot
    tx.extend_from_slice(&usdc_transfer_message());

    let d = decode(&tx).expect("unsigned tx form decodes");
    assert!(!d.facts.signed, "zeroed signatures = unsigned");

    let mut tx2 = shortvec_encode(1);
    let mut sig = [0u8; 64];
    sig[10] = 0xaa;
    tx2.extend_from_slice(&sig);
    tx2.extend_from_slice(&usdc_transfer_message());
    let d2 = decode(&tx2).expect("signed tx form decodes");
    assert!(d2.facts.signed, "nonzero signature byte = signed");

    let mut wrong_count = shortvec_encode(2);
    wrong_count.extend_from_slice(&[0u8; 128]);
    wrong_count.extend_from_slice(&usdc_transfer_message());
    assert!(
        decode(&wrong_count).is_err(),
        "signature count must match header"
    );
}

#[test]
fn v0_message_with_nonce_parses() {
    // Hand-craft a minimal v0 message: version byte, header(1,0,1), 3 keys,
    // blockhash, 1 AdvanceNonceAccount ix, 0 ALT tables.
    let nonce_account = Pubkey::new_from_array([9u8; 32]);
    let authority = payer();
    let system = Pubkey::default();

    let mut m = vec![0x80u8]; // v0 marker
    m.extend_from_slice(&[1, 0, 1]); // header: 1 signer, 0 ro-signed, 1 ro-unsigned
    m.extend_from_slice(&shortvec_encode(3));
    m.extend_from_slice(authority.as_ref());
    m.extend_from_slice(nonce_account.as_ref());
    m.extend_from_slice(system.as_ref());
    m.extend_from_slice(&[7u8; 32]); // blockhash
                                     // 1 instruction: AdvanceNonceAccount (program idx 2, accounts [1, 2, 0])
    m.extend_from_slice(&shortvec_encode(1));
    m.push(2u8); // program index
    m.extend_from_slice(&shortvec_encode(3));
    m.extend_from_slice(&[1, 2, 0]); // account indices
    let data = 4u32.to_le_bytes();
    m.extend_from_slice(&shortvec_encode(data.len()));
    m.extend_from_slice(&data);
    // 0 ALT tables
    m.extend_from_slice(&shortvec_encode(0));

    let d = decode(&m).expect("v0 decodes");
    assert_eq!(d.version, TxVersion::V0);
    assert!(
        d.facts.durable_nonce_used,
        "AdvanceNonceAccount must flag durable nonce"
    );
    assert_eq!(d.facts.instructions[0].program, "system");
    assert_eq!(
        d.facts.instructions[0].name.as_deref(),
        Some("advance_nonce")
    );
}

#[test]
fn v0_alt_loaded_recipient_requires_resolution_then_decodes() {
    // Minimal v0 transfer whose destination is loaded from an ALT. Static
    // keys: payer + system program. Dynamic key index 2 = loaded recipient.
    let authority = payer();
    let system = Pubkey::default();
    let table = Pubkey::new_from_array([11u8; 32]);
    let loaded_recipient = dest();

    let mut m = vec![0x80u8];
    m.extend_from_slice(&[1, 0, 1]);
    m.extend_from_slice(&shortvec_encode(2));
    m.extend_from_slice(authority.as_ref());
    m.extend_from_slice(system.as_ref());
    m.extend_from_slice(&[7u8; 32]);
    m.extend_from_slice(&shortvec_encode(1));
    m.push(1);
    m.extend_from_slice(&shortvec_encode(2));
    m.extend_from_slice(&[0, 2]);
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&1_000_000u64.to_le_bytes());
    m.extend_from_slice(&shortvec_encode(data.len()));
    m.extend_from_slice(&data);
    m.extend_from_slice(&shortvec_encode(1));
    m.extend_from_slice(table.as_ref());
    m.extend_from_slice(&shortvec_encode(1));
    m.push(3);
    m.extend_from_slice(&shortvec_encode(0));

    let unresolved = decode(&m).expect_err("ALT-backed instruction must not guess keys");
    assert!(
        unresolved.contains("ALT resolution required"),
        "{unresolved}"
    );

    let d = safe_hands_core::decode::decode_with_loaded_addresses(&m, &[loaded_recipient], &[])
        .expect("resolved v0 decodes");
    assert_eq!(d.version, TxVersion::V0);
    assert_eq!(d.alt_refs.len(), 1);
    assert_eq!(d.alt_refs[0].table, table.to_string());
    assert_eq!(d.facts.transfers[0].recipient, loaded_recipient.to_string());
    assert_eq!(d.facts.transfers[0].amount_raw, 1_000_000);
}

#[test]
fn malformed_versioned_framing_is_rejected_independently() {
    let authority = payer();
    let system = Pubkey::default();
    let minimal = |marker: u8, key_count: &[u8], lookup_count: &[u8], trailing: &[u8]| {
        let mut message = vec![marker];
        message.extend_from_slice(&[1, 0, 1]);
        message.extend_from_slice(key_count);
        message.extend_from_slice(authority.as_ref());
        message.extend_from_slice(system.as_ref());
        message.extend_from_slice(&[7u8; 32]);
        message.push(0); // no instructions
        message.extend_from_slice(lookup_count);
        message.extend_from_slice(trailing);
        message
    };

    assert!(decode(&minimal(0x80, &[2], &[0], &[])).is_ok());
    for marker in [0x81, 0x82, 0xff] {
        assert!(decode(&minimal(marker, &[2], &[0], &[])).is_err());
    }
    assert!(decode(&minimal(0x80, &[0x82, 0x00], &[0], &[])).is_err());
    assert!(decode(&minimal(0x80, &[2], &[0x80, 0x00], &[])).is_err());
    assert!(decode(&minimal(0x80, &[2], &[0], &[0])).is_err());
}

#[test]
fn memo_decode_is_strict_utf8_and_cardinality_bounded() {
    let payer = payer();
    let memo_program = parse_pubkey(safe_hands_core::ix::MEMO_PROGRAM).unwrap();
    let serialize = |instructions: Vec<solana_instruction::Instruction>| {
        let mut message = Message::new(&instructions, Some(&payer));
        message.recent_blockhash = Hash::new_from_array([7u8; 32]);
        bincode::serialize(&message).unwrap()
    };
    let invalid_utf8 = solana_instruction::Instruction {
        program_id: memo_program,
        accounts: vec![],
        data: vec![0xff],
    };
    assert!(decode(&serialize(vec![invalid_utf8])).is_err());

    let memos = (0..9)
        .map(|index| ix::memo(&format!("memo-{index}")))
        .collect();
    assert!(decode(&serialize(memos)).is_err());
}

#[test]
fn approve_is_authority_change() {
    // SPL Approve ix: disc 7 — latent drain path, must flag.
    let payer = payer();
    let token_program = ix::spl_token_program();
    let source = Pubkey::new_from_array([3u8; 32]);
    let delegate = Pubkey::new_from_array([4u8; 32]);
    let mut data = vec![7u8];
    data.extend_from_slice(&u64::MAX.to_le_bytes());
    let approve_ix = solana_instruction::Instruction {
        program_id: token_program,
        accounts: vec![
            solana_instruction::AccountMeta::new(source, false),
            solana_instruction::AccountMeta::new_readonly(delegate, false),
            solana_instruction::AccountMeta::new_readonly(payer, true),
        ],
        data,
    };
    let mut msg = Message::new(&[approve_ix], Some(&payer));
    msg.recent_blockhash = Hash::new_from_array([7u8; 32]);
    let bytes = bincode::serialize(&msg).expect("serialize");
    let d = decode(&bytes).expect("decode");
    assert!(
        d.facts.authority_change,
        "Approve must flag authority change"
    );
}

#[test]
fn garbage_fails_closed() {
    assert!(decode(&[]).is_err());
    assert!(decode(&[0xff, 0xff, 0xff]).is_err());
    assert!(decode(b"hello world this is not a transaction").is_err());
}

// --- Property: the decoder is a total function (never panics) ---------------
// Untrusted wire bytes are the primary attack surface. This asserts that any
// input within the canonical size bound returns Ok or Err — never a panic,
// arithmetic overflow, or hang. Fuzz-style coverage inside plain `cargo test`.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn decoder_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..1300)) {
        // The verdict is irrelevant here; we assert only that the call returns
        // (Ok or Err) without unwinding.
        let _ = decode(&bytes);
    }
}
