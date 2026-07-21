//! Round-trip tests: build with our instruction builders → serialize → decode
//! → the facts must come back exactly. This is the suite-coherence invariant.

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
