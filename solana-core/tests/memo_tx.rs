use solana_core::ix::{memo_instruction, MEMO_PROGRAM_ID, SYSTEM_PROGRAM_ID};
use solana_core::keys::Pubkey;
use solana_core::tx::{
    build_durable_memo_tx, encode_legacy_message, encode_unsigned_legacy_tx, to_base64,
};

#[test]
fn memo_program_id_decodes() {
    assert_eq!(
        MEMO_PROGRAM_ID.to_base58(),
        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
    );
}

#[test]
fn memo_ix_data_is_utf8_bytes() {
    let payer = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
    let ix = memo_instruction(&payer, "hello");
    assert_eq!(ix.data, b"hello");
    assert_eq!(ix.program_id, MEMO_PROGRAM_ID);
    assert_eq!(ix.accounts.len(), 1);
}

#[test]
fn memo_ix_account_meta_marks_payer_signer_readonly() {
    let payer = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
    let ix = memo_instruction(&payer, "hello");
    assert_eq!(ix.accounts[0].pubkey, payer);
    assert!(ix.accounts[0].is_signer);
    assert!(!ix.accounts[0].is_writable);
}

#[test]
fn unsigned_tx_roundtrips_base64() {
    let payer = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
    let ix = memo_instruction(&payer, "ZCDEPIN|test");
    let blockhash = [7u8; 32];
    let msg = encode_legacy_message(
        /* num_required_signatures */ 1,
        /* num_readonly_signed */ 0,
        /* num_readonly_unsigned */ 1, // memo program
        &[payer, MEMO_PROGRAM_ID],
        &blockhash,
        &[ix],
    );
    let tx = encode_unsigned_legacy_tx(&msg, 1);
    assert_eq!(tx[0], 1); // compact-u16 length of signatures = 1
    let b64 = to_base64(&tx);
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64).unwrap();
    assert_eq!(decoded, tx);
}

#[test]
fn legacy_message_uses_multibyte_shortvec_lengths() {
    let payer = Pubkey::from_base58("11111111111111111111111111111111").unwrap();
    let ix = memo_instruction(&payer, &"x".repeat(128));
    let blockhash = [7u8; 32];
    let msg = encode_legacy_message(1, 0, 1, &[payer, MEMO_PROGRAM_ID], &blockhash, &[ix]);

    let instruction_data_len_offset = 3 + 1 + (2 * 32) + 32 + 1 + 1 + 1 + 1;
    assert_eq!(
        &msg[instruction_data_len_offset..instruction_data_len_offset + 2],
        &[0x80, 0x01]
    );

    let tx = encode_unsigned_legacy_tx(&msg, 128);
    assert_eq!(&tx[..2], &[0x80, 0x01]);
}

#[test]
fn durable_memo_tx_matches_golden_base64_and_layout() {
    const MEMO: &str = "ZCDEPIN|device-7|temperature|21.234568|celsius|5733333|162751dec7d2";
    const GOLDEN_TX_BASE64: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAMFAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQECAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgan1RcZLFaO4IqEX3PSl4jPA1wxRbIas0TYBi6pQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFSlNamSkhBk0k6HFg2jh8fDW13bySu4HkH6hAQQVEjQcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHAgMDAQIABAQAAAAEAQBDWkNERVBJTnxkZXZpY2UtN3x0ZW1wZXJhdHVyZXwyMS4yMzQ1Njh8Y2Vsc2l1c3w1NzMzMzMzfDE2Mjc1MWRlYzdkMg==";

    let payer = Pubkey::new([1u8; 32]);
    let nonce_account = Pubkey::new([2u8; 32]);
    let recent_blockhashes_sysvar =
        Pubkey::from_base58("SysvarRecentB1ockHashes11111111111111111111").unwrap();
    let durable_nonce = [7u8; 32];

    let tx = build_durable_memo_tx(&payer, &nonce_account, &payer, &durable_nonce, MEMO).unwrap();

    assert_eq!(to_base64(&tx), GOLDEN_TX_BASE64);
    assert_eq!(tx[0], 1);
    assert_eq!(&tx[1..65], &[0u8; 64]);

    let message = &tx[65..];
    assert_eq!(&message[0..3], &[1, 0, 3]);
    assert_eq!(message[3], 5);

    let account_keys = &message[4..164];
    assert_eq!(&account_keys[0..32], payer.as_bytes());
    assert_eq!(&account_keys[32..64], nonce_account.as_bytes());
    assert_eq!(&account_keys[64..96], recent_blockhashes_sysvar.as_bytes());
    assert_eq!(&account_keys[96..128], SYSTEM_PROGRAM_ID.as_bytes());
    assert_eq!(&account_keys[128..160], MEMO_PROGRAM_ID.as_bytes());

    assert_eq!(&message[164..196], &durable_nonce);
    assert_eq!(message[196], 2);
    assert_eq!(&message[197..207], &[3, 3, 1, 2, 0, 4, 4, 0, 0, 0]);
    assert_eq!(&message[207..211], &[4, 1, 0, MEMO.len() as u8]);
    assert_eq!(&message[211..], MEMO.as_bytes());
}
