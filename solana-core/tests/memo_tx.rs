use solana_core::ix::{memo_instruction, MEMO_PROGRAM_ID};
use solana_core::keys::Pubkey;
use solana_core::tx::{encode_legacy_message, encode_unsigned_legacy_tx, to_base64};

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
