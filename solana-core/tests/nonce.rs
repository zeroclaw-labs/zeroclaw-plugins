use solana_core::ix::advance_nonce_instruction;
use solana_core::keys::Pubkey;
use solana_core::nonce::{parse_nonce_account, NONCE_ACCOUNT_SIZE};
use solana_core::tx::build_durable_memo_tx;

fn initialized_nonce_fixture(authority: &Pubkey, durable_nonce: &[u8; 32], fee: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(NONCE_ACCOUNT_SIZE);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(authority.as_bytes());
    data.extend_from_slice(durable_nonce);
    data.extend_from_slice(&fee.to_le_bytes());
    data
}

#[test]
fn parses_initialized_nonce_account() {
    let authority = Pubkey::new([3u8; 32]);
    let durable_nonce = [9u8; 32];
    let data = initialized_nonce_fixture(&authority, &durable_nonce, 5_000);

    let parsed = parse_nonce_account(&data).expect("parse initialized nonce");

    assert_eq!(data.len(), NONCE_ACCOUNT_SIZE);
    assert_eq!(parsed.authority, authority);
    assert_eq!(parsed.durable_nonce, durable_nonce);
    assert_eq!(parsed.fee_calculator_lamports_per_signature, 5_000);
}

#[test]
fn rejects_non_initialized_nonce_account() {
    let authority = Pubkey::new([3u8; 32]);
    let durable_nonce = [9u8; 32];
    let mut data = initialized_nonce_fixture(&authority, &durable_nonce, 5_000);
    data[4..8].copy_from_slice(&0u32.to_le_bytes());

    assert!(parse_nonce_account(&data).is_err());
}

#[test]
fn advance_nonce_instruction_matches_system_program_shape() {
    let nonce_account = Pubkey::new([4u8; 32]);
    let authority = Pubkey::new([5u8; 32]);

    let ix = advance_nonce_instruction(&nonce_account, &authority);

    assert_eq!(
        ix.program_id.to_base58(),
        "11111111111111111111111111111111"
    );
    assert_eq!(ix.data, 4u32.to_le_bytes());
    assert_eq!(ix.accounts.len(), 3);
    assert_eq!(ix.accounts[0].pubkey, nonce_account);
    assert!(!ix.accounts[0].is_signer);
    assert!(ix.accounts[0].is_writable);
    assert_eq!(
        ix.accounts[1].pubkey.to_base58(),
        "SysvarRecentB1ockHashes11111111111111111111"
    );
    assert!(!ix.accounts[1].is_signer);
    assert!(!ix.accounts[1].is_writable);
    assert_eq!(ix.accounts[2].pubkey, authority);
    assert!(ix.accounts[2].is_signer);
    assert!(!ix.accounts[2].is_writable);
}

#[test]
fn durable_memo_tx_uses_nonce_blockhash_and_two_instructions() {
    let payer = Pubkey::new([1u8; 32]);
    let nonce_account = Pubkey::new([2u8; 32]);
    let authority = Pubkey::new([3u8; 32]);
    let durable_nonce = [7u8; 32];

    let tx = build_durable_memo_tx(
        &payer,
        &nonce_account,
        &authority,
        &durable_nonce,
        "ZCDEPIN|durable",
    )
    .expect("build durable memo tx");

    assert_eq!(tx[0], 2);
    assert_eq!(&tx[1..129], &[0u8; 128]);

    let message = &tx[129..];
    assert_eq!(&message[0..3], &[2, 1, 3]);
    assert_eq!(message[3], 6);

    let blockhash_offset = 3 + 1 + (6 * 32);
    assert_eq!(
        &message[blockhash_offset..blockhash_offset + 32],
        &durable_nonce
    );
    assert_eq!(message[blockhash_offset + 32], 2);
}
