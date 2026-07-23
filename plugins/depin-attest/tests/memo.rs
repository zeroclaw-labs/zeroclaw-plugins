use depin_attest::memo::{build_memo_instruction, MAX_MEMO_LEN, MEMO_PROGRAM_ID_B58};

#[test]
fn build_memo_instruction_empty_accounts() {
    let ix = build_memo_instruction("hello").unwrap();
    assert!(ix.accounts.is_empty());
    
    let expected_prog = bs58::decode(MEMO_PROGRAM_ID_B58).into_vec().unwrap();
    assert_eq!(ix.program_id, expected_prog.as_slice());
    assert_eq!(ix.data, b"hello");
}

#[test]
fn build_memo_instruction_rejects_oversized_text() {
    let oversized = "a".repeat(MAX_MEMO_LEN + 1);
    let res = build_memo_instruction(&oversized);
    assert!(res.is_err());
    
    let exact_size = "a".repeat(MAX_MEMO_LEN);
    assert!(build_memo_instruction(&exact_size).is_ok());
}
