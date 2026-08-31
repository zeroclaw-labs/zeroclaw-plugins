use solana_core::keys::Pubkey;
use solana_core::shape::{assert_budget, truncate};

#[test]
fn pubkey_roundtrip_system_program() {
    // System Program: 11111111111111111111111111111111
    let s = "11111111111111111111111111111111";
    let pk = Pubkey::from_base58(s).expect("decode");
    assert_eq!(pk.to_base58(), s);
    assert_eq!(pk.as_bytes(), &[0u8; 32]);
}

#[test]
fn pubkey_rejects_bad_base58() {
    assert!(Pubkey::from_base58("!!!").is_err());
}

#[test]
fn truncate_and_budget() {
    assert_eq!(truncate("abcdef", 3), "abc");
    assert!(assert_budget("hi", 10).is_ok());
    assert!(assert_budget("hello world", 5).is_err());
}
