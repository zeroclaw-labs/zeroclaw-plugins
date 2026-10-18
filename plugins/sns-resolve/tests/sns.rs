//! Tests for the SNS resolver core, over the public API the wasm `execute` path
//! uses. Runs on the host with a plain `cargo test`, no network. The derivation
//! golden vector is verified live on mainnet (bonfida.sol's name account exists,
//! is owned by the SPL Name Service program, and resolves to a real wallet).

use sns_resolve::sns::{domain_account, normalize, owner_from_data};

#[test]
fn derives_bonfida_dot_sol() {
    assert_eq!(
        domain_account("bonfida").unwrap(),
        "Crf8hzfthWGbGbLTVCiqRqV5MVnbpHB1L9KQMd6gsinb"
    );
}

#[test]
fn normalize_strips_sol_and_at() {
    assert_eq!(normalize("bonfida.sol").unwrap(), "bonfida");
    assert_eq!(normalize("  @bonfida ").unwrap(), "bonfida");
    assert_eq!(normalize("toly").unwrap(), "toly");
}

#[test]
fn normalize_rejects_subdomains_and_empty() {
    assert!(normalize("sub.bonfida.sol").is_err());
    assert!(normalize("").is_err());
    assert!(normalize(".sol").is_err());
}

#[test]
fn derivation_is_case_sensitive() {
    // SNS hashes exact bytes; different case => a different (still valid) account.
    assert_ne!(
        domain_account("bonfida").unwrap(),
        domain_account("Bonfida").unwrap()
    );
}

#[test]
fn owner_parsed_from_header_offset_32_64() {
    let mut data = vec![0u8; 96];
    for b in &mut data[32..64] {
        *b = 5; // a recognizable owner at bytes 32..64
    }
    assert_eq!(
        owner_from_data(&data).unwrap(),
        bs58::encode([5u8; 32]).into_string()
    );
}

#[test]
fn owner_fails_closed_on_short_data() {
    assert!(owner_from_data(&[0u8; 40]).is_err());
}
