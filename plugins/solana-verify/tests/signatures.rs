//! ed25519 verification tests — Solana's signature scheme.
//!
//! Keys and signatures are generated here from fixed secret bytes (deterministic,
//! no RNG), so every assertion is against a real signature rather than a canned
//! blob. The failure cases matter most: an agent must never treat a bad signature
//! as valid.

use ed25519_dalek::{Signer, SigningKey};
use solana_verify::verify::*;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn signed(seed: u8, msg: &[u8]) -> ([u8; 32], [u8; 64]) {
    let sk = key(seed);
    let sig = sk.sign(msg);
    (sk.verifying_key().to_bytes(), sig.to_bytes())
}

#[test]
fn valid_signature_verifies() {
    let msg = b"transfer 1 SOL";
    let (pk, sig) = signed(1, msg);
    assert!(ed25519_verify(&pk, msg, &sig));
}

#[test]
fn valid_signature_over_empty_message_verifies() {
    let (pk, sig) = signed(2, b"");
    assert!(ed25519_verify(&pk, b"", &sig));
}

#[test]
fn valid_signature_over_long_message_verifies() {
    let msg = vec![0xABu8; 4096];
    let (pk, sig) = signed(3, &msg);
    assert!(ed25519_verify(&pk, &msg, &sig));
}

#[test]
fn signature_does_not_verify_for_a_different_message() {
    let (pk, sig) = signed(4, b"send 1 SOL to alice");
    assert!(!ed25519_verify(&pk, b"send 1000 SOL to mallory", &sig));
}

#[test]
fn single_bit_change_in_the_message_is_rejected() {
    let msg = b"amount=100";
    let (pk, sig) = signed(5, msg);
    let mut tampered = msg.to_vec();
    tampered[7] ^= 0x01;
    assert!(!ed25519_verify(&pk, &tampered, &sig));
}

#[test]
fn truncated_message_is_rejected() {
    let msg = b"amount=100";
    let (pk, sig) = signed(6, msg);
    assert!(!ed25519_verify(&pk, &msg[..msg.len() - 1], &sig));
}

#[test]
fn extended_message_is_rejected() {
    let msg = b"amount=100";
    let (pk, sig) = signed(7, msg);
    let mut longer = msg.to_vec();
    longer.push(b'0');
    assert!(!ed25519_verify(&pk, &longer, &sig));
}

#[test]
fn signature_does_not_verify_under_a_different_pubkey() {
    let msg = b"payload";
    let (_pk, sig) = signed(8, msg);
    let other = key(9).verifying_key().to_bytes();
    assert!(!ed25519_verify(&other, msg, &sig));
}

#[test]
fn corrupted_signature_r_half_is_rejected() {
    let msg = b"payload";
    let (pk, mut sig) = signed(10, msg);
    sig[0] ^= 0xFF;
    assert!(!ed25519_verify(&pk, msg, &sig));
}

#[test]
fn corrupted_signature_s_half_is_rejected() {
    let msg = b"payload";
    let (pk, mut sig) = signed(11, msg);
    sig[63] ^= 0x01;
    assert!(!ed25519_verify(&pk, msg, &sig));
}

#[test]
fn all_zero_signature_is_rejected() {
    let msg = b"payload";
    let (pk, _sig) = signed(12, msg);
    assert!(!ed25519_verify(&pk, msg, &[0u8; 64]));
}

#[test]
fn all_ones_signature_is_rejected() {
    let msg = b"payload";
    let (pk, _sig) = signed(13, msg);
    assert!(!ed25519_verify(&pk, msg, &[0xFFu8; 64]));
}

#[test]
fn invalid_pubkey_bytes_are_rejected_not_panicking() {
    // 0xFF..FF is not a canonical compressed Edwards point.
    let msg = b"payload";
    let (_pk, sig) = signed(14, msg);
    assert!(!ed25519_verify(&[0xFFu8; 32], msg, &sig));
}

#[test]
fn zero_pubkey_is_rejected() {
    let msg = b"payload";
    let (_pk, sig) = signed(15, msg);
    assert!(!ed25519_verify(&[0u8; 32], msg, &sig));
}

#[test]
fn swapping_two_signers_signatures_is_rejected() {
    let msg = b"same message";
    let (pk_a, _sig_a) = signed(16, msg);
    let (_pk_b, sig_b) = signed(17, msg);
    assert!(!ed25519_verify(&pk_a, msg, &sig_b));
}

#[test]
fn same_key_signs_different_messages_independently() {
    let sk = key(18);
    let pk = sk.verifying_key().to_bytes();
    let s1 = sk.sign(b"msg-one").to_bytes();
    let s2 = sk.sign(b"msg-two").to_bytes();
    assert!(ed25519_verify(&pk, b"msg-one", &s1));
    assert!(ed25519_verify(&pk, b"msg-two", &s2));
    assert!(!ed25519_verify(&pk, b"msg-one", &s2));
    assert!(!ed25519_verify(&pk, b"msg-two", &s1));
}

#[test]
fn signing_is_deterministic_for_ed25519() {
    // ed25519 is deterministic: the same key + message always yields the same
    // signature, which is why these tests need no RNG.
    let sk = key(19);
    assert_eq!(sk.sign(b"x").to_bytes(), sk.sign(b"x").to_bytes());
}

#[test]
fn verification_is_side_effect_free_and_repeatable() {
    let msg = b"idempotent";
    let (pk, sig) = signed(20, msg);
    for _ in 0..5 {
        assert!(ed25519_verify(&pk, msg, &sig));
    }
}
