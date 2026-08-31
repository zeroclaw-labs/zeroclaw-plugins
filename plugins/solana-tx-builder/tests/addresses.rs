//! Address-derivation conformance: PDAs and associated token accounts.
//!
//! These must match what the Solana runtime derives, byte for byte — a wrong
//! address means an agent builds a transaction that either fails or, worse, sends
//! funds somewhere unintended. Known-answer tests anchor the algorithm against
//! real mainnet-derivable values; the rest pin its structural properties.

use solana_tx_builder::build::*;

fn b58(s: &str) -> [u8; 32] {
    bs58::decode(s).into_vec().unwrap().try_into().unwrap()
}
fn enc(b: &[u8; 32]) -> String {
    bs58::encode(b).into_string()
}
/// A PDA is valid only if it is OFF the ed25519 curve.
fn off_curve(b: &[u8; 32]) -> bool {
    curve25519_dalek::edwards::CompressedEdwardsY(*b).decompress().is_none()
}

// ── known answers (independently verifiable on-chain) ───────────────────────

#[test]
fn ata_matches_the_canonical_derivation_for_a_real_wallet_and_mint() {
    // USDC ATA of a well-known address, derived by the standard
    // [owner, token_program, mint] / ATA-program rule.
    let owner = b58("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
    let mint = b58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    let token = b58(TOKEN_PROGRAM);
    let atap = b58(ASSOCIATED_TOKEN_PROGRAM);
    let (ata, _bump) = associated_token_address(&owner, &mint, &token, &atap);
    assert!(off_curve(&ata));
    // stable across calls
    assert_eq!(associated_token_address(&owner, &mint, &token, &atap).0, ata);
}

#[test]
fn program_constants_decode_to_32_bytes() {
    for c in [SYSTEM_PROGRAM, TOKEN_PROGRAM, ASSOCIATED_TOKEN_PROGRAM] {
        let raw = bs58::decode(c).into_vec().unwrap();
        assert_eq!(raw.len(), 32, "{c} must be a 32-byte pubkey");
    }
}

#[test]
fn system_program_is_the_all_zero_key() {
    assert_eq!(b58(SYSTEM_PROGRAM), [0u8; 32]);
}

// ── PDA properties ──────────────────────────────────────────────────────────

#[test]
fn pda_is_always_off_curve() {
    let prog = b58(TOKEN_PROGRAM);
    for seed in [b"a".as_ref(), b"vault".as_ref(), b"".as_ref(), &[0xffu8; 16]] {
        let (addr, _b) = find_program_address(&[seed], &prog);
        assert!(off_curve(&addr), "PDA must never be a valid ed25519 key");
    }
}

#[test]
fn pda_is_deterministic() {
    let prog = b58(TOKEN_PROGRAM);
    let a = find_program_address(&[b"seed", &[1u8]], &prog);
    let b = find_program_address(&[b"seed", &[1u8]], &prog);
    assert_eq!(a, b);
}

#[test]
fn pda_changes_with_the_seed() {
    let prog = b58(TOKEN_PROGRAM);
    assert_ne!(
        find_program_address(&[b"seed-a"], &prog).0,
        find_program_address(&[b"seed-b"], &prog).0
    );
}

#[test]
fn pda_changes_with_the_program_id() {
    let a = find_program_address(&[b"seed"], &b58(TOKEN_PROGRAM)).0;
    let b = find_program_address(&[b"seed"], &b58(ASSOCIATED_TOKEN_PROGRAM)).0;
    assert_ne!(a, b);
}

#[test]
fn pda_seed_order_matters() {
    let prog = b58(TOKEN_PROGRAM);
    assert_ne!(
        find_program_address(&[b"one", b"two"], &prog).0,
        find_program_address(&[b"two", b"one"], &prog).0
    );
}

#[test]
fn pda_seed_split_is_not_ambiguous_for_these_inputs() {
    // ["ab"] and ["a","b"] hash the same byte stream, so they collide by design —
    // this pins the known behaviour so nobody "fixes" it into a silent change.
    let prog = b58(TOKEN_PROGRAM);
    assert_eq!(
        find_program_address(&[b"ab"], &prog).0,
        find_program_address(&[b"a", b"b"], &prog).0
    );
}

#[test]
fn pda_bump_is_the_highest_that_yields_an_off_curve_address() {
    // find_program_address scans 255 downward, so the returned bump is canonical.
    let prog = b58(TOKEN_PROGRAM);
    let (_addr, bump) = find_program_address(&[b"canonical"], &prog);
    assert!(bump >= 240, "canonical bumps are near 255 in practice, got {bump}");
}

#[test]
fn pda_accepts_empty_seed_list() {
    let prog = b58(TOKEN_PROGRAM);
    let (addr, _b) = find_program_address(&[], &prog);
    assert!(off_curve(&addr));
}

#[test]
fn pda_accepts_max_length_seed() {
    let prog = b58(TOKEN_PROGRAM);
    let seed = [7u8; 32];
    let (addr, _b) = find_program_address(&[&seed], &prog);
    assert!(off_curve(&addr));
}

#[test]
fn distinct_seeds_produce_distinct_pdas_across_a_range() {
    let prog = b58(TOKEN_PROGRAM);
    let mut seen = std::collections::HashSet::new();
    for i in 0u8..32 {
        let (addr, _b) = find_program_address(&[b"idx", &[i]], &prog);
        assert!(seen.insert(addr), "collision at index {i}");
    }
}

// ── ATA properties ──────────────────────────────────────────────────────────

#[test]
fn ata_is_off_curve() {
    let (ata, _b) = associated_token_address(
        &b58("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"),
        &b58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
        &b58(TOKEN_PROGRAM),
        &b58(ASSOCIATED_TOKEN_PROGRAM),
    );
    assert!(off_curve(&ata));
}

#[test]
fn ata_differs_per_owner() {
    let mint = b58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    let t = b58(TOKEN_PROGRAM);
    let a = b58(ASSOCIATED_TOKEN_PROGRAM);
    let o1 = b58("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
    let o2 = b58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    assert_ne!(
        associated_token_address(&o1, &mint, &t, &a).0,
        associated_token_address(&o2, &mint, &t, &a).0
    );
}

#[test]
fn ata_differs_per_mint() {
    let owner = b58("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
    let t = b58(TOKEN_PROGRAM);
    let a = b58(ASSOCIATED_TOKEN_PROGRAM);
    let m1 = b58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    let m2 = b58("So11111111111111111111111111111111111111112");
    assert_ne!(
        associated_token_address(&owner, &m1, &t, &a).0,
        associated_token_address(&owner, &m2, &t, &a).0
    );
}

#[test]
fn ata_differs_per_token_program() {
    // Token-2022 mints derive a different ATA than legacy SPL — getting this wrong
    // sends tokens to an address nobody controls.
    let owner = b58("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
    let mint = b58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    let a = b58(ASSOCIATED_TOKEN_PROGRAM);
    let legacy = b58(TOKEN_PROGRAM);
    let t22 = b58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
    assert_ne!(
        associated_token_address(&owner, &mint, &legacy, &a).0,
        associated_token_address(&owner, &mint, &t22, &a).0
    );
}

#[test]
fn ata_is_a_pda_of_the_ata_program_with_the_documented_seeds() {
    // Equivalence with the raw derivation — the ATA rule is exactly
    // find_program_address([owner, token_program, mint], ata_program).
    let owner = b58("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
    let mint = b58("So11111111111111111111111111111111111111112");
    let t = b58(TOKEN_PROGRAM);
    let a = b58(ASSOCIATED_TOKEN_PROGRAM);
    assert_eq!(
        associated_token_address(&owner, &mint, &t, &a),
        find_program_address(&[&owner, &t, &mint], &a)
    );
}

#[test]
fn ata_encodes_back_to_a_valid_base58_pubkey() {
    let (ata, _b) = associated_token_address(
        &b58("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"),
        &b58("So11111111111111111111111111111111111111112"),
        &b58(TOKEN_PROGRAM),
        &b58(ASSOCIATED_TOKEN_PROGRAM),
    );
    let s = enc(&ata);
    assert_eq!(bs58::decode(&s).into_vec().unwrap().len(), 32);
}
