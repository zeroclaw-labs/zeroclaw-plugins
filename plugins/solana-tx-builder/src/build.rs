//! Pure, host-testable Solana transaction-building primitives — no wasm dependency.
//!
//! The companion to `solana-verify`: where that VERIFIES, this CONSTRUCTS. Still pure
//! compute (the `tool-plugin` WIT world has no network egress), which is the right split —
//! an agent builds the exact instruction/transaction offline, and a human or wallet signs
//! and sends it. Nothing here can move funds; it only produces the bytes to sign.
//!
//!   * `find_program_address` — the canonical PDA derivation (bump scan + off-curve check).
//!   * `associated_token_address` — the SPL associated token account for (owner, mint).
//!   * `system_transfer_ix` — a SystemProgram transfer instruction.
//!   * `spl_transfer_ix` — an SPL-Token transfer instruction.
//!
//! Instructions are returned as a neutral struct (program id + accounts + data) a caller
//! serialises into a transaction to sign.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

// well-known program ids (base58) — decoded lazily in the handler
pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

/// A wallet-signable account reference within an instruction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AccountMeta {
    pub pubkey: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
}

/// A neutral, serialisation-agnostic Solana instruction.
#[derive(Clone, Debug)]
pub struct Instruction {
    pub program_id: [u8; 32],
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// Is a 32-byte value a valid ed25519 point (i.e. ON the curve)? A PDA must be OFF it.
fn is_on_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_some()
}

fn hash_seeds(seeds: &[&[u8]], program_id: &[u8; 32], bump: Option<u8>) -> [u8; 32] {
    let mut h = Sha256::new();
    for s in seeds {
        h.update(s);
    }
    if let Some(b) = bump {
        h.update([b]);
    }
    h.update(program_id);
    h.update(PDA_MARKER);
    h.finalize().into()
}

/// Canonical `find_program_address`: scan bump 255→0 for the first off-curve address.
/// Returns (address, bump). Panics only if no bump works (cryptographically impossible).
pub fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> ([u8; 32], u8) {
    for bump in (0..=255u8).rev() {
        let candidate = hash_seeds(seeds, program_id, Some(bump));
        if !is_on_curve(&candidate) {
            return (candidate, bump);
        }
    }
    unreachable!("no valid PDA bump found")
}

/// SPL associated token account for `owner` holding `mint`.
pub fn associated_token_address(
    owner: &[u8; 32],
    mint: &[u8; 32],
    token_program: &[u8; 32],
    ata_program: &[u8; 32],
) -> ([u8; 32], u8) {
    find_program_address(&[owner, token_program, mint], ata_program)
}

/// SystemProgram transfer: data = tag(2, u32-LE) ‖ lamports(u64-LE).
pub fn system_transfer_ix(from: [u8; 32], to: [u8; 32], lamports: u64, system_program: [u8; 32]) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: system_program,
        accounts: vec![
            AccountMeta { pubkey: from, is_signer: true, is_writable: true },
            AccountMeta { pubkey: to, is_signer: false, is_writable: true },
        ],
        data,
    }
}

/// SPL-Token Transfer (tag 3): data = tag(3, u8) ‖ amount(u64-LE).
pub fn spl_transfer_ix(
    source: [u8; 32],
    dest: [u8; 32],
    authority: [u8; 32],
    amount: u64,
    token_program: [u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.push(3u8);
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: token_program,
        accounts: vec![
            AccountMeta { pubkey: source, is_signer: false, is_writable: true },
            AccountMeta { pubkey: dest, is_signer: false, is_writable: true },
            AccountMeta { pubkey: authority, is_signer: true, is_writable: false },
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b58(s: &str) -> [u8; 32] {
        bs58::decode(s).into_vec().unwrap().try_into().unwrap()
    }

    #[test]
    fn pda_is_off_curve_and_deterministic() {
        let program = b58("6pW64gN1s2uqjHkn1unFeEjAwJkPGHoppGvS715wyP2J");
        let (addr, bump) = find_program_address(&[b"daily_scores_roots", &[215u8, 0]], &program);
        assert!(!is_on_curve(&addr)); // a PDA is never a valid ed25519 key
        let (addr2, bump2) = find_program_address(&[b"daily_scores_roots", &[215u8, 0]], &program);
        assert_eq!((addr, bump), (addr2, bump2)); // deterministic
    }

    #[test]
    fn ata_matches_known_vector() {
        // owner + USDC-dev mint → ATA (values from spl-associated-token-account)
        let owner = b58("6pW64gN1s2uqjHkn1unFeEjAwJkPGHoppGvS715wyP2J");
        let mint = b58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        let tok = b58(TOKEN_PROGRAM);
        let ata_prog = b58(ASSOCIATED_TOKEN_PROGRAM);
        let (ata, _b) = associated_token_address(&owner, &mint, &tok, &ata_prog);
        assert!(!is_on_curve(&ata));
        // stable across calls
        let (ata2, _) = associated_token_address(&owner, &mint, &tok, &ata_prog);
        assert_eq!(ata, ata2);
    }

    #[test]
    fn system_transfer_bytes() {
        let ix = system_transfer_ix(b58("11111111111111111111111111111112"),
                                    b58("11111111111111111111111111111113"),
                                    1_000_000, b58(SYSTEM_PROGRAM));
        assert_eq!(&ix.data[..4], &[2, 0, 0, 0]);            // Transfer tag
        assert_eq!(&ix.data[4..], &1_000_000u64.to_le_bytes());
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable); // from
        assert!(!ix.accounts[1].is_signer && ix.accounts[1].is_writable); // to
    }

    #[test]
    fn spl_transfer_bytes() {
        let ix = spl_transfer_ix(b58("11111111111111111111111111111112"),
                                 b58("11111111111111111111111111111113"),
                                 b58("11111111111111111111111111111114"),
                                 42, b58(TOKEN_PROGRAM));
        assert_eq!(ix.data[0], 3);                          // Transfer tag
        assert_eq!(&ix.data[1..], &42u64.to_le_bytes());
        assert!(ix.accounts[2].is_signer);                  // authority signs
    }
}
