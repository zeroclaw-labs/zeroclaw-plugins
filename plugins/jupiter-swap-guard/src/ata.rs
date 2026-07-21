//! Canonical Program Derived Address / Associated Token Account derivation.
//!
//! This is the primitive behind destination binding (`D1`): the plugin derives
//! the payer's own associated token account for the output mint and refuses to
//! emit a transaction whose swap output lands anywhere else. Because the ATA is a
//! PDA that only the payer controls, an aggregator response cannot redirect the
//! output to an attacker without changing this address — which the check catches.
//!
//! Pure, wasm-free crypto: `sha2` for the hash, `curve25519-dalek` only for the
//! off-curve test. Both are built with `default-features = false` so the wasm
//! build pulls no browser/`getrandom` code. Correctness is pinned by a test
//! against a real on-chain ATA (`FMbvJrg96qADXK2QYx2kuEVbSHwbjxAh2z4qeYjd2MSw`,
//! the USDC ATA of the fixture payer).

#![forbid(unsafe_code)]

use crate::encode::Pubkey;
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

/// The SPL Associated Token Account program id.
pub const ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// The SPL Token program id.
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// The SPL Token-2022 program id.
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

/// True if `bytes` is a valid Ed25519 curve point (i.e. a possible native
/// wallet). A PDA must be OFF the curve, so `find_program_address` skips any bump
/// whose hash lands on it.
fn is_on_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY::from_slice(bytes)
        .ok()
        .and_then(|c| c.decompress())
        .is_some()
}

/// Solana `find_program_address`: the highest bump (255 down to 0) whose derived
/// hash is off-curve. Returns the address and that canonical bump. `None` only in
/// the cryptographically unreachable case that every bump is on-curve.
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Option<(Pubkey, u8)> {
    for bump in (0u8..=255).rev() {
        let mut h = Sha256::new();
        for s in seeds {
            h.update(s);
        }
        h.update([bump]);
        h.update(program_id);
        h.update(PDA_MARKER);
        let out: Pubkey = h.finalize().into();
        if !is_on_curve(&out) {
            return Some((out, bump));
        }
    }
    None
}

/// Canonical associated token account for `(owner, mint)` under `token_program`.
/// Seeds are `[owner, token_program, mint]`, matching the SPL ATA program.
pub fn associated_token_address(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
    ata_program: &Pubkey,
) -> Pubkey {
    // Unwrap: a canonical ATA always exists for well-formed 32-byte inputs.
    find_program_address(&[owner, token_program, mint], ata_program)
        .expect("no off-curve bump found")
        .0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b58::decode_pubkey;

    #[test]
    fn derives_real_onchain_usdc_ata() {
        // Ground truth captured from a live Jupiter /swap-instructions setup ix:
        // the ATA the ATA program itself created for (payer, USDC).
        let payer = decode_pubkey("4sLWYqVXqQHs7s4PQPrQ2agNVX1y3W4sL5QtzFsuijDz").unwrap();
        let usdc = decode_pubkey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let token = decode_pubkey(TOKEN_PROGRAM_ID).unwrap();
        let ata_prog = decode_pubkey(ATA_PROGRAM_ID).unwrap();

        let got = associated_token_address(&payer, &usdc, &token, &ata_prog);
        assert_eq!(
            crate::b58::encode_pubkey(&got),
            "FMbvJrg96qADXK2QYx2kuEVbSHwbjxAh2z4qeYjd2MSw"
        );
    }

    #[test]
    fn derives_real_onchain_wsol_ata() {
        let payer = decode_pubkey("4sLWYqVXqQHs7s4PQPrQ2agNVX1y3W4sL5QtzFsuijDz").unwrap();
        let wsol = decode_pubkey("So11111111111111111111111111111111111111112").unwrap();
        let token = decode_pubkey(TOKEN_PROGRAM_ID).unwrap();
        let ata_prog = decode_pubkey(ATA_PROGRAM_ID).unwrap();

        let got = associated_token_address(&payer, &wsol, &token, &ata_prog);
        assert_eq!(
            crate::b58::encode_pubkey(&got),
            "LxAHHWbVdtBuAPLV2ev7wunHW9bxoeXnQi5BLLmuibk"
        );
    }
}
