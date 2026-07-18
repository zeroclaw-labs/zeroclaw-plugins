//! Base58 ed25519 public keys and program-derived-address (PDA) derivation.
//!
//! PDA derivation follows the runtime exactly: sha256 over
//! `seeds || bump || program_id || "ProgramDerivedAddress"`, rejecting any
//! candidate that decompresses to a valid ed25519 point (on-curve keys can
//! sign, so they are not valid PDAs).

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

pub const PUBKEY_BYTES: usize = 32;

/// A Solana account address. Wraps the raw 32 bytes; display form is base58.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Pubkey(pub [u8; PUBKEY_BYTES]);

/// System program `11111111111111111111111111111111`.
pub const SYSTEM_PROGRAM: Pubkey = Pubkey([0u8; 32]);

impl Pubkey {
    /// Parse a base58 address; rejects anything that is not exactly 32 bytes.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut buf = [0u8; PUBKEY_BYTES];
        let len = bs58::decode(s.trim())
            .onto(&mut buf)
            .map_err(|_| format!("invalid base58 address: {s:?}"))?;
        if len != PUBKEY_BYTES {
            return Err(format!(
                "invalid address length: {s:?} decodes to {len} bytes, expected 32"
            ));
        }
        Ok(Pubkey(buf))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// True when the bytes decompress to a valid ed25519 curve point, i.e.
    /// the address could hold a private key.
    pub fn is_on_curve(&self) -> bool {
        CompressedEdwardsY(self.0).decompress().is_some()
    }
}

impl std::fmt::Display for Pubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base58())
    }
}

/// SPL Token program.
pub fn token_program() -> Pubkey {
    Pubkey::parse("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
}

/// Token-2022 (token extensions) program.
pub fn token_2022_program() -> Pubkey {
    Pubkey::parse("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap()
}

/// Associated token account program.
pub fn ata_program() -> Pubkey {
    Pubkey::parse("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap()
}

/// SPL memo v2 program.
pub fn memo_program() -> Pubkey {
    Pubkey::parse("MemoSq4gqABAXKb96qnH8TySNcWxMyWCqXgDLGmfcHr").unwrap()
}

/// `RecentBlockhashes` sysvar, still required by `AdvanceNonceAccount`.
pub fn recent_blockhashes_sysvar() -> Pubkey {
    Pubkey::parse("SysvarRecentB1ockHashes11111111111111111111").unwrap()
}

const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";
const MAX_SEED_LEN: usize = 32;

/// Derive a PDA for `seeds` + explicit bump. Errors if the candidate lands on
/// the curve or a seed exceeds the runtime's 32-byte limit.
pub fn create_program_address(
    seeds: &[&[u8]],
    bump: u8,
    program_id: &Pubkey,
) -> Result<Pubkey, String> {
    let mut hasher = Sha256::new();
    for seed in seeds {
        if seed.len() > MAX_SEED_LEN {
            return Err(format!("seed exceeds {MAX_SEED_LEN} bytes"));
        }
        hasher.update(seed);
    }
    hasher.update([bump]);
    hasher.update(program_id.0);
    hasher.update(PDA_MARKER);
    let candidate = Pubkey(hasher.finalize().into());
    if candidate.is_on_curve() {
        return Err("candidate PDA is on the ed25519 curve".to_string());
    }
    Ok(candidate)
}

/// Find the canonical (highest-bump) PDA for `seeds` under `program_id`.
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Result<(Pubkey, u8), String> {
    for bump in (0..=u8::MAX).rev() {
        if let Ok(pda) = create_program_address(seeds, bump, program_id) {
            return Ok((pda, bump));
        }
    }
    Err("no viable PDA bump found".to_string())
}

/// Derive the associated token account for `wallet` × `mint` under the given
/// token program (SPL Token or Token-2022).
pub fn derive_ata(
    wallet: &Pubkey,
    mint: &Pubkey,
    token_program_id: &Pubkey,
) -> Result<Pubkey, String> {
    let (ata, _) =
        find_program_address(&[&wallet.0, &token_program_id.0, &mint.0], &ata_program())?;
    Ok(ata)
}
