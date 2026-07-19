//! 32-byte Solana public keys + well-known program IDs + PDA helpers.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

use crate::base58;

pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey([0u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pubkey(pub [u8; 32]);

impl std::fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pubkey({})", self.to_base58())
    }
}

impl Pubkey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_base58(s: &str) -> Result<Self, String> {
        let bytes = base58::decode(s)?;
        if bytes.len() != 32 {
            return Err(format!(
                "pubkey must decode to 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn to_base58(&self) -> String {
        base58::encode(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn short(&self) -> String {
        let s = self.to_base58();
        if s.len() <= 8 {
            s
        } else {
            format!("{}…{}", &s[..4], &s[s.len() - 4..])
        }
    }
}

pub fn token_program() -> Pubkey {
    Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").expect("token program")
}

pub fn associated_token_program() -> Pubkey {
    Pubkey::from_base58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").expect("ata program")
}

pub fn memo_program() -> Pubkey {
    Pubkey::from_base58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").expect("memo program")
}

pub fn usdc_mint_mainnet() -> Pubkey {
    Pubkey::from_base58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").expect("usdc mint")
}

pub fn system_program() -> Pubkey {
    SYSTEM_PROGRAM_ID
}

fn is_off_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_none()
}

/// Solana `find_program_address` — returns (pda, bump).
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Result<(Pubkey, u8), String> {
    for bump in (0u8..=255).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds {
            if seed.len() > 32 {
                return Err("seed length exceeds 32 bytes".into());
            }
            hasher.update(seed);
        }
        hasher.update([bump]);
        hasher.update(program_id.as_bytes());
        hasher.update(b"ProgramDerivedAddress");
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        if is_off_curve(&bytes) {
            return Ok((Pubkey(bytes), bump));
        }
    }
    Err("unable to find a viable program address bump".into())
}

pub fn get_associated_token_address(wallet: &Pubkey, mint: &Pubkey) -> Result<Pubkey, String> {
    let token = token_program();
    let ata_program = associated_token_program();
    let (pda, _) = find_program_address(
        &[wallet.as_bytes(), token.as_bytes(), mint.as_bytes()],
        &ata_program,
    )?;
    Ok(pda)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_program_base58() {
        assert_eq!(
            SYSTEM_PROGRAM_ID.to_base58(),
            "11111111111111111111111111111111"
        );
    }

    #[test]
    fn usdc_roundtrip() {
        let p = usdc_mint_mainnet();
        assert_eq!(p.to_base58(), "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    }

    #[test]
    fn known_ata_vector() {
        let wallet = SYSTEM_PROGRAM_ID;
        let mint = usdc_mint_mainnet();
        let a = get_associated_token_address(&wallet, &mint).unwrap();
        let b = get_associated_token_address(&wallet, &mint).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, wallet);
    }
}
