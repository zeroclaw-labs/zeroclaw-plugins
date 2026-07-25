//! Pubkeys, well-known program IDs, and PDA / ATA derivation.

use sha2::{Digest, Sha256};

/// A 32-byte Solana public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pubkey(pub [u8; 32]);

/// The system program: 32 zero bytes.
pub const SYSTEM_PROGRAM: Pubkey = Pubkey([0u8; 32]);

/// Errors from pubkey parsing.
#[derive(Debug, PartialEq, Eq)]
pub enum PubkeyError {
    BadBase58,
    BadLength(usize),
}

impl std::fmt::Display for PubkeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PubkeyError::BadBase58 => write!(f, "not valid base58"),
            PubkeyError::BadLength(n) => write!(f, "decoded to {n} bytes, expected 32"),
        }
    }
}

impl Pubkey {
    /// Parse a base58 pubkey string. Strict: must decode to exactly 32 bytes.
    pub fn parse(s: &str) -> Result<Self, PubkeyError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| PubkeyError::BadBase58)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| PubkeyError::BadLength(v.len()))?;
        Ok(Pubkey(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    /// True if the bytes decompress to a curve point (i.e. could be a real
    /// ed25519 key rather than a PDA).
    pub fn is_on_curve(&self) -> bool {
        curve25519_dalek::edwards::CompressedEdwardsY(self.0)
            .decompress()
            .is_some()
    }
}

impl std::fmt::Display for Pubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

/// SPL token program.
pub fn token_program() -> Pubkey {
    Pubkey::parse("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").expect("const")
}

/// Associated token account program.
pub fn ata_program() -> Pubkey {
    Pubkey::parse("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").expect("const")
}

/// SPL memo program (v2).
pub fn memo_program() -> Pubkey {
    Pubkey::parse("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").expect("const")
}

/// RecentBlockhashes sysvar (deprecated but still required in nonce metas).
pub fn recent_blockhashes_sysvar() -> Pubkey {
    Pubkey::parse("SysvarRecentB1ockHashes11111111111111111111").expect("const")
}

/// Rent sysvar.
pub fn rent_sysvar() -> Pubkey {
    Pubkey::parse("SysvarRent111111111111111111111111111111111").expect("const")
}

/// Derive a program address: try bumps 255..0, first off-curve hash wins.
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> ([u8; 32], u8) {
    for bump in (0u8..=255).rev() {
        let mut h = Sha256::new();
        for s in seeds {
            h.update(s);
        }
        h.update([bump]);
        h.update(program_id.0);
        h.update(b"ProgramDerivedAddress");
        let out: [u8; 32] = h.finalize().into();
        if !Pubkey(out).is_on_curve() {
            return (out, bump);
        }
    }
    unreachable!("no off-curve PDA found for any bump")
}

/// Derive the associated token account for (wallet, mint) under the classic
/// token program.
pub fn derive_ata(wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
    let tp = token_program();
    let (addr, _) = find_program_address(&[&wallet.0, &tp.0, &mint.0], &ata_program());
    Pubkey(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        let s = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        assert_eq!(Pubkey::parse(s).unwrap().to_base58(), s);
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(Pubkey::parse("abc").unwrap_err(), PubkeyError::BadLength(3));
    }

    #[test]
    fn rejects_bad_chars() {
        assert_eq!(Pubkey::parse("0OIl").unwrap_err(), PubkeyError::BadBase58);
    }

    #[test]
    fn system_program_is_zeroes() {
        assert_eq!(
            SYSTEM_PROGRAM.to_base58(),
            "11111111111111111111111111111111"
        );
    }
}
