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
    TooLong(usize),
}

/// The longest base58 encoding of 32 bytes. Nothing longer can be a pubkey, and
/// base58 decoding is quadratic in the input length: 50,000 characters take
/// seconds and a megabyte takes hours, all to fail at the end anyway. Argument
/// strings come from a model that can be talked into anything, so the length is
/// checked before any decoding happens.
pub const MAX_BASE58_CHARS: usize = 44;

impl std::fmt::Display for PubkeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PubkeyError::BadBase58 => write!(f, "not valid base58"),
            PubkeyError::BadLength(n) => write!(f, "decoded to {n} bytes, expected 32"),
            PubkeyError::TooLong(n) => write!(
                f,
                "is {n} bytes, too long for a 32-byte key (at most {MAX_BASE58_CHARS} base58 characters)"
            ),
        }
    }
}

impl Pubkey {
    /// Parse a base58 pubkey string. Strict: must decode to exactly 32 bytes.
    pub fn parse(s: &str) -> Result<Self, PubkeyError> {
        if s.len() > MAX_BASE58_CHARS {
            return Err(PubkeyError::TooLong(s.len()));
        }
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

/// SPL token program (the classic one).
pub fn token_program() -> Pubkey {
    Pubkey::parse("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").expect("const")
}

/// SPL Token-2022. A separate program with its own accounts: it derives a
/// different associated token account for the same wallet and mint, and its
/// transfers carry this program id, so the two are never interchangeable.
pub fn token_2022_program() -> Pubkey {
    Pubkey::parse("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").expect("const")
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

/// Derive the associated token account for (wallet, mint) under
/// `token_program`.
///
/// The token program is the middle seed, so the classic program and Token-2022
/// derive different addresses for the same wallet and mint. It is an explicit
/// argument with no default: the owning program comes from the mint account,
/// and a caller that assumes the classic one for a Token-2022 mint builds a
/// transaction that cannot execute.
pub fn derive_ata(wallet: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    let (addr, _) = find_program_address(&[&wallet.0, &token_program.0, &mint.0], &ata_program());
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

    /// The token program is the middle seed, so the same wallet and mint land on
    /// two different addresses under the two programs. A classic ATA for a
    /// Token-2022 mint is an account that program will never accept.
    #[test]
    fn the_two_token_programs_derive_different_atas() {
        let wallet = Pubkey([1; 32]);
        let mint = Pubkey([2; 32]);
        let classic = derive_ata(&wallet, &mint, &token_program());
        let t22 = derive_ata(&wallet, &mint, &token_2022_program());
        assert_ne!(classic, t22, "the derivation ignored the token program");
    }

    #[test]
    fn refuses_a_string_too_long_to_be_a_key() {
        // base58 decoding is quadratic, so the length is checked first.
        let long = "z".repeat(MAX_BASE58_CHARS + 1);
        assert_eq!(
            Pubkey::parse(&long).unwrap_err(),
            PubkeyError::TooLong(MAX_BASE58_CHARS + 1)
        );
        assert_eq!(Pubkey([0xFF; 32]).to_base58().len(), MAX_BASE58_CHARS);
    }
}
