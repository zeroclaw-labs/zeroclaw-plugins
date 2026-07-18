//! A 32-byte Solana public key, plus the handful of program ids the plugins
//! reference. No curve math here: `find_program_address` needs ed25519
//! on-curve checks that pull in heavy crypto, and none of the shipped plugins
//! derive PDAs. When that lands it goes in its own module behind a feature.

use std::fmt;
use std::str::FromStr;

use crate::base58;
use crate::error::CoreError;

/// A Solana public key: 32 raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub const LEN: usize = 32;

    /// The all-zero key. Also the System program id and the "empty signature"
    /// placeholder in an unsigned transaction.
    pub const fn zeroed() -> Self {
        Pubkey([0u8; 32])
    }

    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_base58(s: &str) -> Result<Self, CoreError> {
        Ok(Pubkey(base58::decode_32(s)?))
    }

    pub fn to_base58(&self) -> String {
        base58::encode(&self.0)
    }

    /// Panicking constructor for compile-time-known-good literals (program ids).
    /// Never call with untrusted input; every use is covered by a test.
    pub(crate) fn literal(s: &str) -> Self {
        Pubkey::from_base58(s).expect("invalid pubkey literal")
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pubkey({})", self.to_base58())
    }
}

impl FromStr for Pubkey {
    type Err = CoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Pubkey::from_base58(s)
    }
}

/// Well-known program ids, resolved from their canonical base58 strings.
/// Functions rather than consts because base58 decoding is not `const`.
pub mod programs {
    use super::Pubkey;

    pub fn system() -> Pubkey {
        Pubkey::literal("11111111111111111111111111111111")
    }
    pub fn token() -> Pubkey {
        Pubkey::literal("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
    }
    pub fn token_2022() -> Pubkey {
        Pubkey::literal("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
    }
    pub fn memo() -> Pubkey {
        Pubkey::literal("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
    }
    pub fn compute_budget() -> Pubkey {
        Pubkey::literal("ComputeBudget111111111111111111111111111111")
    }
    pub fn associated_token() -> Pubkey {
        Pubkey::literal("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_program_ids_decode_and_roundtrip() {
        // If any literal above has a typo, from_base58 still succeeds (wrong
        // 32 bytes) but the roundtrip string won't match — catch it here.
        let ids = [
            ("system", programs::system(), "11111111111111111111111111111111"),
            ("token", programs::token(), "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            ("token_2022", programs::token_2022(), "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
            ("memo", programs::memo(), "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"),
            ("compute_budget", programs::compute_budget(), "ComputeBudget111111111111111111111111111111"),
            ("associated_token", programs::associated_token(), "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
        ];
        for (name, key, want) in ids {
            assert_eq!(key.to_base58(), want, "{name}");
        }
    }

    #[test]
    fn system_program_is_zero() {
        assert_eq!(programs::system(), Pubkey::zeroed());
    }

    #[test]
    fn parse_and_display() {
        let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let k: Pubkey = usdc.parse().unwrap();
        assert_eq!(k.to_string(), usdc);
    }

    #[test]
    fn rejects_bad_length() {
        assert!(matches!("abc".parse::<Pubkey>(), Err(CoreError::BadPubkey(_))));
    }
}
