//! Solana public keys: base58 codec only.
//!
//! VENDORED. See `mod.rs` for the upstream source and revision. This copy is
//! REDUCED, not merely copied: upstream also carries the ed25519 on-curve test,
//! program-derived-address and associated-token-account derivation, and the
//! well-known program ids. This plugin parses and renders addresses and derives
//! nothing, so those are omitted along with the `curve25519-dalek`, `ed25519-dalek`
//! and `sha2` dependencies they need. `bs58` is the only dependency that remains.
//!
//! Keeping the reduction visible matters: a future need for PDA derivation here
//! should pull the upstream module back in whole rather than regrow it by hand.

/// A 32-byte Solana public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pubkey([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubkeyError {
    /// base58 decoded to a length other than 32 bytes.
    WrongLength(usize),
    /// Input was not valid base58.
    BadBase58,
}

impl Pubkey {
    pub const LEN: usize = 32;

    #[inline]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Pubkey(bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[inline]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Decode a base58 address. Rejects anything that is not exactly 32 bytes.
    pub fn from_base58(s: &str) -> Result<Self, PubkeyError> {
        let v = bs58::decode(s)
            .into_vec()
            .map_err(|_| PubkeyError::BadBase58)?;
        let arr: [u8; 32] = v
            .as_slice()
            .try_into()
            .map_err(|_| PubkeyError::WrongLength(v.len()))?;
        Ok(Pubkey(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }
}

impl core::fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl core::fmt::Display for Pubkey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    #[test]
    fn round_trips_a_real_mint() {
        let pk = Pubkey::from_base58(USDC_MINT).expect("valid base58 pubkey");
        assert_eq!(pk.to_base58(), USDC_MINT);
        assert_eq!(pk.as_bytes().len(), Pubkey::LEN);
    }

    #[test]
    fn rejects_non_base58() {
        // `0`, `O`, `I` and `l` are outside the base58 alphabet.
        assert_eq!(
            Pubkey::from_base58("0OIl"),
            Err(PubkeyError::BadBase58),
            "characters outside the alphabet must not decode"
        );
    }

    #[test]
    fn rejects_a_valid_base58_string_of_the_wrong_length() {
        // Decodes cleanly as base58 but is not 32 bytes, which is the case a
        // bare alphabet check would wave through.
        let short = bs58::encode([7u8; 31]).into_string();
        assert_eq!(
            Pubkey::from_base58(&short),
            Err(PubkeyError::WrongLength(31))
        );
    }

    #[test]
    fn renders_through_display_and_debug_as_base58() {
        let pk = Pubkey::from_base58(USDC_MINT).expect("valid base58 pubkey");
        assert_eq!(format!("{pk}"), USDC_MINT);
        assert_eq!(format!("{pk:?}"), USDC_MINT);
    }
}
