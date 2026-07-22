//! Base58 <-> fixed-size byte packing for Solana-shaped keys and hashes.
//!
//! Deliberately independent of `solana-sdk`: everything here is a thin
//! wrapper over `bs58` plus fixed-size arrays, so the core crate never pulls
//! in the full Solana client stack.

use borsh::{BorshDeserialize, BorshSerialize};

pub const PUBKEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// A 32-byte Solana-style public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct Pubkey(pub [u8; PUBKEY_LEN]);

impl Pubkey {
    /// The System Program address: 32 zero bytes, base58-encoded as 32 `1` characters.
    pub const SYSTEM_PROGRAM: Pubkey = Pubkey([0u8; PUBKEY_LEN]);

    pub const fn new(bytes: [u8; PUBKEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_base58(s: &str) -> Result<Self, String> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| format!("invalid base58 pubkey: {e}"))?;
        if bytes.len() != PUBKEY_LEN {
            return Err(format!(
                "invalid pubkey length: expected {PUBKEY_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; PUBKEY_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }
}

impl std::fmt::Display for Pubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl std::fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pubkey({})", self.to_base58())
    }
}

/// A 64-byte ed25519 signature slot. All-zero denotes "not yet signed" — the
/// placeholder a transaction builder leaves for an external signer to fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Signature(pub [u8; SIGNATURE_LEN]);

impl Signature {
    pub const fn unsigned() -> Self {
        Self([0u8; SIGNATURE_LEN])
    }

    pub fn from_base58(s: &str) -> Result<Self, String> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| format!("invalid base58 signature: {e}"))?;
        if bytes.len() != SIGNATURE_LEN {
            return Err(format!(
                "invalid signature length: expected {SIGNATURE_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; SIGNATURE_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }
}

/// A blockhash (or, when used as a durable nonce value, the nonce account's
/// current stored value) is wire-identical to a 32-byte key.
pub type Blockhash = [u8; 32];

pub fn blockhash_from_base58(s: &str) -> Result<Blockhash, String> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| format!("invalid base58 blockhash: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "invalid blockhash length: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// The `SysvarRecentBlockhashes` sysvar address, required as an account
/// reference by the System Program's legacy `AdvanceNonceAccount` instruction.
pub fn recent_blockhashes_sysvar() -> Pubkey {
    Pubkey::from_base58("SysvarRecentB1ockHashes11111111111111111111")
        .expect("hardcoded sysvar address must be valid base58")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_base58_round_trips() {
        let original = Pubkey([7u8; 32]);
        let encoded = original.to_base58();
        let decoded = Pubkey::from_base58(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn system_program_is_all_zero() {
        assert_eq!(Pubkey::SYSTEM_PROGRAM.0, [0u8; 32]);
    }

    #[test]
    fn rejects_wrong_length_pubkey() {
        // Valid base58 but decodes to fewer than 32 bytes.
        let err = Pubkey::from_base58("11111111111111111111111111111111111111111").unwrap_err();
        assert!(err.contains("invalid pubkey length"));
    }

    #[test]
    fn rejects_invalid_base58_characters() {
        // '0', 'O', 'I', 'l' are excluded from the base58 alphabet.
        let err = Pubkey::from_base58("0OIl").unwrap_err();
        assert!(err.contains("invalid base58"));
    }

    #[test]
    fn recent_blockhashes_sysvar_is_well_formed() {
        // Must decode cleanly to 32 bytes; guards against a typo in the literal.
        let pk = recent_blockhashes_sysvar();
        assert_eq!(pk.0.len(), 32);
    }
}
