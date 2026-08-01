//! 32-byte Solana public key helpers.

use crate::core::base58;

pub const PUBKEY_BYTES: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pubkey(pub [u8; PUBKEY_BYTES]);

impl Pubkey {
    pub fn new(bytes: [u8; PUBKEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, String> {
        let arr: [u8; PUBKEY_BYTES] = slice
            .try_into()
            .map_err(|_| "pubkey must be 32 bytes".to_string())?;
        Ok(Self(arr))
    }

    pub fn to_base58(&self) -> String {
        base58::encode(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8; PUBKEY_BYTES] {
        &self.0
    }

    pub fn is_system_program(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl std::fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pubkey({})", self.to_base58())
    }
}

impl std::fmt::Display for Pubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}
