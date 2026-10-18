//! 32-byte ed25519 public keys + base58 codec.

use std::fmt;

/// A Solana public key: 32 raw ed25519 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pubkey(pub [u8; 32]);

/// Well-known program ids.
pub mod program_ids {
    pub const SYSTEM: &str = "11111111111111111111111111111111";
    pub const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    pub const SPL_TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
    pub const ATA: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
    pub const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
    /// SysvarRecentBlockhashes — still required by AdvanceNonceAccount.
    pub const SYSVAR_RECENT_BLOCKHASHES: &str = "SysvarRecentB1ockHashes11111111111111111111";
    pub const SYSVAR_RENT: &str = "SysvarRent111111111111111111111111111111111";
    /// Native mint (wrapped SOL) — useful for mint allowlists.
    pub const NATIVE_MINT: &str = "So11111111111111111111111111111111111111112";
}

impl Pubkey {
    /// Parse a base58 string. Fails closed on anything that is not exactly
    /// 32 bytes — a truncated or padded key is an attack surface, not a typo.
    pub fn from_base58(s: &str) -> Result<Self, String> {
        let bytes = bs58::decode(s.trim())
            .into_vec()
            .map_err(|e| format!("invalid base58: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))?;
        Ok(Pubkey(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    pub const fn zero() -> Self {
        Pubkey([0u8; 32])
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

/// Shorten a base58 key for human-readable summaries: `7xKX…gAsU`.
pub fn short(key: &str) -> String {
    let k = key.trim();
    if k.len() <= 9 {
        return k.to_string();
    }
    format!("{}…{}", &k[..4], &k[k.len() - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let k = Pubkey::from_base58(program_ids::SPL_TOKEN).unwrap();
        assert_eq!(k.to_base58(), program_ids::SPL_TOKEN);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(Pubkey::from_base58("abc").is_err());
        assert!(Pubkey::from_base58("").is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(Pubkey::from_base58("not!!base58%%").is_err());
    }

    #[test]
    fn short_format() {
        assert_eq!(
            short("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            "Toke…Q5DA"
        );
        assert_eq!(short("short"), "short");
    }
}
