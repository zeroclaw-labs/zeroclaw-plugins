//! Durable nonce account state: the fix for blockhash expiry in
//! approval-gated agent payments.
//!
//! A transaction built on a recent blockhash dies in ~60-90 seconds; an agent
//! payment sitting in a human approval queue routinely outlives that. A
//! durable-nonce transaction instead carries the nonce account's stored hash
//! and stays valid until the nonce advances, i.e. until it (or a competing
//! transaction) actually lands.
//!
//! Account layout (80 bytes, verified against devnet post-state):
//! u32 LE versions tag (1 = Current) | u32 LE state tag (1 = Initialized) |
//! 32-byte authority | 32-byte durable nonce | u64 LE lamports_per_signature.
//! Legacy-version nonces (tag 0) never validate on the current runtime and
//! are rejected here.

use crate::pubkey::Pubkey;

/// Parsed state of an initialized durable nonce account.
#[derive(Debug, PartialEq, Eq)]
pub struct NonceState {
    pub authority: Pubkey,
    /// The stored durable nonce: used as the transaction's recent_blockhash.
    pub durable_nonce: [u8; 32],
    pub lamports_per_signature: u64,
}

/// Errors from nonce account parsing. Every branch fails closed.
#[derive(Debug, PartialEq, Eq)]
pub enum NonceError {
    WrongLength(usize),
    LegacyVersion,
    UnknownVersion(u32),
    Uninitialized,
    UnknownState(u32),
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NonceError::WrongLength(n) => write!(f, "nonce account data is {n} bytes, expected 80"),
            NonceError::LegacyVersion => {
                write!(
                    f,
                    "legacy-version nonce: never validates on the current runtime"
                )
            }
            NonceError::UnknownVersion(v) => write!(f, "unknown nonce versions tag {v}"),
            NonceError::Uninitialized => write!(f, "nonce account is uninitialized"),
            NonceError::UnknownState(s) => write!(f, "unknown nonce state tag {s}"),
        }
    }
}

/// Parse the raw 80-byte account data of a durable nonce account.
pub fn parse_nonce_account(data: &[u8]) -> Result<NonceState, NonceError> {
    if data.len() != 80 {
        return Err(NonceError::WrongLength(data.len()));
    }
    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
    match version {
        0 => return Err(NonceError::LegacyVersion),
        1 => {}
        v => return Err(NonceError::UnknownVersion(v)),
    }
    let state = u32::from_le_bytes(data[4..8].try_into().unwrap());
    match state {
        0 => return Err(NonceError::Uninitialized),
        1 => {}
        s => return Err(NonceError::UnknownState(s)),
    }
    Ok(NonceState {
        authority: Pubkey(data[8..40].try_into().unwrap()),
        durable_nonce: data[40..72].try_into().unwrap(),
        lamports_per_signature: u64::from_le_bytes(data[72..80].try_into().unwrap()),
    })
}

/// Rent-exempt balance for an 80-byte nonce account (devnet/mainnet default
/// rent parameters). Used only for operator documentation, never enforced.
pub const NONCE_RENT_LAMPORTS: u64 = 1_447_680;

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_data() -> Vec<u8> {
        let mut d = Vec::with_capacity(80);
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&[7u8; 32]);
        d.extend_from_slice(&[9u8; 32]);
        d.extend_from_slice(&5000u64.to_le_bytes());
        d
    }

    #[test]
    fn parses_initialized_current() {
        let s = parse_nonce_account(&valid_data()).unwrap();
        assert_eq!(s.authority, Pubkey([7; 32]));
        assert_eq!(s.durable_nonce, [9; 32]);
        assert_eq!(s.lamports_per_signature, 5000);
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            parse_nonce_account(&[0; 79]),
            Err(NonceError::WrongLength(79))
        );
    }

    #[test]
    fn rejects_legacy_version() {
        let mut d = valid_data();
        d[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse_nonce_account(&d), Err(NonceError::LegacyVersion));
    }

    #[test]
    fn rejects_uninitialized() {
        let mut d = valid_data();
        d[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse_nonce_account(&d), Err(NonceError::Uninitialized));
    }

    #[test]
    fn rejects_unknown_tags() {
        let mut d = valid_data();
        d[0..4].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(parse_nonce_account(&d), Err(NonceError::UnknownVersion(9)));
        let mut d2 = valid_data();
        d2[4..8].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(parse_nonce_account(&d2), Err(NonceError::UnknownState(3)));
    }

    /// The durable nonce is a domain-separated hash, not a raw blockhash:
    /// sha256("DURABLE_NONCE" || blockhash). Pin the prefix constant.
    #[test]
    fn durable_nonce_domain_hash() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"DURABLE_NONCE");
        h.update([171u8; 32]);
        let out: [u8; 32] = h.finalize().into();
        assert_eq!(
            hex(&out),
            "8e78351b9e96209014d3ca6056eb9d6bea6c772c38e84f344a83f13d581ad391"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
