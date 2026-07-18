//! Durable nonce account decoding.
//!
//! This is the answer to the bounty's trap #1: an approval-gated transaction
//! whose blockhash expires while the human is at lunch. A durable-nonce tx uses
//! the account's *stored* nonce as its blockhash, so it stays valid until the
//! nonce is advanced. To build one we need the stored nonce and the authority,
//! which live in this 80-byte System-owned account.
//!
//! Layout (`nonce::state::Versions::Current`):
//! ```text
//!   [ 0.. 4) version (u32 LE)
//!   [ 4.. 8) state   (u32 LE: 0 = Uninitialized, 1 = Initialized)
//!   [ 8..40) authority (Pubkey)
//!   [40..72) durable nonce / blockhash (32 bytes)
//!   [72..80) fee_calculator.lamports_per_signature (u64 LE)
//! ```

use crate::error::{CoreError, Result};
use crate::pubkey::Pubkey;

/// Decoded, initialized nonce account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceData {
    pub authority: Pubkey,
    /// The stored nonce, used as the transaction's blockhash.
    pub blockhash: [u8; 32],
    pub lamports_per_signature: u64,
}

pub fn decode_nonce_account(data: &[u8]) -> Result<NonceData> {
    if data.len() < 80 {
        return Err(CoreError::Layout(format!(
            "nonce account is {} bytes, need 80",
            data.len()
        )));
    }
    let state = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if state != 1 {
        return Err(CoreError::Invalid(
            "nonce account is not initialized".into(),
        ));
    }
    let mut authority = [0u8; 32];
    authority.copy_from_slice(&data[8..40]);
    let mut blockhash = [0u8; 32];
    blockhash.copy_from_slice(&data[40..72]);
    let lamports_per_signature = u64::from_le_bytes(data[72..80].try_into().unwrap());
    Ok(NonceData {
        authority: Pubkey(authority),
        blockhash,
        lamports_per_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(state: u32, authority: [u8; 32], nonce: [u8; 32]) -> Vec<u8> {
        let mut d = vec![0u8; 80];
        d[0..4].copy_from_slice(&1u32.to_le_bytes());
        d[4..8].copy_from_slice(&state.to_le_bytes());
        d[8..40].copy_from_slice(&authority);
        d[40..72].copy_from_slice(&nonce);
        d[72..80].copy_from_slice(&5000u64.to_le_bytes());
        d
    }

    #[test]
    fn decodes_initialized_nonce() {
        let auth = [7u8; 32];
        let nonce = [9u8; 32];
        let n = decode_nonce_account(&build(1, auth, nonce)).unwrap();
        assert_eq!(n.authority, Pubkey(auth));
        assert_eq!(n.blockhash, nonce);
        assert_eq!(n.lamports_per_signature, 5000);
    }

    #[test]
    fn rejects_uninitialized() {
        assert!(matches!(
            decode_nonce_account(&build(0, [0u8; 32], [0u8; 32])),
            Err(CoreError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_short() {
        assert!(matches!(
            decode_nonce_account(&[0u8; 40]),
            Err(CoreError::Layout(_))
        ));
    }
}
