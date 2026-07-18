//! Durable nonce account parsing — the fix for the approval-gate blockhash
//! problem. A transaction built on a recent blockhash dies ~60–90 seconds
//! after build; one built on a durable nonce (with `AdvanceNonceAccount`
//! leading) stays valid until the nonce is consumed, so a human can approve
//! from their phone an hour later.
//!
//! On-chain layout (bincode, 80 bytes):
//! `u32 version tag (1 = Current)` · `u32 state tag (1 = Initialized)` ·
//! `authority Pubkey (32)` · `durable nonce hash (32)` ·
//! `fee lamports-per-signature (u64)`.

use crate::pubkey::Pubkey;

pub const NONCE_ACCOUNT_LEN: usize = 80;

pub struct NonceState {
    pub authority: Pubkey,
    /// The durable nonce value, used in place of a recent blockhash.
    pub durable_nonce: [u8; 32],
}

/// Parse a system-program nonce account's data. Rejects uninitialized
/// accounts and unknown versions.
pub fn parse_nonce_account(data: &[u8]) -> Result<NonceState, String> {
    if data.len() < NONCE_ACCOUNT_LEN {
        return Err(format!(
            "nonce account data is {} bytes, expected {NONCE_ACCOUNT_LEN}",
            data.len()
        ));
    }
    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let state = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != 1 {
        return Err(format!("unsupported nonce account version {version}"));
    }
    if state != 1 {
        return Err("nonce account is not initialized".to_string());
    }
    let mut authority = [0u8; 32];
    authority.copy_from_slice(&data[8..40]);
    let mut durable_nonce = [0u8; 32];
    durable_nonce.copy_from_slice(&data[40..72]);
    Ok(NonceState {
        authority: Pubkey(authority),
        durable_nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(version: u32, state: u32) -> Vec<u8> {
        let mut data = Vec::with_capacity(NONCE_ACCOUNT_LEN);
        data.extend_from_slice(&version.to_le_bytes());
        data.extend_from_slice(&state.to_le_bytes());
        data.extend_from_slice(&[7u8; 32]); // authority
        data.extend_from_slice(&[9u8; 32]); // durable nonce
        data.extend_from_slice(&5000u64.to_le_bytes());
        data
    }

    #[test]
    fn parses_initialized_nonce() {
        let state = parse_nonce_account(&sample(1, 1)).unwrap();
        assert_eq!(state.authority.0, [7u8; 32]);
        assert_eq!(state.durable_nonce, [9u8; 32]);
    }

    #[test]
    fn rejects_uninitialized_and_short() {
        assert!(parse_nonce_account(&sample(1, 0)).is_err());
        assert!(parse_nonce_account(&sample(2, 1)).is_err());
        assert!(parse_nonce_account(&[0u8; 10]).is_err());
    }
}
