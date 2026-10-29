//! Durable nonce account state parsing.
//!
//! On-chain layout (`solana_sdk::nonce::state::Versions`, bincode, 80 bytes):
//! ```text
//! version:u32 (1 = Current) | state:u32 (0 = Uninitialized, 1 = Initialized)
//! authority: [u8;32] | durable_nonce (blockhash): [u8;32] | fee_calculator: u64
//! ```

use crate::core::pubkey::Pubkey;

pub const NONCE_ACCOUNT_SIZE: u64 = 80;

#[derive(Debug, PartialEq, Eq)]
pub struct NonceState {
    pub authority: Pubkey,
    /// The stored durable nonce, used as the transaction's recent_blockhash.
    pub blockhash: [u8; 32],
    pub lamports_per_signature: u64,
}

/// Parse the 80-byte nonce account data. Fails closed on anything that is not
/// an initialized, current-version nonce.
pub fn parse_nonce_account(data: &[u8]) -> Result<NonceState, String> {
    if data.len() < NONCE_ACCOUNT_SIZE as usize {
        return Err(format!(
            "account data is {} bytes; an initialized nonce account is {NONCE_ACCOUNT_SIZE}",
            data.len()
        ));
    }
    let version = u32::from_le_bytes(data[0..4].try_into().expect("4 bytes"));
    if version != 1 {
        return Err(format!("unsupported nonce account version {version}"));
    }
    let state = u32::from_le_bytes(data[4..8].try_into().expect("4 bytes"));
    if state != 1 {
        return Err("nonce account exists but is not initialized".into());
    }
    let authority = Pubkey(data[8..40].try_into().expect("32 bytes"));
    let blockhash: [u8; 32] = data[40..72].try_into().expect("32 bytes");
    let lamports_per_signature = u64::from_le_bytes(data[72..80].try_into().expect("8 bytes"));
    Ok(NonceState {
        authority,
        blockhash,
        lamports_per_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_account_bytes() -> Vec<u8> {
        let mut d = Vec::with_capacity(80);
        d.extend_from_slice(&1u32.to_le_bytes()); // version Current
        d.extend_from_slice(&1u32.to_le_bytes()); // state Initialized
        d.extend_from_slice(&[7u8; 32]); // authority
        d.extend_from_slice(&[9u8; 32]); // durable nonce
        d.extend_from_slice(&5000u64.to_le_bytes());
        d
    }

    #[test]
    fn parses_initialized_nonce() {
        let st = parse_nonce_account(&valid_account_bytes()).unwrap();
        assert_eq!(st.authority, Pubkey([7u8; 32]));
        assert_eq!(st.blockhash, [9u8; 32]);
        assert_eq!(st.lamports_per_signature, 5000);
    }

    #[test]
    fn rejects_uninitialized_wrong_version_and_short_data() {
        let mut uninit = valid_account_bytes();
        uninit[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_nonce_account(&uninit).is_err());

        let mut wrong_ver = valid_account_bytes();
        wrong_ver[0..4].copy_from_slice(&9u32.to_le_bytes());
        assert!(parse_nonce_account(&wrong_ver).is_err());

        assert!(parse_nonce_account(&[0u8; 10]).is_err());
        assert!(parse_nonce_account(&[]).is_err());
    }
}
