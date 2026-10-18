//! Durable nonce account state parsing.
//!
//! A nonce account's data (v2 layout, 80 bytes) is:
//! `u32 version (LE) | u32 state (LE) | 32B authority | 32B durable nonce (blockhash) | u64 lamports_per_signature`.
//! We parse it from the base64 `getAccountInfo` response so a T1 builder can
//! anchor an unsigned transaction to the CURRENT stored nonce value.

use crate::encoding::b64_decode;
use crate::pubkey::Pubkey;

#[derive(Debug, Clone, PartialEq)]
pub struct NonceState {
    pub authority: Pubkey,
    /// The stored durable nonce — used as `recent_blockhash` in the tx.
    pub durable_nonce: [u8; 32],
    pub lamports_per_signature: u64,
}

/// Parse nonce account data from its base64 representation.
/// Fails closed on wrong owner-size/uninitialized state.
pub fn parse_nonce_account_b64(data_b64: &str) -> Result<NonceState, String> {
    let data = b64_decode(data_b64)?;
    parse_nonce_account(&data)
}

pub fn parse_nonce_account(data: &[u8]) -> Result<NonceState, String> {
    if data.len() < 80 {
        return Err(format!(
            "nonce account data too short: {} bytes",
            data.len()
        ));
    }
    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let state = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != 1 {
        return Err(format!("unsupported nonce account version {version}"));
    }
    // state: 0 = Uninitialized, 1 = Initialized
    if state != 1 {
        return Err("nonce account is uninitialized".into());
    }
    let authority = Pubkey(data[8..40].try_into().unwrap());
    let durable_nonce: [u8; 32] = data[40..72].try_into().unwrap();
    let lamports_per_signature = u64::from_le_bytes(data[72..80].try_into().unwrap());
    Ok(NonceState {
        authority,
        durable_nonce,
        lamports_per_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::b64_encode;

    fn sample(version: u32, state: u32) -> Vec<u8> {
        let mut d = Vec::with_capacity(80);
        d.extend_from_slice(&version.to_le_bytes());
        d.extend_from_slice(&state.to_le_bytes());
        d.extend_from_slice(&[0xAA; 32]); // authority
        d.extend_from_slice(&[0xBB; 32]); // nonce
        d.extend_from_slice(&5000u64.to_le_bytes());
        d
    }

    #[test]
    fn parses_initialized() {
        let st = parse_nonce_account(&sample(1, 1)).unwrap();
        assert_eq!(st.durable_nonce, [0xBB; 32]);
        assert_eq!(st.authority.0, [0xAA; 32]);
        assert_eq!(st.lamports_per_signature, 5000);
    }

    #[test]
    fn rejects_uninitialized() {
        assert!(parse_nonce_account(&sample(1, 0)).is_err());
    }

    #[test]
    fn rejects_bad_version() {
        assert!(parse_nonce_account(&sample(7, 1)).is_err());
    }

    #[test]
    fn rejects_short_data() {
        assert!(parse_nonce_account(&[0u8; 10]).is_err());
    }

    #[test]
    fn b64_path() {
        let b64 = b64_encode(&sample(1, 1));
        assert!(parse_nonce_account_b64(&b64).is_ok());
    }
}
