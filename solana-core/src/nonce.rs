use crate::keys::Pubkey;
use crate::{CoreError, CoreResult};

pub const NONCE_ACCOUNT_SIZE: usize = 80;

const INITIALIZED_STATE: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceState {
    pub authority: Pubkey,
    pub durable_nonce: [u8; 32],
    pub fee_calculator_lamports_per_signature: u64,
}

pub fn parse_nonce_account(data: &[u8]) -> CoreResult<NonceState> {
    if data.len() < NONCE_ACCOUNT_SIZE {
        return Err(CoreError::msg(format!(
            "nonce account data must be at least {NONCE_ACCOUNT_SIZE} bytes, got {}",
            data.len()
        )));
    }

    let state = u32::from_le_bytes(data[4..8].try_into().expect("state slice is 4 bytes"));
    if state != INITIALIZED_STATE {
        return Err(CoreError::msg(format!(
            "nonce account is not initialized: state {state}"
        )));
    }

    let mut authority = [0u8; 32];
    authority.copy_from_slice(&data[8..40]);

    let mut durable_nonce = [0u8; 32];
    durable_nonce.copy_from_slice(&data[40..72]);

    let fee_calculator_lamports_per_signature =
        u64::from_le_bytes(data[72..80].try_into().expect("fee slice is 8 bytes"));

    Ok(NonceState {
        authority: Pubkey::new(authority),
        durable_nonce,
        fee_calculator_lamports_per_signature,
    })
}
