//! SPL / Token-2022 **token account** (balance) decoding.
//!
//! The 165-byte `spl-token` `Account` layout, shared by Token-2022 (which then
//! appends extensions we ignore here). Used by balance-reading plugins such as
//! `portfolio-brief`. Only the fields a read-only balance view needs are
//! decoded; everything is bounds-checked.

use crate::base58;
use crate::Pubkey;

/// Length of the packed base token account (`spl_token::state::Account::LEN`).
pub const TOKEN_ACCOUNT_LEN: usize = 165;

/// A decoded token account holding a balance of one mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAccount {
    /// The mint this account holds.
    pub mint: Pubkey,
    /// The wallet that owns this token account.
    pub owner: Pubkey,
    /// Raw balance in base units (pre-decimals).
    pub amount: u64,
    /// Whether the account is frozen (state == 2).
    pub frozen: bool,
}

impl TokenAccount {
    /// Base58 mint address, for keying prices and display.
    pub fn mint_str(&self) -> String {
        base58::encode(&self.mint)
    }
}

/// Decode a 165-byte token account. Accepts longer buffers (Token-2022 accounts
/// with extensions) and reads only the base fields.
pub fn parse_token_account(data: &[u8]) -> Result<TokenAccount, String> {
    if data.len() < TOKEN_ACCOUNT_LEN {
        return Err(format!(
            "account data is {} bytes, too short for a token account ({TOKEN_ACCOUNT_LEN})",
            data.len()
        ));
    }
    let mut mint = [0u8; 32];
    mint.copy_from_slice(&data[0..32]);
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&data[32..64]);
    let amount = u64::from_le_bytes(data[64..72].try_into().unwrap());
    let frozen = data[108] == 2;

    Ok(TokenAccount {
        mint,
        owner,
        amount,
        frozen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_bytes(mint: [u8; 32], owner: [u8; 32], amount: u64, state: u8) -> Vec<u8> {
        let mut b = vec![0u8; TOKEN_ACCOUNT_LEN];
        b[0..32].copy_from_slice(&mint);
        b[32..64].copy_from_slice(&owner);
        b[64..72].copy_from_slice(&amount.to_le_bytes());
        b[108] = state;
        b
    }

    #[test]
    fn decodes_a_balance() {
        let mint = [1u8; 32];
        let owner = [2u8; 32];
        let a = parse_token_account(&account_bytes(mint, owner, 12_345, 1)).unwrap();
        assert_eq!(a.mint, mint);
        assert_eq!(a.owner, owner);
        assert_eq!(a.amount, 12_345);
        assert!(!a.frozen);
    }

    #[test]
    fn detects_frozen_state() {
        let a = parse_token_account(&account_bytes([1u8; 32], [2u8; 32], 1, 2)).unwrap();
        assert!(a.frozen);
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(parse_token_account(&[0u8; 64]).is_err());
    }

    #[test]
    fn accepts_token_2022_account_with_trailing_extensions() {
        let mut b = account_bytes([3u8; 32], [4u8; 32], 99, 1);
        b.extend_from_slice(&[0xAB; 40]); // trailing extension bytes, ignored
        let a = parse_token_account(&b).unwrap();
        assert_eq!(a.amount, 99);
    }
}
