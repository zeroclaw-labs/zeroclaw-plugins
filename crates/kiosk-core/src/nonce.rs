//! Durable nonce: parse a nonce account's stored state, and build the
//! `AdvanceNonceAccount` System instruction that must be the first instruction
//! of any durable-nonce transaction.
//!
//! Nonce account data layout (bincode `nonce::state::Versions`, 80 bytes):
//! ```text
//!   [ 0.. 4]  version  u32 LE   (0 = Legacy, 1 = Current)
//!   [ 4.. 8]  state    u32 LE   (0 = Uninitialized, 1 = Initialized)
//!   [ 8..40]  authority         Pubkey (32)
//!   [40..72]  durable_nonce     Hash (32)  — the stored blockhash
//!   [72..80]  fee_calculator    u64 LE (lamports_per_signature)
//! ```
//! We accept only `Current` + `Initialized`; anything else fails closed.

use crate::memo::{AccountMeta, Instruction};
use crate::{b58, b64};

/// `SysvarRecentB1ockHashes11111111111111111111` — required account #2 of
/// AdvanceNonceAccount.
pub const RECENT_BLOCKHASHES_SYSVAR_B58: &str = "SysvarRecentB1ockHashes11111111111111111111";
/// System program id (32 zero bytes).
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];
/// SystemInstruction::AdvanceNonceAccount discriminant (u32 LE).
const ADVANCE_NONCE_DISCRIMINANT: [u8; 4] = [4, 0, 0, 0];
const NONCE_ACCOUNT_LEN: usize = 80;

#[derive(Debug, Clone, PartialEq)]
pub struct NonceAccount {
    pub authority: [u8; 32],
    /// The durable nonce (a stored blockhash) used in place of a recent blockhash.
    pub blockhash: [u8; 32],
}

/// Parse a base64 `getAccountInfo` data blob into a [`NonceAccount`].
/// Returns `None` unless it is a Current + Initialized nonce account of the
/// exact expected length — fail closed.
pub fn parse_nonce_account(base64_data: &str) -> Option<NonceAccount> {
    let bytes = b64::decode(base64_data)?;
    if bytes.len() < NONCE_ACCOUNT_LEN {
        return None;
    }
    let version = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let state = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    if version != 1 || state != 1 {
        return None; // not Current+Initialized
    }
    let authority: [u8; 32] = bytes[8..40].try_into().ok()?;
    let blockhash: [u8; 32] = bytes[40..72].try_into().ok()?;
    Some(NonceAccount {
        authority,
        blockhash,
    })
}

/// Build the `AdvanceNonceAccount` instruction. Accounts, in the order the
/// System program requires:
///   0. nonce account            (writable, not signer)
///   1. recent blockhashes sysvar (readonly, not signer)
///   2. nonce authority          (readonly, signer)
pub fn build_advance_nonce_ix(nonce_account: [u8; 32], nonce_authority: [u8; 32]) -> Instruction {
    let sysvar = b58::decode_pubkey(RECENT_BLOCKHASHES_SYSVAR_B58)
        .expect("recent blockhashes sysvar id is valid");
    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            AccountMeta {
                pubkey: nonce_account,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: sysvar,
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: nonce_authority,
                is_signer: true,
                is_writable: false,
            },
        ],
        data: ADVANCE_NONCE_DISCRIMINANT.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHORITY_B58: &str = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T";

    /// Assemble an 80-byte nonce account per the documented layout.
    fn nonce_blob(version: u32, state: u32, authority: [u8; 32], blockhash: [u8; 32]) -> String {
        let mut b = Vec::with_capacity(NONCE_ACCOUNT_LEN);
        b.extend_from_slice(&version.to_le_bytes());
        b.extend_from_slice(&state.to_le_bytes());
        b.extend_from_slice(&authority);
        b.extend_from_slice(&blockhash);
        b.extend_from_slice(&5000u64.to_le_bytes()); // fee_calculator
        b64::encode(&b)
    }

    #[test]
    fn parses_current_initialized_account() {
        let authority = b58::decode_pubkey(AUTHORITY_B58).unwrap();
        let blockhash = [0x11u8; 32];
        let blob = nonce_blob(1, 1, authority, blockhash);
        let parsed = parse_nonce_account(&blob).unwrap();
        assert_eq!(parsed.authority, authority);
        assert_eq!(parsed.blockhash, blockhash);
    }

    #[test]
    fn rejects_uninitialized_or_legacy_or_short() {
        let authority = b58::decode_pubkey(AUTHORITY_B58).unwrap();
        let bh = [0x22u8; 32];
        assert!(parse_nonce_account(&nonce_blob(1, 0, authority, bh)).is_none()); // uninitialized
        assert!(parse_nonce_account(&nonce_blob(0, 1, authority, bh)).is_none()); // legacy
        assert!(parse_nonce_account(&b64::encode(&[0u8; 40])).is_none()); // too short
        assert!(parse_nonce_account("not base64!!").is_none());
    }

    #[test]
    fn advance_nonce_ix_layout_is_correct() {
        let nonce = [0xAAu8; 32];
        let authority = b58::decode_pubkey(AUTHORITY_B58).unwrap();
        let ix = build_advance_nonce_ix(nonce, authority);

        assert_eq!(ix.program_id, SYSTEM_PROGRAM_ID);
        assert_eq!(ix.data, vec![4, 0, 0, 0]); // AdvanceNonceAccount discriminant
        assert_eq!(ix.accounts.len(), 3);

        // 0: nonce account — writable, not signer
        assert_eq!(ix.accounts[0].pubkey, nonce);
        assert!(ix.accounts[0].is_writable && !ix.accounts[0].is_signer);
        // 1: recent blockhashes sysvar — readonly, not signer
        assert_eq!(
            ix.accounts[1].pubkey,
            b58::decode_pubkey(RECENT_BLOCKHASHES_SYSVAR_B58).unwrap()
        );
        assert!(!ix.accounts[1].is_writable && !ix.accounts[1].is_signer);
        // 2: authority — signer, readonly
        assert_eq!(ix.accounts[2].pubkey, authority);
        assert!(ix.accounts[2].is_signer && !ix.accounts[2].is_writable);
    }
}
