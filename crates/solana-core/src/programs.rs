//! Instruction builders for the native programs the plugins use. Encodings are
//! spelled out by hand (no `solana-sdk`), each pinned by a byte-level test.

use crate::instruction::{AccountMeta, Instruction};
use crate::pubkey::{programs, Pubkey};

/// The RecentBlockhashes sysvar, required by AdvanceNonceAccount.
pub fn recent_blockhashes_sysvar() -> Pubkey {
    Pubkey::literal("SysvarRecentB1ockHashes11111111111111111111")
}

/// System program `Transfer`: move `lamports` from `from` (signer) to `to`.
/// Instruction index 2; data = u32 LE index + u64 LE lamports.
pub fn system_transfer(from: Pubkey, to: Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: programs::system(),
        accounts: vec![
            AccountMeta::new(from, true),
            AccountMeta::new(to, false),
        ],
        data,
    }
}

/// System program `AdvanceNonceAccount` (index 4). This must be the FIRST
/// instruction in a durable-nonce transaction; the message's blockhash field
/// carries the stored nonce instead of a live blockhash.
pub fn advance_nonce_account(nonce: Pubkey, authority: Pubkey) -> Instruction {
    Instruction {
        program_id: programs::system(),
        accounts: vec![
            AccountMeta::new(nonce, false),
            AccountMeta::readonly(recent_blockhashes_sysvar(), false),
            AccountMeta::readonly(authority, true),
        ],
        data: 4u32.to_le_bytes().to_vec(),
    }
}

/// SPL Memo v2 instruction carrying arbitrary UTF-8. Any `signers` become
/// required-signer accounts (the memo program verifies them); pass `&[]` for a
/// bare memo. Useful for invoice reconciliation and DePIN attestations.
pub fn memo(text: &str, signers: &[Pubkey]) -> Instruction {
    Instruction {
        program_id: programs::memo(),
        accounts: signers
            .iter()
            .map(|k| AccountMeta::readonly(*k, true))
            .collect(),
        data: text.as_bytes().to_vec(),
    }
}

/// ComputeBudget `SetComputeUnitLimit` (index 2): cap CU for the tx.
pub fn set_compute_unit_limit(units: u32) -> Instruction {
    let mut data = Vec::with_capacity(5);
    data.push(2);
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id: programs::compute_budget(),
        accounts: vec![],
        data,
    }
}

/// ComputeBudget `SetComputeUnitPrice` (index 3): priority fee in micro-lamports
/// per CU.
pub fn set_compute_unit_price(micro_lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.push(3);
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Instruction {
        program_id: programs::compute_budget(),
        accounts: vec![],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_encoding_is_index2_plus_lamports() {
        let ix = system_transfer(Pubkey([1u8; 32]), Pubkey([2u8; 32]), 1_000_000_000);
        assert_eq!(&ix.data[0..4], &2u32.to_le_bytes());
        assert_eq!(&ix.data[4..12], &1_000_000_000u64.to_le_bytes());
        assert_eq!(ix.program_id, programs::system());
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert!(!ix.accounts[1].is_signer && ix.accounts[1].is_writable);
    }

    #[test]
    fn advance_nonce_is_index4_with_three_accounts() {
        let ix = advance_nonce_account(Pubkey([5u8; 32]), Pubkey([6u8; 32]));
        assert_eq!(ix.data, 4u32.to_le_bytes());
        assert_eq!(ix.accounts.len(), 3);
        assert_eq!(ix.accounts[1].pubkey, recent_blockhashes_sysvar());
        assert!(ix.accounts[2].is_signer && !ix.accounts[2].is_writable);
    }

    #[test]
    fn memo_data_is_utf8() {
        let ix = memo("invoice #412", &[]);
        assert_eq!(ix.data, b"invoice #412");
        assert!(ix.accounts.is_empty());
        assert_eq!(ix.program_id, programs::memo());
    }

    #[test]
    fn compute_budget_encodings() {
        assert_eq!(set_compute_unit_limit(200_000).data[0], 2);
        assert_eq!(set_compute_unit_price(1_000).data[0], 3);
        assert_eq!(&set_compute_unit_price(1_000).data[1..9], &1_000u64.to_le_bytes());
    }
}
