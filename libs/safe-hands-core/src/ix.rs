//! Instruction builders: exact byte layouts for the programs Safe Hands speaks.
//!
//! Every builder returns a canonical `solana_instruction::Instruction`. Layouts
//! follow the official program sources (SPL, Token-2022, Squads v4 — never
//! reverse-engineered from docs).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::crypto::{parse_pubkey, ATA_PROGRAM, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};

/// SPL Memo program (v2).
pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
/// Compute Budget program.
pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
/// Squads v4 multisig program (from official source: declare_id).
pub const SQUADS_V4_PROGRAM: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";
/// Recent Blockhashes sysvar.
pub const SYSVAR_RECENT_BLOCKHASHES: &str = "SysvarRecentB1ockHashes11111111111111111111";
/// System instruction discriminants (u32 LE).
pub const SYSTEM_IX_CREATE_ACCOUNT: u32 = 0;
pub const SYSTEM_IX_ASSIGN: u32 = 1;
pub const SYSTEM_IX_TRANSFER: u32 = 2;
pub const SYSTEM_IX_ADVANCE_NONCE: u32 = 4;
/// SPL Token / Token-2022 instruction discriminants (u8).
pub const TOKEN_IX_TRANSFER: u8 = 3;
pub const TOKEN_IX_SET_AUTHORITY: u8 = 6;
pub const TOKEN_IX_APPROVE: u8 = 7;
pub const TOKEN_IX_TRANSFER_CHECKED: u8 = 12;

fn meta(key: Pubkey, signer: bool, writable: bool) -> AccountMeta {
    if writable {
        AccountMeta::new(key, signer)
    } else {
        AccountMeta::new_readonly(key, signer)
    }
}

/// SystemProgram::Transfer { lamports } — data: u32 LE 2 + u64 LE lamports.
pub fn system_transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&SYSTEM_IX_TRANSFER.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: parse_pubkey(SYSTEM_PROGRAM).expect("constant"),
        accounts: vec![meta(*from, true, true), meta(*to, false, true)],
        data,
    }
}

/// SPL Token / Token-2022 TransferChecked — data: u8 12 + u64 LE amount + u8 decimals.
/// Accounts: source, mint, destination, owner (signer).
pub fn transfer_checked(
    token_program: &Pubkey,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(TOKEN_IX_TRANSFER_CHECKED);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: *token_program,
        accounts: vec![
            meta(*source, false, true),
            meta(*mint, false, false),
            meta(*destination, false, true),
            meta(*owner, true, false),
        ],
        data,
    }
}

/// AssociatedTokenAccount::CreateIdempotent — data: u8 1.
/// Accounts: payer, ata, owner, mint, system program, token program.
pub fn ata_create_idempotent(
    payer: &Pubkey,
    ata: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: parse_pubkey(ATA_PROGRAM).expect("constant"),
        accounts: vec![
            meta(*payer, true, true),
            meta(*ata, false, true),
            meta(*owner, false, false),
            meta(*mint, false, false),
            meta(
                parse_pubkey(SYSTEM_PROGRAM).expect("constant"),
                false,
                false,
            ),
            meta(*token_program, false, false),
        ],
        data: vec![1],
    }
}

/// Memo — raw UTF-8 payload, no discriminators.
pub fn memo(text: &str) -> Instruction {
    Instruction {
        program_id: parse_pubkey(MEMO_PROGRAM).expect("constant"),
        accounts: vec![],
        data: text.as_bytes().to_vec(),
    }
}

/// ComputeBudget::SetComputeUnitLimit — data: u8 2 + u32 LE units.
pub fn compute_unit_limit(units: u32) -> Instruction {
    let mut data = Vec::with_capacity(5);
    data.push(2);
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id: parse_pubkey(COMPUTE_BUDGET_PROGRAM).expect("constant"),
        accounts: vec![],
        data,
    }
}

/// ComputeBudget::SetComputeUnitPrice — data: u8 3 + u64 LE micro-lamports.
pub fn compute_unit_price(micro_lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.push(3);
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Instruction {
        program_id: parse_pubkey(COMPUTE_BUDGET_PROGRAM).expect("constant"),
        accounts: vec![],
        data,
    }
}

/// SystemProgram::AdvanceNonceAccount — data: u32 LE 4. Must be instruction 0.
/// Accounts: nonce account (writable), recent blockhashes sysvar, nonce authority.
pub fn advance_nonce(nonce_account: &Pubkey, nonce_authority: &Pubkey) -> Instruction {
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&SYSTEM_IX_ADVANCE_NONCE.to_le_bytes());
    Instruction {
        program_id: parse_pubkey(SYSTEM_PROGRAM).expect("constant"),
        accounts: vec![
            meta(*nonce_account, false, true),
            meta(
                parse_pubkey(SYSVAR_RECENT_BLOCKHASHES).expect("constant"),
                false,
                false,
            ),
            meta(*nonce_authority, false, false),
        ],
        data,
    }
}

/// The classic SPL Token program pubkey.
pub fn spl_token_program() -> Pubkey {
    parse_pubkey(TOKEN_PROGRAM).expect("constant")
}

/// The Token-2022 program pubkey.
pub fn token_2022_program() -> Pubkey {
    parse_pubkey(TOKEN_2022_PROGRAM).expect("constant")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_transfer_layout() {
        let from = Pubkey::new_from_array([1u8; 32]);
        let to = Pubkey::new_from_array([2u8; 32]);
        let ix = system_transfer(&from, &to, 1_000_000_000);
        assert_eq!(ix.data.len(), 12);
        assert_eq!(&ix.data[..4], &2u32.to_le_bytes());
        assert_eq!(&ix.data[4..], &1_000_000_000u64.to_le_bytes());
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert!(!ix.accounts[1].is_signer && ix.accounts[1].is_writable);
    }

    #[test]
    fn transfer_checked_layout() {
        let k = Pubkey::new_from_array;
        let ix = transfer_checked(
            &spl_token_program(),
            &k([3; 32]),
            &k([4; 32]),
            &k([5; 32]),
            &k([6; 32]),
            25_000_000,
            6,
        );
        assert_eq!(ix.data[0], TOKEN_IX_TRANSFER_CHECKED);
        assert_eq!(&ix.data[1..9], &25_000_000u64.to_le_bytes());
        assert_eq!(ix.data[9], 6);
        assert_eq!(ix.accounts.len(), 4);
        assert!(ix.accounts[3].is_signer);
    }

    #[test]
    fn nonce_advance_layout() {
        let ix = advance_nonce(
            &Pubkey::new_from_array([9; 32]),
            &Pubkey::new_from_array([8; 32]),
        );
        assert_eq!(&ix.data[..], &4u32.to_le_bytes());
        assert_eq!(ix.accounts.len(), 3);
    }
}
