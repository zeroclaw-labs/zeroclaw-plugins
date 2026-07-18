//! `Instruction`/`AccountMeta` plus hand-rolled builders for the handful of
//! programs agent plugins compose: system transfers, SPL Token / Token-2022
//! `TransferChecked`, associated-token-account creation, memos, and durable
//! nonce advancement. Instruction data layouts follow the on-chain programs
//! byte for byte; each builder's encoding is pinned by a host test.

use crate::pubkey::{ata_program, memo_program, recent_blockhashes_sysvar, Pubkey, SYSTEM_PROGRAM};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn writable(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: true,
        }
    }
    pub fn readonly(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// System program `Transfer { lamports }` (enum index 2, bincode u32 tag).
pub fn system_transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: SYSTEM_PROGRAM,
        accounts: vec![
            AccountMeta::writable(*from, true),
            AccountMeta::writable(*to, false),
        ],
        data,
    }
}

/// SPL Token / Token-2022 `TransferChecked` (instruction 12): the checked
/// variant binds mint and decimals so a wrong-decimals build fails on-chain
/// instead of moving the wrong amount.
pub fn transfer_checked(
    token_program_id: &Pubkey,
    source_ata: &Pubkey,
    mint: &Pubkey,
    dest_ata: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(12u8);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: *token_program_id,
        accounts: vec![
            AccountMeta::writable(*source_ata, false),
            AccountMeta::readonly(*mint, false),
            AccountMeta::writable(*dest_ata, false),
            AccountMeta::readonly(*owner, true),
        ],
        data,
    }
}

/// Associated token account program `CreateIdempotent` (instruction 1):
/// creates the recipient's ATA if absent, no-ops if it already exists, so a
/// build never fails because the receiver is new to the mint.
pub fn create_ata_idempotent(
    payer: &Pubkey,
    ata: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    token_program_id: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: ata_program(),
        accounts: vec![
            AccountMeta::writable(*payer, true),
            AccountMeta::writable(*ata, false),
            AccountMeta::readonly(*owner, false),
            AccountMeta::readonly(*mint, false),
            AccountMeta::readonly(SYSTEM_PROGRAM, false),
            AccountMeta::readonly(*token_program_id, false),
        ],
        data: vec![1u8],
    }
}

/// SPL memo v2: UTF-8 payload, signed by the fee payer for attribution.
pub fn memo(signer: &Pubkey, text: &str) -> Instruction {
    Instruction {
        program_id: memo_program(),
        accounts: vec![AccountMeta::readonly(*signer, true)],
        data: text.as_bytes().to_vec(),
    }
}

/// System program `AdvanceNonceAccount` (enum index 4). Must be the first
/// instruction of a durable-nonce transaction.
pub fn advance_nonce(nonce_account: &Pubkey, nonce_authority: &Pubkey) -> Instruction {
    Instruction {
        program_id: SYSTEM_PROGRAM,
        accounts: vec![
            AccountMeta::writable(*nonce_account, false),
            AccountMeta::readonly(recent_blockhashes_sysvar(), false),
            AccountMeta::readonly(*nonce_authority, true),
        ],
        data: 4u32.to_le_bytes().to_vec(),
    }
}
