//! Hand-encoded instructions for the five programs this suite touches:
//! system, SPL Token, associated-token-account, and memo.
//!
//! System-program instruction data is bincode: a `u32` little-endian
//! discriminant followed by fixed-width fields (strings are `u64` length +
//! bytes). SPL Token uses a single-byte discriminant. These layouts are
//! stable, documented in the respective program sources, and pinned by the
//! byte-exact tests in [`crate::core::message`].

use crate::core::pubkey::{
    ata_program, memo_program, system_program, sysvar_recent_blockhashes, sysvar_rent, Pubkey,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn signer_writable(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: true,
            is_writable: true,
        }
    }
    pub fn signer(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: true,
            is_writable: false,
        }
    }
    pub fn writable(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: false,
            is_writable: true,
        }
    }
    pub fn readonly(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            is_signer: false,
            is_writable: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

// --- System program (discriminants from solana_sdk::system_instruction) ---

const SYS_CREATE_ACCOUNT_WITH_SEED: u32 = 3;
const SYS_ADVANCE_NONCE: u32 = 4;
const SYS_INITIALIZE_NONCE: u32 = 6;
pub const SYS_TRANSFER: u32 = 2;

/// Fund and create `new_account` at the address derived from
/// `(base, seed, owner)`. `base` and the funding account are the same key
/// here by design: the human authority signs once, no extra keypair exists.
pub fn create_account_with_seed(
    from_base: &Pubkey,
    new_account: &Pubkey,
    seed: &str,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(4 + 32 + 8 + seed.len() + 8 + 8 + 32);
    data.extend_from_slice(&SYS_CREATE_ACCOUNT_WITH_SEED.to_le_bytes());
    data.extend_from_slice(&from_base.0);
    data.extend_from_slice(&(seed.len() as u64).to_le_bytes());
    data.extend_from_slice(seed.as_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(&owner.0);
    Instruction {
        program_id: system_program(),
        accounts: vec![
            AccountMeta::signer_writable(*from_base),
            AccountMeta::writable(*new_account),
        ],
        data,
    }
}

pub fn initialize_nonce_account(nonce_account: &Pubkey, authority: &Pubkey) -> Instruction {
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&SYS_INITIALIZE_NONCE.to_le_bytes());
    data.extend_from_slice(&authority.0);
    Instruction {
        program_id: system_program(),
        accounts: vec![
            AccountMeta::writable(*nonce_account),
            AccountMeta::readonly(sysvar_recent_blockhashes()),
            AccountMeta::readonly(sysvar_rent()),
        ],
        data,
    }
}

/// Must be the first instruction of every durable transaction.
pub fn advance_nonce_account(nonce_account: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction {
        program_id: system_program(),
        accounts: vec![
            AccountMeta::writable(*nonce_account),
            AccountMeta::readonly(sysvar_recent_blockhashes()),
            AccountMeta::signer(*authority),
        ],
        data: SYS_ADVANCE_NONCE.to_le_bytes().to_vec(),
    }
}

pub fn system_transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&SYS_TRANSFER.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: system_program(),
        accounts: vec![
            AccountMeta::signer_writable(*from),
            AccountMeta::writable(*to),
        ],
        data,
    }
}

// --- SPL Token ---

pub const TOKEN_TRANSFER_CHECKED: u8 = 12;

/// `TransferChecked`: amount and decimals are both validated on-chain against
/// the mint, which is exactly the property an approval flow wants.
pub fn spl_transfer_checked(
    token_prog: &Pubkey,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(TOKEN_TRANSFER_CHECKED);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: *token_prog,
        accounts: vec![
            AccountMeta::writable(*source),
            AccountMeta::readonly(*mint),
            AccountMeta::writable(*destination),
            AccountMeta::signer(*owner),
        ],
        data,
    }
}

// --- Associated Token Account program ---

/// `CreateIdempotent` (discriminant 1): safe to include even when the account
/// already exists, which keeps approval-delayed transactions valid.
pub fn create_ata_idempotent(
    payer: &Pubkey,
    ata: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
    token_prog: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: ata_program(),
        accounts: vec![
            AccountMeta::signer_writable(*payer),
            AccountMeta::writable(*ata),
            AccountMeta::readonly(*wallet),
            AccountMeta::readonly(*mint),
            AccountMeta::readonly(system_program()),
            AccountMeta::readonly(*token_prog),
        ],
        data: vec![1],
    }
}

// --- Memo ---

pub fn memo(text: &str) -> Instruction {
    Instruction {
        program_id: memo_program(),
        accounts: vec![],
        data: text.as_bytes().to_vec(),
    }
}
