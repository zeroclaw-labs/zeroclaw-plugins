//! Instruction builders for the handful of programs agent payment flows need.
//!
//! Layout ground truth (all simulated on devnet with `err: null`, see
//! `tests/vectors.rs`): the system program encodes `bincode`-style
//! (u32 LE enum tag + LE integers), SPL token / ATA / memo use single-byte or
//! raw discriminants. No borsh anywhere.

use crate::pubkey::{
    ata_program, memo_program, recent_blockhashes_sysvar, rent_sysvar, token_program, Pubkey,
    SYSTEM_PROGRAM,
};

/// How an account participates in an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// An un-compiled instruction: program + metas + data.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// SystemProgram::Transfer — tag 2, u64 LE lamports.
pub fn system_transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = 2u32.to_le_bytes().to_vec();
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

/// spl-token TransferChecked — discriminant 12, u64 LE amount, u8 decimals.
/// Metas: source ATA (w), mint (r), destination ATA (w), owner (s).
pub fn spl_transfer_checked(
    source_ata: &Pubkey,
    mint: &Pubkey,
    dest_ata: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::writable(*source_ata, false),
            AccountMeta::readonly(*mint, false),
            AccountMeta::writable(*dest_ata, false),
            AccountMeta::readonly(*owner, true),
        ],
        data,
    }
}

/// ATA CreateIdempotent — discriminant [1]. Creates the destination ATA when
/// missing; a no-op when it already exists.
/// Metas: payer (w,s), ata (w), wallet (r), mint (r), system (r), token (r).
pub fn ata_create_idempotent(
    payer: &Pubkey,
    ata: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: ata_program(),
        accounts: vec![
            AccountMeta::writable(*payer, true),
            AccountMeta::writable(*ata, false),
            AccountMeta::readonly(*wallet, false),
            AccountMeta::readonly(*mint, false),
            AccountMeta::readonly(SYSTEM_PROGRAM, false),
            AccountMeta::readonly(token_program(), false),
        ],
        data: vec![1u8],
    }
}

/// SPL memo — raw UTF-8 bytes, no accounts required.
pub fn memo(text: &str) -> Instruction {
    Instruction {
        program_id: memo_program(),
        accounts: vec![],
        data: text.as_bytes().to_vec(),
    }
}

/// SystemProgram::AdvanceNonceAccount — tag 4, no payload. MUST be the first
/// instruction of a durable-nonce transaction.
/// Metas: nonce account (w), RecentBlockhashes sysvar (r), authority (s).
pub fn advance_nonce(nonce_account: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction {
        program_id: SYSTEM_PROGRAM,
        accounts: vec![
            AccountMeta::writable(*nonce_account, false),
            AccountMeta::readonly(recent_blockhashes_sysvar(), false),
            AccountMeta::readonly(*authority, true),
        ],
        data: 4u32.to_le_bytes().to_vec(),
    }
}

/// SystemProgram::CreateAccount — tag 0, lamports u64, space u64, owner 32B.
/// The new account must also sign.
pub fn system_create_account(
    payer: &Pubkey,
    new_account: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let mut data = 0u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(&owner.0);
    Instruction {
        program_id: SYSTEM_PROGRAM,
        accounts: vec![
            AccountMeta::writable(*payer, true),
            AccountMeta::writable(*new_account, true),
        ],
        data,
    }
}

/// SystemProgram::InitializeNonceAccount — tag 6, authority 32B.
/// Metas: nonce (w), RecentBlockhashes sysvar (r), Rent sysvar (r).
pub fn initialize_nonce_account(nonce_account: &Pubkey, authority: &Pubkey) -> Instruction {
    let mut data = 6u32.to_le_bytes().to_vec();
    data.extend_from_slice(&authority.0);
    Instruction {
        program_id: SYSTEM_PROGRAM,
        accounts: vec![
            AccountMeta::writable(*nonce_account, false),
            AccountMeta::readonly(recent_blockhashes_sysvar(), false),
            AccountMeta::readonly(rent_sysvar(), false),
        ],
        data,
    }
}

/// Attach Solana Pay reference keys to a transfer instruction: read-only
/// non-signer metas appended in order, so validators index the transaction
/// under each reference.
pub fn attach_references(ix: &mut Instruction, references: &[Pubkey]) {
    for r in references {
        ix.accounts.push(AccountMeta::readonly(*r, false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_transfer_data_layout() {
        let a = Pubkey([1; 32]);
        let b = Pubkey([2; 32]);
        let ix = system_transfer(&a, &b, 1);
        // [2,0,0,0] tag ++ u64 LE 1 — the exact bytes from the Solana Pay
        // spec's example transaction.
        assert_eq!(ix.data, vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert!(!ix.accounts[1].is_signer && ix.accounts[1].is_writable);
    }

    #[test]
    fn transfer_checked_layout() {
        let ix = spl_transfer_checked(
            &Pubkey([1; 32]),
            &Pubkey([2; 32]),
            &Pubkey([3; 32]),
            &Pubkey([4; 32]),
            25_000_000,
            6,
        );
        assert_eq!(ix.data[0], 12);
        assert_eq!(
            u64::from_le_bytes(ix.data[1..9].try_into().unwrap()),
            25_000_000
        );
        assert_eq!(ix.data[9], 6);
        assert_eq!(ix.accounts.len(), 4);
        assert!(ix.accounts[3].is_signer, "owner signs");
    }

    #[test]
    fn advance_nonce_is_tag_4() {
        let ix = advance_nonce(&Pubkey([9; 32]), &Pubkey([7; 32]));
        assert_eq!(ix.data, vec![4, 0, 0, 0]);
        assert_eq!(ix.accounts.len(), 3);
        assert!(ix.accounts[2].is_signer, "authority signs");
        assert!(ix.accounts[0].is_writable, "nonce account writable");
    }

    #[test]
    fn create_idempotent_discriminant() {
        let ix = ata_create_idempotent(
            &Pubkey([1; 32]),
            &Pubkey([2; 32]),
            &Pubkey([3; 32]),
            &Pubkey([4; 32]),
        );
        assert_eq!(ix.data, vec![1]);
        assert_eq!(ix.accounts.len(), 6);
    }

    #[test]
    fn references_are_readonly_nonsigners() {
        let mut ix = system_transfer(&Pubkey([1; 32]), &Pubkey([2; 32]), 5);
        attach_references(&mut ix, &[Pubkey([8; 32]), Pubkey([9; 32])]);
        assert_eq!(ix.accounts.len(), 4);
        let r = &ix.accounts[3];
        assert!(!r.is_signer && !r.is_writable);
    }
}
