//! Hand-rolled instruction encoding for the System, SPL-Token, ATA and Memo
//! programs, plus program-derived-address (PDA) math.
//!
//! `solana-sdk` does not compile for `wasm32-wasip2`, so the byte layouts
//! below are written against the on-chain programs' source and verified by
//! unit tests with vectors produced by the official SDK.

use sha2::{Digest, Sha256};

use crate::pubkey::{program_ids, Pubkey};

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

#[derive(Clone, Debug)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

fn pk(s: &str) -> Pubkey {
    Pubkey::from_base58(s).expect("static program id")
}

/// System program `Transfer` (enum index 2, bincode u32 LE + u64 LE lamports).
pub fn system_transfer(from: Pubkey, to: Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: pk(program_ids::SYSTEM),
        accounts: vec![
            AccountMeta::writable(from, true),
            AccountMeta::writable(to, false),
        ],
        data,
    }
}

/// System program `AdvanceNonceAccount` (enum index 4).
///
/// Must be the FIRST instruction of a durable-nonce transaction; the runtime
/// then accepts the nonce account's stored blockhash as `recent_blockhash`.
pub fn advance_nonce_account(nonce_account: Pubkey, authority: Pubkey) -> Instruction {
    Instruction {
        program_id: pk(program_ids::SYSTEM),
        accounts: vec![
            AccountMeta::writable(nonce_account, false),
            AccountMeta::readonly(pk(program_ids::SYSVAR_RECENT_BLOCKHASHES), false),
            AccountMeta::readonly(authority, true),
        ],
        data: 4u32.to_le_bytes().to_vec(),
    }
}

/// SPL-Token `TransferChecked` (instruction 12): amount + decimals are both
/// verified on-chain against the mint — safer than bare `Transfer` (3).
pub fn spl_transfer_checked(
    token_program: Pubkey,
    source_ata: Pubkey,
    mint: Pubkey,
    dest_ata: Pubkey,
    authority: Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(12u8);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: token_program,
        accounts: vec![
            AccountMeta::writable(source_ata, false),
            AccountMeta::readonly(mint, false),
            AccountMeta::writable(dest_ata, false),
            AccountMeta::readonly(authority, true),
        ],
        data,
    }
}

/// ATA program `CreateIdempotent` (instruction 1): no-op when the ATA exists,
/// which is exactly what an unsigned-proposal builder wants.
pub fn create_ata_idempotent(
    payer: Pubkey,
    ata: Pubkey,
    owner: Pubkey,
    mint: Pubkey,
    token_program: Pubkey,
) -> Instruction {
    Instruction {
        program_id: pk(program_ids::ATA),
        accounts: vec![
            AccountMeta::writable(payer, true),
            AccountMeta::writable(ata, false),
            AccountMeta::readonly(owner, false),
            AccountMeta::readonly(mint, false),
            AccountMeta::readonly(pk(program_ids::SYSTEM), false),
            AccountMeta::readonly(token_program, false),
        ],
        data: vec![1u8],
    }
}

/// SPL Memo: free-text reconciliation reference, signed by `signer`.
pub fn memo(text: &str, signer: Pubkey) -> Instruction {
    Instruction {
        program_id: pk(program_ids::MEMO),
        accounts: vec![AccountMeta::readonly(signer, true)],
        data: text.as_bytes().to_vec(),
    }
}

/// Is a 32-byte value a valid ed25519 curve point? PDAs must NOT be.
fn is_on_curve(bytes: &[u8; 32]) -> bool {
    curve25519_dalek::edwards::CompressedEdwardsY(*bytes)
        .decompress()
        .is_some()
}

/// `Pubkey::find_program_address` — the canonical bump-seed search.
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Result<(Pubkey, u8), String> {
    for bump in (0u8..=255).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update([bump]);
        hasher.update(program_id.0);
        hasher.update(b"ProgramDerivedAddress");
        let hash: [u8; 32] = hasher.finalize().into();
        if !is_on_curve(&hash) {
            return Ok((Pubkey(hash), bump));
        }
    }
    Err("no viable bump seed".into())
}

/// Derive the associated token account for (owner, mint) under `token_program`.
pub fn derive_ata(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Result<Pubkey, String> {
    let ata_program = pk(program_ids::ATA);
    find_program_address(&[&owner.0, &token_program.0, &mint.0], &ata_program).map(|(k, _)| k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_layout() {
        let from = pk(program_ids::MEMO); // arbitrary distinct keys
        let to = pk(program_ids::ATA);
        let ix = system_transfer(from, to, 1_000_000);
        assert_eq!(&ix.data[..4], &[2, 0, 0, 0]);
        assert_eq!(&ix.data[4..], &1_000_000u64.to_le_bytes());
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert!(!ix.accounts[1].is_signer && ix.accounts[1].is_writable);
    }

    #[test]
    fn advance_nonce_layout() {
        let ix = advance_nonce_account(pk(program_ids::MEMO), pk(program_ids::ATA));
        assert_eq!(ix.data, vec![4, 0, 0, 0]);
        assert_eq!(ix.accounts.len(), 3);
        assert_eq!(
            ix.accounts[1].pubkey.to_base58(),
            program_ids::SYSVAR_RECENT_BLOCKHASHES
        );
        assert!(ix.accounts[2].is_signer);
    }

    #[test]
    fn transfer_checked_layout() {
        let t = pk(program_ids::SPL_TOKEN);
        let ix = spl_transfer_checked(
            t,
            pk(program_ids::MEMO),
            pk(program_ids::NATIVE_MINT),
            pk(program_ids::ATA),
            pk(program_ids::SYSTEM),
            25_000_000,
            6,
        );
        assert_eq!(ix.data[0], 12);
        assert_eq!(&ix.data[1..9], &25_000_000u64.to_le_bytes());
        assert_eq!(ix.data[9], 6);
    }

    /// Golden vector: USDC ATA for the prize wallet, cross-checked 2026-07-22
    /// against mainnet `getTokenAccountsByOwner` (the account exists on-chain).
    #[test]
    fn derives_known_usdc_ata() {
        let owner = Pubkey::from_base58("4oL5MdWr2FFFzF1u2w8ctx8Yj77BYe8GLadGHuNvANd3").unwrap();
        let usdc = Pubkey::from_base58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let token = pk(program_ids::SPL_TOKEN);
        let ata = derive_ata(&owner, &usdc, &token).unwrap();
        assert_eq!(
            ata.to_base58(),
            "7JktSFAdMVixgsBQVm7V9RJ34LHy2RfyxHgqXfDJHFWa"
        );
    }

    #[test]
    fn pda_is_off_curve() {
        let (pda, _bump) = find_program_address(&[b"seed"], &pk(program_ids::SPL_TOKEN)).unwrap();
        assert!(!is_on_curve(&pda.0));
    }
}
