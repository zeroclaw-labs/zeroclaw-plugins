//! Well-known Solana program IDs and instruction labels.

use crate::core::base58;
use crate::core::pubkey::Pubkey;

fn pk(b58: &str) -> Pubkey {
    let bytes = base58::decode(b58).expect("valid well-known pubkey");
    Pubkey::from_slice(&bytes).expect("32-byte pubkey")
}

pub fn system_program() -> Pubkey {
    Pubkey::new([0u8; 32])
}

pub fn token_program() -> Pubkey {
    pk("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}

pub fn token_2022_program() -> Pubkey {
    pk("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
}

pub fn associated_token_program() -> Pubkey {
    pk("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
}

pub fn compute_budget_program() -> Pubkey {
    pk("ComputeBudget111111111111111111111111111111")
}

pub fn bpf_upgradeable_loader() -> Pubkey {
    pk("BPFLoaderUpgradeab1e11111111111111111111111")
}

pub fn stake_program() -> Pubkey {
    pk("Stake11111111111111111111111111111111111111")
}

pub fn memo_program() -> Pubkey {
    pk("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
}

/// Human-readable name for a known program, if any.
pub fn program_label(program: &Pubkey) -> Option<&'static str> {
    if *program == system_program() {
        Some("System Program")
    } else if *program == token_program() {
        Some("SPL Token")
    } else if *program == token_2022_program() {
        Some("Token-2022")
    } else if *program == associated_token_program() {
        Some("Associated Token Account")
    } else if *program == compute_budget_program() {
        Some("Compute Budget")
    } else if *program == bpf_upgradeable_loader() {
        Some("BPF Upgradeable Loader")
    } else if *program == stake_program() {
        Some("Stake Program")
    } else if *program == memo_program() {
        Some("Memo")
    } else {
        None
    }
}

pub fn is_token_family(program: &Pubkey) -> bool {
    *program == token_program() || *program == token_2022_program()
}
