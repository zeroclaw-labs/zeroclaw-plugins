//! Pre-compile instruction types: full pubkeys and role flags, before addresses
//! are replaced by message indices. The instruction gate (`D1`–`D5`) reasons over
//! these; `encode` turns them into a compiled `V0Message`. Pure, no wasm dep.

#![forbid(unsafe_code)]

use crate::encode::Pubkey;

/// An account reference within an instruction, with its signer/writable roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// A Solana instruction as returned by Jupiter (or as we build it): the invoked
/// program, its account list with roles, and opaque data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}
