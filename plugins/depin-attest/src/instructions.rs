//! Instruction builders. Hand-rolled: solana-sdk does not compile to wasm32-wasip2.
use crate::{encode::decode_pubkey, CoreError};

pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
pub const RECENT_BLOCKHASHES_SYSVAR: &str = "SysvarRecentB1ockHashes11111111111111111111";

pub type Pubkey = [u8; 32];

#[derive(Debug, Clone, PartialEq)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// SPL Memo instruction (data ≤ 566 bytes). No signer accounts: the memo is
/// covered by the fee payer's signature on the transaction.
pub fn memo(text: &str) -> Result<Instruction, CoreError> {
    if text.len() > 566 {
        return Err(CoreError::Input(format!(
            "memo {} bytes exceeds 566",
            text.len()
        )));
    }
    Ok(Instruction {
        program_id: decode_pubkey(MEMO_PROGRAM_ID)?,
        accounts: vec![],
        data: text.as_bytes().to_vec(),
    })
}

/// SystemProgram::AdvanceNonceAccount (instruction index 4). MUST be the first
/// instruction in a durable-nonce transaction.
pub fn advance_nonce_account(
    nonce_pubkey: &str,
    authority: &str,
) -> Result<Instruction, CoreError> {
    Ok(Instruction {
        program_id: decode_pubkey(SYSTEM_PROGRAM_ID)?,
        accounts: vec![
            AccountMeta {
                pubkey: decode_pubkey(nonce_pubkey)?,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: decode_pubkey(RECENT_BLOCKHASHES_SYSVAR)?,
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: decode_pubkey(authority)?,
                is_signer: true,
                is_writable: false,
            },
        ],
        data: 4u32.to_le_bytes().to_vec(),
    })
}
