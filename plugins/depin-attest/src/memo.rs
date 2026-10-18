//! Hand-rolled Solana Memo program instruction. No `solana-sdk` dependency —
//! the memo program takes no accounts and its instruction data is just the
//! UTF-8 text to commit, so there is nothing an SDK buys us here.
//!
//! Memo v2 program id: `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`.

pub const MEMO_PROGRAM_ID: [u8; 32] = [
    0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06, 0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38,
    0x7c, 0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81, 0xe4, 0x16, 0x53, 0x13, 0x36, 0x08,
    0x00, 0x09,
];

/// A compiled instruction ready for inclusion in a `MessageV0`.
pub struct CompiledInstruction {
    /// Index of the program id within the message's `account_keys`.
    pub program_id_index: u8,
    /// Indices of accounts within `account_keys`. The memo program needs none.
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

/// Build a Memo instruction from UTF-8 text. `program_id_index` assumes the
/// caller places the memo program as the second entry in `account_keys`
/// (index 1), after the fee payer (index 0) — see [`crate::tx::serialize`].
pub fn memo_instruction(text: &str) -> CompiledInstruction {
    CompiledInstruction {
        program_id_index: 1,
        accounts: vec![],
        data: text.as_bytes().to_vec(),
    }
}
