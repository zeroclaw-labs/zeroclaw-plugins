//! SPL Memo program instruction builder, plus the shared instruction model
//! (`Instruction` / `AccountMeta`) that `nonce` and `msg` build on.
//!
//! The Memo program takes no accounts and stores its raw UTF-8 argument as the
//! instruction data. Program id (SPL Memo v2):
//! `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`.

use crate::b58;

/// SPL Memo v2 program id (base58).
pub const MEMO_PROGRAM_ID_B58: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// One account reference within an instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountMeta {
    pub pubkey: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
}

/// A single Solana instruction, pre-compilation (real pubkeys, not indices).
#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    pub program_id: [u8; 32],
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// The 32-byte Memo program id.
pub fn memo_program_id() -> [u8; 32] {
    // Safe: the constant is a known-valid 32-byte base58 pubkey (golden-tested).
    b58::decode_pubkey(MEMO_PROGRAM_ID_B58).expect("memo program id is a valid pubkey")
}

/// Build the SPL Memo instruction for `text`: no accounts, data = raw UTF-8.
pub fn build_memo_ix(text: &str) -> Instruction {
    Instruction {
        program_id: memo_program_id(),
        accounts: Vec::new(),
        data: text.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memo_program_id_is_valid_32_bytes() {
        let id = memo_program_id();
        // Round-trips back to the canonical base58 string.
        assert_eq!(b58::encode(&id), MEMO_PROGRAM_ID_B58);
    }

    #[test]
    fn memo_ix_has_no_accounts_and_raw_utf8_data() {
        let ix = build_memo_ix("hello");
        assert!(ix.accounts.is_empty());
        assert_eq!(ix.data, b"hello");
        assert_eq!(ix.program_id, memo_program_id());
    }

    #[test]
    fn empty_memo_is_handled() {
        let ix = build_memo_ix("");
        assert!(ix.accounts.is_empty());
        assert!(ix.data.is_empty());
    }

    #[test]
    fn memo_data_is_exactly_the_input_bytes() {
        let json = r#"{"v":1,"dev":"kiosk01","seq":7}"#;
        let ix = build_memo_ix(json);
        assert_eq!(ix.data, json.as_bytes());
        // UTF-8 multibyte survives intact.
        let ix2 = build_memo_ix("café ☕");
        assert_eq!(ix2.data, "café ☕".as_bytes());
    }
}
