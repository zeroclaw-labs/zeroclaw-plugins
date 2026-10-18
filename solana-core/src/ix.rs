use crate::keys::Pubkey;

pub const MEMO_PROGRAM_ID: Pubkey = Pubkey::new([
    0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06, 0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38, 0x7c,
    0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81, 0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, 0x44, 0x8d,
]);
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new([0u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

pub fn memo_instruction(payer: &Pubkey, memo: &str) -> Instruction {
    Instruction {
        program_id: MEMO_PROGRAM_ID,
        accounts: vec![AccountMeta {
            pubkey: *payer,
            is_signer: true,
            is_writable: false,
        }],
        data: memo.as_bytes().to_vec(),
    }
}

pub fn advance_nonce_instruction(nonce_account: &Pubkey, authority: &Pubkey) -> Instruction {
    let recent_blockhashes_sysvar =
        Pubkey::from_base58("SysvarRecentB1ockHashes11111111111111111111")
            .expect("valid recent blockhashes sysvar id");

    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            AccountMeta {
                pubkey: *nonce_account,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: recent_blockhashes_sysvar,
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: *authority,
                is_signer: true,
                is_writable: false,
            },
        ],
        data: 4u32.to_le_bytes().to_vec(),
    }
}
