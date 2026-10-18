use crate::memo::{AccountMeta, Instruction};

pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

// Decoded from "SysvarRecentB1ockHashes11111111111111111111"
pub const SYSVAR_RECENT_BLOCKHASHES: [u8; 32] = [
    6, 167, 213, 23, 25, 44, 86, 142, 224, 138, 132, 95, 115, 210, 151, 136,
    207, 3, 92, 49, 69, 178, 26, 179, 68, 216, 6, 46, 169, 64, 0, 0
];

pub fn build_advance_nonce_instruction(nonce_account: &[u8; 32], nonce_authority: &[u8; 32]) -> Instruction {
    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            AccountMeta {
                pubkey: *nonce_account,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: SYSVAR_RECENT_BLOCKHASHES,
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: *nonce_authority,
                is_signer: true,
                is_writable: false,
            },
        ],
        data: vec![4, 0, 0, 0],
    }
}
