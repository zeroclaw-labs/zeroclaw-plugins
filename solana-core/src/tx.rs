use base64::Engine;

use crate::ix::Instruction;
use crate::keys::Pubkey;

pub fn encode_legacy_message(
    num_required_signatures: u8,
    num_readonly_signed_accounts: u8,
    num_readonly_unsigned_accounts: u8,
    account_keys: &[Pubkey],
    blockhash: &[u8; 32],
    instructions: &[Instruction],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(num_required_signatures);
    out.push(num_readonly_signed_accounts);
    out.push(num_readonly_unsigned_accounts);

    encode_compact_u16(account_keys.len(), &mut out);
    for key in account_keys {
        out.extend_from_slice(key.as_bytes());
    }

    out.extend_from_slice(blockhash);

    encode_compact_u16(instructions.len(), &mut out);
    for instruction in instructions {
        let program_id_index = account_index(account_keys, &instruction.program_id);
        out.push(program_id_index);

        encode_compact_u16(instruction.accounts.len(), &mut out);
        for account in &instruction.accounts {
            out.push(account_index(account_keys, &account.pubkey));
        }

        encode_compact_u16(instruction.data.len(), &mut out);
        out.extend_from_slice(&instruction.data);
    }

    out
}

pub fn encode_unsigned_legacy_tx(message: &[u8], num_required_signatures: u8) -> Vec<u8> {
    let mut out = Vec::new();
    encode_compact_u16(num_required_signatures as usize, &mut out);
    for _ in 0..num_required_signatures {
        out.extend_from_slice(&[0u8; 64]);
    }
    out.extend_from_slice(message);
    out
}

pub fn to_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn encode_compact_u16(len: usize, out: &mut Vec<u8>) {
    assert!(
        len <= u16::MAX as usize,
        "compact-u16 length exceeds u16::MAX"
    );
    let mut remaining = len as u16;
    loop {
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining == 0 {
            out.push(byte);
            break;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

fn account_index(account_keys: &[Pubkey], pubkey: &Pubkey) -> u8 {
    let index = account_keys
        .iter()
        .position(|account_key| account_key == pubkey)
        .expect("instruction references pubkey missing from account_keys");
    u8::try_from(index).expect("legacy account index exceeds u8::MAX")
}
