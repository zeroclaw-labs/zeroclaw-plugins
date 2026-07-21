use base64::Engine;

use crate::ix::{advance_nonce_instruction, memo_instruction, AccountMeta, Instruction};
use crate::keys::Pubkey;
use crate::{CoreError, CoreResult};

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

pub fn build_durable_memo_tx(
    payer: &Pubkey,
    nonce_account: &Pubkey,
    authority: &Pubkey,
    durable_nonce: &[u8; 32],
    memo: &str,
) -> CoreResult<Vec<u8>> {
    let instructions = vec![
        advance_nonce_instruction(nonce_account, authority),
        memo_instruction(payer, memo),
    ];
    let (account_keys, num_required_signatures, num_readonly_signed, num_readonly_unsigned) =
        compile_legacy_account_keys(payer, &instructions)?;
    let message = encode_legacy_message(
        num_required_signatures,
        num_readonly_signed,
        num_readonly_unsigned,
        &account_keys,
        durable_nonce,
        &instructions,
    );

    Ok(encode_unsigned_legacy_tx(&message, num_required_signatures))
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

fn compile_legacy_account_keys(
    payer: &Pubkey,
    instructions: &[Instruction],
) -> CoreResult<(Vec<Pubkey>, u8, u8, u8)> {
    let mut metas = Vec::new();
    add_or_merge_meta(
        &mut metas,
        AccountMeta {
            pubkey: *payer,
            is_signer: true,
            is_writable: true,
        },
    );

    for instruction in instructions {
        for account in &instruction.accounts {
            add_or_merge_meta(&mut metas, account.clone());
        }
        add_or_merge_meta(
            &mut metas,
            AccountMeta {
                pubkey: instruction.program_id,
                is_signer: false,
                is_writable: false,
            },
        );
    }

    let mut account_keys = Vec::with_capacity(metas.len());
    extend_keys_matching(&mut account_keys, &metas, true, true);
    extend_keys_matching(&mut account_keys, &metas, true, false);
    extend_keys_matching(&mut account_keys, &metas, false, true);
    extend_keys_matching(&mut account_keys, &metas, false, false);

    let num_required_signatures = checked_u8(
        metas.iter().filter(|meta| meta.is_signer).count(),
        "required signatures",
    )?;
    let num_readonly_signed = checked_u8(
        metas
            .iter()
            .filter(|meta| meta.is_signer && !meta.is_writable)
            .count(),
        "readonly signed accounts",
    )?;
    let num_readonly_unsigned = checked_u8(
        metas
            .iter()
            .filter(|meta| !meta.is_signer && !meta.is_writable)
            .count(),
        "readonly unsigned accounts",
    )?;

    Ok((
        account_keys,
        num_required_signatures,
        num_readonly_signed,
        num_readonly_unsigned,
    ))
}

fn add_or_merge_meta(metas: &mut Vec<AccountMeta>, meta: AccountMeta) {
    if let Some(existing) = metas
        .iter_mut()
        .find(|existing| existing.pubkey == meta.pubkey)
    {
        existing.is_signer |= meta.is_signer;
        existing.is_writable |= meta.is_writable;
        return;
    }

    metas.push(meta);
}

fn extend_keys_matching(
    account_keys: &mut Vec<Pubkey>,
    metas: &[AccountMeta],
    is_signer: bool,
    is_writable: bool,
) {
    account_keys.extend(
        metas
            .iter()
            .filter(|meta| meta.is_signer == is_signer && meta.is_writable == is_writable)
            .map(|meta| meta.pubkey),
    );
}

fn checked_u8(value: usize, label: &str) -> CoreResult<u8> {
    u8::try_from(value).map_err(|_| CoreError::msg(format!("{label} exceeds u8::MAX")))
}
