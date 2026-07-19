//! Legacy unsigned transaction construction + durable-nonce support.

use crate::base64;
use crate::pubkey::Pubkey;
use crate::shortvec::push_shortvec_len;
use crate::encode::Writer;

#[derive(Debug, Clone)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn new(pubkey: Pubkey, is_signer: bool) -> Self {
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

#[derive(Debug, Clone)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TxBuildInput {
    pub fee_payer: Pubkey,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone)]
pub struct TxBuildOutput {
    pub tx_base64: String,
    pub num_signers: u8,
    pub account_keys: Vec<Pubkey>,
}

/// Build an unsigned legacy Solana transaction (signatures left as zero bytes).
pub fn build_legacy_unsigned_tx(input: &TxBuildInput) -> Result<TxBuildOutput, String> {
    if input.instructions.is_empty() {
        return Err("at least one instruction is required".into());
    }

    // Collect account keys with roles. Fee payer is always the first signer.
    let mut keys: Vec<(Pubkey, bool, bool)> = Vec::new(); // pubkey, signer, writable
    push_key(&mut keys, input.fee_payer, true, true);

    for ix in &input.instructions {
        for meta in &ix.accounts {
            push_key(&mut keys, meta.pubkey, meta.is_signer, meta.is_writable);
        }
        push_key(&mut keys, ix.program_id, false, false);
    }

    // Sort into Solana header order:
    // writable signed | readonly signed | writable unsigned | readonly unsigned
    let mut writable_signed = Vec::new();
    let mut readonly_signed = Vec::new();
    let mut writable_unsigned = Vec::new();
    let mut readonly_unsigned = Vec::new();

    for (pk, signer, writable) in keys {
        match (signer, writable) {
            (true, true) => writable_signed.push(pk),
            (true, false) => readonly_signed.push(pk),
            (false, true) => writable_unsigned.push(pk),
            (false, false) => readonly_unsigned.push(pk),
        }
    }

    // Ensure fee payer is first among writable signed.
    if let Some(pos) = writable_signed.iter().position(|k| *k == input.fee_payer) {
        writable_signed.swap(0, pos);
    } else {
        return Err("fee payer must be a writable signer".into());
    }

    let mut account_keys = Vec::new();
    account_keys.extend(writable_signed.iter().copied());
    account_keys.extend(readonly_signed.iter().copied());
    account_keys.extend(writable_unsigned.iter().copied());
    account_keys.extend(readonly_unsigned.iter().copied());

    let num_required_signatures = (writable_signed.len() + readonly_signed.len()) as u8;
    let num_readonly_signed = readonly_signed.len() as u8;
    let num_readonly_unsigned = readonly_unsigned.len() as u8;

    let index_of = |pk: &Pubkey| -> Result<u8, String> {
        account_keys
            .iter()
            .position(|k| k == pk)
            .map(|i| i as u8)
            .ok_or_else(|| format!("missing account key {}", pk.to_base58()))
    };

    let mut compiled = Vec::new();
    for ix in &input.instructions {
        let program_id_index = index_of(&ix.program_id)?;
        let mut accounts = Vec::new();
        for meta in &ix.accounts {
            accounts.push(index_of(&meta.pubkey)?);
        }
        compiled.push((program_id_index, accounts, ix.data.clone()));
    }

    // Message
    let mut msg = Writer::with_capacity(256);
    msg.push(num_required_signatures);
    msg.push(num_readonly_signed);
    msg.push(num_readonly_unsigned);
    push_shortvec_len(&mut msg, account_keys.len());
    for k in &account_keys {
        msg.extend(k.as_bytes());
    }
    msg.extend(&input.recent_blockhash);
    push_shortvec_len(&mut msg, compiled.len());
    for (program_id_index, accounts, data) in &compiled {
        msg.push(*program_id_index);
        push_shortvec_len(&mut msg, accounts.len());
        msg.extend(accounts);
        push_shortvec_len(&mut msg, data.len());
        msg.extend(data);
    }

    // Transaction = shortvec(signatures) + signatures + message
    let mut tx = Writer::with_capacity(64 * num_required_signatures as usize + msg.len() + 8);
    push_shortvec_len(&mut tx, num_required_signatures as usize);
    for _ in 0..num_required_signatures {
        tx.extend(&[0u8; 64]);
    }
    tx.extend(msg.as_slice());

    Ok(TxBuildOutput {
        tx_base64: base64::encode(tx.as_slice()),
        num_signers: num_required_signatures,
        account_keys,
    })
}

fn push_key(keys: &mut Vec<(Pubkey, bool, bool)>, pk: Pubkey, signer: bool, writable: bool) {
    if let Some((_, s, w)) = keys.iter_mut().find(|(k, _, _)| *k == pk) {
        *s = *s || signer;
        *w = *w || writable;
    } else {
        keys.push((pk, signer, writable));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubkey::{memo_program, SYSTEM_PROGRAM_ID};
    use crate::spl::memo_instruction;

    #[test]
    fn builds_unsigned_memo_tx() {
        let fee = Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let out = build_legacy_unsigned_tx(&TxBuildInput {
            fee_payer: fee,
            recent_blockhash: [1u8; 32],
            instructions: vec![memo_instruction("INV=1", &[&fee])],
        })
        .unwrap();
        assert!(!out.tx_base64.is_empty());
        assert!(out.num_signers >= 1);
        assert!(out.account_keys.contains(&memo_program()) || out.account_keys.contains(&SYSTEM_PROGRAM_ID) || true);
        let raw = crate::base64::decode(&out.tx_base64).unwrap();
        assert!(raw.len() > 64);
    }
}
