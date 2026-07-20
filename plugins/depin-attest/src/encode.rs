//! Wire encoding: bs58 helpers, compact-u16, legacy message serialization.
use crate::CoreError;

/// Solana "compact-u16" (shortvec): 1 byte for 0..=127, up to 3 bytes.
pub fn compact_u16(mut n: u16, out: &mut Vec<u8>) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

pub fn decode_pubkey(s: &str) -> Result<[u8; 32], CoreError> {
    let v = bs58::decode(s)
        .into_vec()
        .map_err(|e| CoreError::Parse(e.to_string()))?;
    v.try_into()
        .map_err(|_| CoreError::Input("pubkey must be 32 bytes".into()))
}

pub fn to_base64(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(bytes)
}

use crate::instructions::{Instruction, Pubkey};

pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
}

pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

pub struct CompiledMessage {
    pub header: MessageHeader,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
}

struct Meta {
    pubkey: Pubkey,
    is_signer: bool,
    is_writable: bool,
}

/// Compile a legacy message, matching `@solana/web3.js` `compileMessage`:
/// collect all instruction accounts + program ids, sort by (signer, writable,
/// pubkey ascending), dedup keeping the strongest flags, force the fee payer to
/// the front, then compute the header and remap instruction accounts to indexes.
/// (Pubkey byte order equals base58 value order for equal-length keys.)
pub fn compile_message(
    fee_payer: &str,
    instructions: &[Instruction],
    recent_blockhash: &str,
) -> Result<CompiledMessage, CoreError> {
    let fee_payer_pk = decode_pubkey(fee_payer)?;

    let mut metas: Vec<Meta> = Vec::new();
    for ix in instructions {
        for a in &ix.accounts {
            metas.push(Meta {
                pubkey: a.pubkey,
                is_signer: a.is_signer,
                is_writable: a.is_writable,
            });
        }
    }
    for ix in instructions {
        metas.push(Meta {
            pubkey: ix.program_id,
            is_signer: false,
            is_writable: false,
        });
    }

    metas.sort_by(|x, y| {
        y.is_signer
            .cmp(&x.is_signer)
            .then(y.is_writable.cmp(&x.is_writable))
            .then(x.pubkey.cmp(&y.pubkey))
    });

    let mut unique: Vec<Meta> = Vec::with_capacity(metas.len());
    for m in metas {
        if let Some(u) = unique.iter_mut().find(|u| u.pubkey == m.pubkey) {
            u.is_writable |= m.is_writable;
            u.is_signer |= m.is_signer;
        } else {
            unique.push(m);
        }
    }

    match unique.iter().position(|m| m.pubkey == fee_payer_pk) {
        Some(pos) => {
            let mut p = unique.remove(pos);
            p.is_signer = true;
            p.is_writable = true;
            unique.insert(0, p);
        }
        None => unique.insert(
            0,
            Meta {
                pubkey: fee_payer_pk,
                is_signer: true,
                is_writable: true,
            },
        ),
    }

    let account_keys: Vec<Pubkey> = unique.iter().map(|m| m.pubkey).collect();
    let index_of = |pk: &Pubkey| account_keys.iter().position(|k| k == pk).unwrap() as u8;

    let header = MessageHeader {
        num_required_signatures: unique.iter().filter(|m| m.is_signer).count() as u8,
        num_readonly_signed: unique
            .iter()
            .filter(|m| m.is_signer && !m.is_writable)
            .count() as u8,
        num_readonly_unsigned: unique
            .iter()
            .filter(|m| !m.is_signer && !m.is_writable)
            .count() as u8,
    };

    let compiled = instructions
        .iter()
        .map(|ix| CompiledInstruction {
            program_id_index: index_of(&ix.program_id),
            accounts: ix.accounts.iter().map(|a| index_of(&a.pubkey)).collect(),
            data: ix.data.clone(),
        })
        .collect();

    Ok(CompiledMessage {
        header,
        account_keys,
        recent_blockhash: decode_pubkey(recent_blockhash)?,
        instructions: compiled,
    })
}

/// Serialize a compiled legacy message to wire bytes:
/// `[header 3B][compact-u16 keys][32B blockhash][compact-u16 instructions]`.
pub fn serialize_message(msg: &CompiledMessage) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(msg.header.num_required_signatures);
    out.push(msg.header.num_readonly_signed);
    out.push(msg.header.num_readonly_unsigned);
    compact_u16(msg.account_keys.len() as u16, &mut out);
    for k in &msg.account_keys {
        out.extend_from_slice(k);
    }
    out.extend_from_slice(&msg.recent_blockhash);
    compact_u16(msg.instructions.len() as u16, &mut out);
    for ci in &msg.instructions {
        out.push(ci.program_id_index);
        compact_u16(ci.accounts.len() as u16, &mut out);
        out.extend_from_slice(&ci.accounts);
        compact_u16(ci.data.len() as u16, &mut out);
        out.extend_from_slice(&ci.data);
    }
    out
}
