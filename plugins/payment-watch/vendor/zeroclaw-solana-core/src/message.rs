//! v0 versioned-message compilation and unsigned-transaction serialization.
//!
//! Compilation mirrors `solana_sdk::message::v0::Message::try_compile` for the
//! no-lookup-table case: the fee payer leads, then writable signers, readonly
//! signers, writable non-signers, readonly non-signers, with signer-ness and
//! writability merged across duplicate keys. The unsigned wire transaction
//! carries `num_required_signatures` all-zero signature placeholders so any
//! standard wallet or signer can deserialize it, fill in signatures, and
//! submit.

use std::collections::HashMap;

use crate::encoding::{push_compact_u16, to_base64};
use crate::instruction::Instruction;
use crate::pubkey::Pubkey;

const SIGNATURE_BYTES: usize = 64;
/// Solana's IPv6-MTU-derived packet limit: a serialized transaction larger
/// than this cannot be submitted.
pub const MAX_TRANSACTION_BYTES: usize = 1232;
/// High bit of the first message byte marks a versioned message; low bits are
/// the version number, so v0 is `0x80`.
const V0_PREFIX: u8 = 0x80;

/// A compiled v0 message plus the metadata callers surface to humans.
pub struct CompiledMessage {
    pub account_keys: Vec<Pubkey>,
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
    bytes: Vec<u8>,
}

impl CompiledMessage {
    pub fn message_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Serialize the full unsigned transaction: a compact array of
    /// `num_required_signatures` zeroed signatures followed by the message.
    /// This is the exact wire size the network will see (signatures included),
    /// so callers can check it against the 1232-byte packet limit.
    pub fn unsigned_transaction_bytes(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(
            1 + SIGNATURE_BYTES * self.num_required_signatures as usize + self.bytes.len(),
        );
        push_compact_u16(&mut wire, self.num_required_signatures as u16);
        wire.extend(std::iter::repeat_n(
            0u8,
            SIGNATURE_BYTES * self.num_required_signatures as usize,
        ));
        wire.extend_from_slice(&self.bytes);
        wire
    }

    pub fn unsigned_transaction_base64(&self) -> String {
        to_base64(&self.unsigned_transaction_bytes())
    }
}

#[derive(Default, Clone, Copy)]
struct KeyUse {
    is_signer: bool,
    is_writable: bool,
}

/// Compile instructions into a v0 message. `recent_blockhash` is the raw
/// 32-byte hash (a durable nonce value works identically).
pub fn compile_v0_message(
    fee_payer: &Pubkey,
    instructions: &[Instruction],
    recent_blockhash: &[u8; 32],
) -> Result<CompiledMessage, String> {
    if instructions.is_empty() {
        return Err("cannot compile an empty instruction list".to_string());
    }

    // Merge usage across every reference to each key.
    let mut uses: HashMap<Pubkey, KeyUse> = HashMap::new();
    let mut note = |key: &Pubkey, is_signer: bool, is_writable: bool| {
        let entry = uses.entry(*key).or_default();
        entry.is_signer |= is_signer;
        entry.is_writable |= is_writable;
    };

    note(fee_payer, true, true);
    for ix in instructions {
        for meta in &ix.accounts {
            note(&meta.pubkey, meta.is_signer, meta.is_writable);
        }
        note(&ix.program_id, false, false);
    }

    // Order: fee payer, writable signers, readonly signers, writable
    // non-signers, readonly non-signers. Within each class the SDK's
    // `CompiledKeys` drains a BTreeMap, so ties break on raw pubkey bytes —
    // matched here so our bytes are identical to `try_compile`'s.
    let class = |u: &KeyUse| match (u.is_signer, u.is_writable) {
        (true, true) => 0u8,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    };
    let mut keys: Vec<(Pubkey, KeyUse)> = uses.into_iter().collect();
    keys.sort_by_key(|(key, u)| (key != fee_payer, class(u), key.0));

    if keys.len() > u8::MAX as usize {
        return Err(format!("too many distinct account keys: {}", keys.len()));
    }

    let num_required_signatures = keys.iter().filter(|(_, u)| u.is_signer).count() as u8;
    let num_readonly_signed = keys
        .iter()
        .filter(|(_, u)| u.is_signer && !u.is_writable)
        .count() as u8;
    let num_readonly_unsigned = keys
        .iter()
        .filter(|(_, u)| !u.is_signer && !u.is_writable)
        .count() as u8;

    let index_of: HashMap<Pubkey, u8> = keys
        .iter()
        .enumerate()
        .map(|(i, (key, _))| (*key, i as u8))
        .collect();

    let mut bytes = Vec::with_capacity(256);
    bytes.push(V0_PREFIX);
    bytes.push(num_required_signatures);
    bytes.push(num_readonly_signed);
    bytes.push(num_readonly_unsigned);
    push_compact_u16(&mut bytes, keys.len() as u16);
    for (key, _) in &keys {
        bytes.extend_from_slice(&key.0);
    }
    bytes.extend_from_slice(recent_blockhash);
    push_compact_u16(&mut bytes, instructions.len() as u16);
    for ix in instructions {
        bytes.push(index_of[&ix.program_id]);
        push_compact_u16(&mut bytes, ix.accounts.len() as u16);
        for meta in &ix.accounts {
            bytes.push(index_of[&meta.pubkey]);
        }
        push_compact_u16(&mut bytes, ix.data.len() as u16);
        bytes.extend_from_slice(&ix.data);
    }
    // No address table lookups: agent-built transfers never need them.
    push_compact_u16(&mut bytes, 0);

    Ok(CompiledMessage {
        account_keys: keys.into_iter().map(|(k, _)| k).collect(),
        num_required_signatures,
        num_readonly_signed,
        num_readonly_unsigned,
        bytes,
    })
}
