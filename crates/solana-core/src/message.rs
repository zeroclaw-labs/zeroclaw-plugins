//! Message compilation and serialization — the hand-rolled replacement for
//! `solana-sdk`'s `Message`/`VersionedTransaction`, which do not build for a
//! wasm32-wasip2 component.
//!
//! We produce an **unsigned** transaction: the correct number of zeroed
//! signature slots followed by the serialized message. A wallet, the ZeroClaw
//! approval gate, or a Squads proposal fills the signatures. The plugin never
//! holds a key, which is the whole point of the T1 tier.

use crate::base64;
use crate::error::{CoreError, Result};
use crate::instruction::Instruction;
use crate::pubkey::Pubkey;
use crate::shortvec;

/// Which transaction version to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageVersion {
    Legacy,
    /// v0 (supports address lookup tables; we emit an empty ALT list).
    V0,
}

/// A message ready to compile: fee payer, blockhash (or durable nonce), and the
/// ordered instruction list.
pub struct MessageBuilder {
    pub fee_payer: Pubkey,
    /// 32-byte recent blockhash, or the stored nonce for a durable-nonce tx.
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<Instruction>,
    pub version: MessageVersion,
}

struct KeyEntry {
    key: Pubkey,
    is_signer: bool,
    is_writable: bool,
}

struct CompiledInstruction {
    program_id_index: u8,
    account_indexes: Vec<u8>,
    data: Vec<u8>,
}

impl MessageBuilder {
    pub fn new(fee_payer: Pubkey, recent_blockhash: [u8; 32]) -> Self {
        Self {
            fee_payer,
            recent_blockhash,
            instructions: Vec::new(),
            version: MessageVersion::V0,
        }
    }

    pub fn legacy(mut self) -> Self {
        self.version = MessageVersion::Legacy;
        self
    }

    pub fn push(mut self, ix: Instruction) -> Self {
        self.instructions.push(ix);
        self
    }

    /// Compile account keys in canonical order and resolve instruction indexes.
    /// Mirrors solana-sdk's ordering: writable signers (fee payer first),
    /// readonly signers, writable non-signers, readonly non-signers.
    fn compile(&self) -> Result<(Vec<KeyEntry>, [u8; 3], Vec<CompiledInstruction>)> {
        // First-seen accumulation with OR-ed privilege bits.
        let mut entries: Vec<KeyEntry> = vec![KeyEntry {
            key: self.fee_payer,
            is_signer: true,
            is_writable: true,
        }];

        let upsert = |key: Pubkey, is_signer: bool, is_writable: bool, entries: &mut Vec<KeyEntry>| {
            if let Some(e) = entries.iter_mut().find(|e| e.key == key) {
                e.is_signer |= is_signer;
                e.is_writable |= is_writable;
            } else {
                entries.push(KeyEntry {
                    key,
                    is_signer,
                    is_writable,
                });
            }
        };

        for ix in &self.instructions {
            for meta in &ix.accounts {
                upsert(meta.pubkey, meta.is_signer, meta.is_writable, &mut entries);
            }
        }
        // Program ids are readonly, non-signer — added after accounts so a key
        // used as a real account keeps its stronger privileges.
        for ix in &self.instructions {
            upsert(ix.program_id, false, false, &mut entries);
        }

        // Stable ordering by (group, first-seen). Sort is stable so first-seen
        // order is preserved within each group.
        let group = |e: &KeyEntry| match (e.is_signer, e.is_writable) {
            (true, true) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (false, false) => 3,
        };
        // Keep fee payer pinned at index 0 by sorting the rest.
        let payer = entries.remove(0);
        entries.sort_by_key(group);
        entries.insert(0, payer);

        let num_signers = entries.iter().filter(|e| e.is_signer).count();
        let num_readonly_signed = entries.iter().filter(|e| e.is_signer && !e.is_writable).count();
        let num_readonly_unsigned =
            entries.iter().filter(|e| !e.is_signer && !e.is_writable).count();
        if num_signers > u8::MAX as usize || entries.len() > u8::MAX as usize {
            return Err(CoreError::Invalid("too many accounts for one message".into()));
        }
        let header = [
            num_signers as u8,
            num_readonly_signed as u8,
            num_readonly_unsigned as u8,
        ];

        let index_of = |key: &Pubkey| -> Result<u8> {
            entries
                .iter()
                .position(|e| &e.key == key)
                .map(|i| i as u8)
                .ok_or_else(|| CoreError::Invalid("account key not in key list".into()))
        };

        let mut compiled = Vec::with_capacity(self.instructions.len());
        for ix in &self.instructions {
            let program_id_index = index_of(&ix.program_id)?;
            let mut account_indexes = Vec::with_capacity(ix.accounts.len());
            for meta in &ix.accounts {
                account_indexes.push(index_of(&meta.pubkey)?);
            }
            compiled.push(CompiledInstruction {
                program_id_index,
                account_indexes,
                data: ix.data.clone(),
            });
        }

        Ok((entries, header, compiled))
    }

    /// Serialize the message bytes (no signatures).
    pub fn serialize_message(&self) -> Result<Vec<u8>> {
        let (entries, header, compiled) = self.compile()?;
        let mut out = Vec::new();

        if self.version == MessageVersion::V0 {
            out.push(0x80); // version prefix: 0x80 | 0
        }
        out.extend_from_slice(&header);

        shortvec::encode_len(&mut out, entries.len());
        for e in &entries {
            out.extend_from_slice(&e.key.0);
        }

        out.extend_from_slice(&self.recent_blockhash);

        shortvec::encode_len(&mut out, compiled.len());
        for ci in &compiled {
            out.push(ci.program_id_index);
            shortvec::encode_len(&mut out, ci.account_indexes.len());
            out.extend_from_slice(&ci.account_indexes);
            shortvec::encode_len(&mut out, ci.data.len());
            out.extend_from_slice(&ci.data);
        }

        if self.version == MessageVersion::V0 {
            // Address table lookups: none.
            shortvec::encode_len(&mut out, 0);
        }
        Ok(out)
    }

    /// Serialize the full **unsigned** transaction and base64-encode it. The
    /// signature array holds `num_required_signatures` all-zero slots.
    pub fn to_unsigned_base64(&self) -> Result<String> {
        let (_, header, _) = self.compile()?;
        let num_sigs = header[0] as usize;
        let message = self.serialize_message()?;
        let mut tx = Vec::with_capacity(1 + num_sigs * 64 + message.len());
        shortvec::encode_len(&mut tx, num_sigs);
        tx.extend(std::iter::repeat_n(0u8, num_sigs * 64));
        tx.extend_from_slice(&message);
        Ok(base64::encode(&tx))
    }

    /// The number of signatures a wallet must supply.
    pub fn required_signatures(&self) -> Result<u8> {
        Ok(self.compile()?.1[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::AccountMeta;
    use crate::pubkey::programs;

    fn ix_transfer(from: Pubkey, to: Pubkey) -> Instruction {
        Instruction {
            program_id: programs::system(),
            accounts: vec![AccountMeta::new(from, true), AccountMeta::new(to, false)],
            data: vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0], // transfer 1 lamport
        }
    }

    #[test]
    fn single_transfer_key_ordering_and_header() {
        let from = Pubkey([1u8; 32]);
        let to = Pubkey([2u8; 32]);
        let msg = MessageBuilder::new(from, [9u8; 32]).push(ix_transfer(from, to));
        let (entries, header, compiled) = msg.compile().unwrap();

        // Keys: [from(signer,writable), to(writable), system(readonly)]
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].key, from);
        assert_eq!(entries[1].key, to);
        assert_eq!(entries[2].key, programs::system());
        // header: 1 signer, 0 readonly-signed, 1 readonly-unsigned
        assert_eq!(header, [1, 0, 1]);
        // instruction references program at index 2, accounts [0,1]
        assert_eq!(compiled[0].program_id_index, 2);
        assert_eq!(compiled[0].account_indexes, vec![0, 1]);
    }

    #[test]
    fn v0_message_has_version_prefix_and_empty_alt() {
        let from = Pubkey([1u8; 32]);
        let to = Pubkey([2u8; 32]);
        let bytes = MessageBuilder::new(from, [0u8; 32])
            .push(ix_transfer(from, to))
            .serialize_message()
            .unwrap();
        assert_eq!(bytes[0], 0x80); // v0 prefix
        assert_eq!(*bytes.last().unwrap(), 0x00); // empty ALT list
    }

    #[test]
    fn legacy_message_has_no_prefix() {
        let from = Pubkey([1u8; 32]);
        let to = Pubkey([2u8; 32]);
        let bytes = MessageBuilder::new(from, [0u8; 32])
            .legacy()
            .push(ix_transfer(from, to))
            .serialize_message()
            .unwrap();
        // First byte is the header's num_required_signatures (1), not 0x80.
        assert_eq!(bytes[0], 1);
    }

    #[test]
    fn unsigned_tx_has_one_zero_signature_slot() {
        let from = Pubkey([1u8; 32]);
        let to = Pubkey([2u8; 32]);
        let b64 = MessageBuilder::new(from, [0u8; 32])
            .push(ix_transfer(from, to))
            .to_unsigned_base64()
            .unwrap();
        let raw = base64::decode(&b64).unwrap();
        // shortvec(1) = 0x01, then 64 zero bytes, then the message.
        assert_eq!(raw[0], 1);
        assert!(raw[1..65].iter().all(|&b| b == 0));
        assert_eq!(raw[65], 0x80); // message v0 prefix follows the signatures
    }

    #[test]
    fn duplicate_writable_signer_dedups_privileges() {
        // fee payer also appears as a plain account; keeps signer+writable.
        let payer = Pubkey([1u8; 32]);
        let to = Pubkey([2u8; 32]);
        let msg = MessageBuilder::new(payer, [0u8; 32]).push(Instruction {
            program_id: programs::system(),
            accounts: vec![
                AccountMeta::new(payer, false), // weaker here...
                AccountMeta::new(to, false),
            ],
            data: vec![],
        });
        let (entries, header, _) = msg.compile().unwrap();
        // payer still index 0, signer+writable; no duplicate key.
        assert_eq!(entries[0].key, payer);
        assert!(entries[0].is_signer && entries[0].is_writable);
        assert_eq!(entries.iter().filter(|e| e.key == payer).count(), 1);
        assert_eq!(header[0], 1);
    }
}
