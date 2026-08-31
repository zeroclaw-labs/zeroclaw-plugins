//! Unsigned legacy Solana message: compile instructions into ordered account
//! keys + header, then serialize to the wire format (and base64).
//!
//! Wire layout (legacy message):
//! ```text
//!   header: num_required_signatures u8, num_readonly_signed u8, num_readonly_unsigned u8
//!   account_keys:   shortvec(len) + 32 bytes each
//!   recent_blockhash: 32 bytes (a durable nonce is placed here)
//!   instructions:   shortvec(len) + each {
//!       program_id_index: u8,
//!       accounts: shortvec(len) + u8 index each,
//!       data:     shortvec(len) + bytes
//!   }
//! ```
//! Account ordering follows Solana `CompiledKeys` (BTreeMap by pubkey, payer
//! forced first), so a serialized message here is byte-identical to one built
//! by solana-sdk for the same inputs.

use std::collections::BTreeMap;

use crate::memo::Instruction;
use crate::{b64, shortvec};

#[derive(Debug, PartialEq)]
pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

#[derive(Debug, PartialEq)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct Message {
    pub header: MessageHeader,
    pub account_keys: Vec<[u8; 32]>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
}

#[derive(Default, Clone, Copy)]
struct Meta {
    is_signer: bool,
    is_writable: bool,
}

impl Message {
    /// Compile instructions into a message. `payer` is the fee payer (forced to
    /// signer+writable and to account index 0). `recent_blockhash` is a real
    /// blockhash or a durable nonce value.
    pub fn compile(
        instructions: &[Instruction],
        payer: [u8; 32],
        recent_blockhash: [u8; 32],
    ) -> Self {
        let mut map: BTreeMap<[u8; 32], Meta> = BTreeMap::new();
        for ix in instructions {
            map.entry(ix.program_id).or_default(); // program id: non-signer, non-writable
            for am in &ix.accounts {
                let m = map.entry(am.pubkey).or_default();
                m.is_signer |= am.is_signer;
                m.is_writable |= am.is_writable;
            }
        }
        let m = map.entry(payer).or_default();
        m.is_signer = true;
        m.is_writable = true;

        // BTreeMap iterates sorted by pubkey; categorize into the four groups.
        let (mut ws, mut rs, mut wn, mut rn) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (k, meta) in &map {
            match (meta.is_signer, meta.is_writable) {
                (true, true) => ws.push(*k),
                (true, false) => rs.push(*k),
                (false, true) => wn.push(*k),
                (false, false) => rn.push(*k),
            }
        }
        let num_required_signatures = (ws.len() + rs.len()) as u8;
        let num_readonly_signed_accounts = rs.len() as u8;
        let num_readonly_unsigned_accounts = rn.len() as u8;

        // Payer to the front of the writable-signers.
        ws.retain(|k| k != &payer);
        let mut account_keys = Vec::with_capacity(1 + ws.len() + rs.len() + wn.len() + rn.len());
        account_keys.push(payer);
        account_keys.extend(ws);
        account_keys.extend(rs);
        account_keys.extend(wn);
        account_keys.extend(rn);

        let index_of = |pk: &[u8; 32]| account_keys.iter().position(|k| k == pk).unwrap() as u8;
        let compiled = instructions
            .iter()
            .map(|ix| CompiledInstruction {
                program_id_index: index_of(&ix.program_id),
                accounts: ix.accounts.iter().map(|am| index_of(&am.pubkey)).collect(),
                data: ix.data.clone(),
            })
            .collect();

        Message {
            header: MessageHeader {
                num_required_signatures,
                num_readonly_signed_accounts,
                num_readonly_unsigned_accounts,
            },
            account_keys,
            recent_blockhash,
            instructions: compiled,
        }
    }

    /// Serialize to the legacy message wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.header.num_required_signatures);
        out.push(self.header.num_readonly_signed_accounts);
        out.push(self.header.num_readonly_unsigned_accounts);
        out.extend(shortvec::encode_len(self.account_keys.len() as u16));
        for k in &self.account_keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&self.recent_blockhash);
        out.extend(shortvec::encode_len(self.instructions.len() as u16));
        for ci in &self.instructions {
            out.push(ci.program_id_index);
            out.extend(shortvec::encode_len(ci.accounts.len() as u16));
            out.extend_from_slice(&ci.accounts);
            out.extend(shortvec::encode_len(ci.data.len() as u16));
            out.extend_from_slice(&ci.data);
        }
        out
    }

    /// Serialize and base64-encode (the shape a wallet/signer consumes).
    pub fn to_base64(&self) -> String {
        b64::encode(&self.serialize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memo::AccountMeta;

    #[test]
    fn golden_minimal_message_bytes() {
        // One instruction: program P=[3;32], one writable non-signer account
        // A=[2;32], data [AA,BB]; payer Y=[1;32]; blockhash [9;32].
        // Each account category has ≤1 member, so ordering is unambiguous:
        // account_keys = [payer(1), writable-nonsigner(2), program(3)].
        let ix = Instruction {
            program_id: [3u8; 32],
            accounts: vec![AccountMeta {
                pubkey: [2u8; 32],
                is_signer: false,
                is_writable: true,
            }],
            data: vec![0xAA, 0xBB],
        };
        let msg = Message::compile(&[ix], [1u8; 32], [9u8; 32]);

        let mut expected = Vec::new();
        expected.extend_from_slice(&[1, 0, 1]); // header: 1 req sig, 0 ro-signed, 1 ro-unsigned
        expected.push(3); // shortvec: 3 account keys
        expected.extend_from_slice(&[1u8; 32]); // payer
        expected.extend_from_slice(&[2u8; 32]); // writable non-signer
        expected.extend_from_slice(&[3u8; 32]); // program (readonly non-signer)
        expected.extend_from_slice(&[9u8; 32]); // blockhash
        expected.push(1); // shortvec: 1 instruction
        expected.push(2); // program_id_index -> account_keys[2]
        expected.push(1); // shortvec: 1 account index
        expected.push(1); // account index -> account_keys[1]
        expected.push(2); // shortvec: data len 2
        expected.extend_from_slice(&[0xAA, 0xBB]);

        assert_eq!(msg.serialize(), expected);
        // base64 round-trips back to the same bytes.
        assert_eq!(b64::decode(&msg.to_base64()).unwrap(), expected);
    }

    #[test]
    fn payer_is_index_zero_and_is_the_only_signer() {
        let ix = Instruction {
            program_id: [7u8; 32],
            accounts: vec![AccountMeta {
                pubkey: [5u8; 32],
                is_signer: false,
                is_writable: false,
            }],
            data: vec![],
        };
        let payer = [1u8; 32];
        let msg = Message::compile(&[ix], payer, [0u8; 32]);
        assert_eq!(msg.account_keys[0], payer);
        assert_eq!(msg.header.num_required_signatures, 1);
    }

    #[test]
    fn compiled_indices_point_back_to_correct_keys() {
        // Two instructions sharing a program; verify every index resolves.
        let a = AccountMeta {
            pubkey: [10u8; 32],
            is_signer: true,
            is_writable: true,
        };
        let b = AccountMeta {
            pubkey: [20u8; 32],
            is_signer: false,
            is_writable: true,
        };
        let ix1 = Instruction {
            program_id: [30u8; 32],
            accounts: vec![a.clone(), b.clone()],
            data: vec![1],
        };
        let ix2 = Instruction {
            program_id: [30u8; 32],
            accounts: vec![b],
            data: vec![2],
        };
        let msg = Message::compile(&[ix1, ix2], [40u8; 32], [0u8; 32]);
        for (ci, orig) in msg.instructions.iter().zip([[30u8; 32], [30u8; 32]]) {
            assert_eq!(msg.account_keys[ci.program_id_index as usize], orig);
        }
        // ix1's first account index resolves to pubkey [10;32].
        let idx = msg.instructions[0].accounts[0] as usize;
        assert_eq!(msg.account_keys[idx], [10u8; 32]);
    }
}
