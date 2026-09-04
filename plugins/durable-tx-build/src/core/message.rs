//! Legacy Solana message construction, unsigned-transaction serialization,
//! and the reverse: parsing a base64 transaction back into instructions so
//! `approval-recheck` can verify what a pending transaction actually does.
//!
//! Wire layout (legacy):
//! ```text
//! transaction := shortvec<signature[64]> message
//! message     := header[3] shortvec<pubkey[32]> blockhash[32] shortvec<instruction>
//! instruction := program_id_index:u8 shortvec<account_index:u8> shortvec<data_byte>
//! ```

use crate::core::instruction::{AccountMeta, Instruction};
use crate::core::pubkey::Pubkey;

// --- compact-u16 ("shortvec") ---

pub fn shortvec_encode_len(out: &mut Vec<u8>, mut len: u16) {
    loop {
        let mut byte = (len & 0x7f) as u8;
        len >>= 7;
        if len != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
}

pub fn shortvec_decode_len(bytes: &[u8], cursor: &mut usize) -> Result<usize, String> {
    let mut len: usize = 0;
    for i in 0..3 {
        let byte = *bytes
            .get(*cursor)
            .ok_or("unexpected end of input while reading length")?;
        *cursor += 1;
        len |= ((byte & 0x7f) as usize) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(len);
        }
    }
    Err("malformed compact-u16 length".into())
}

// --- compile & serialize ---

struct KeyEntry {
    pubkey: Pubkey,
    is_signer: bool,
    is_writable: bool,
}

/// Compile instructions into a serialized legacy message. `fee_payer` is
/// forced into slot 0 as a writable signer; account ordering follows the
/// runtime's requirement: writable signers, readonly signers, writable
/// non-signers, readonly non-signers.
pub fn compile_message(
    fee_payer: &Pubkey,
    instructions: &[Instruction],
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
    let mut entries: Vec<KeyEntry> = vec![KeyEntry {
        pubkey: *fee_payer,
        is_signer: true,
        is_writable: true,
    }];

    let mut upsert = |meta: &AccountMeta| {
        if let Some(e) = entries.iter_mut().find(|e| e.pubkey == meta.pubkey) {
            e.is_signer |= meta.is_signer;
            e.is_writable |= meta.is_writable;
        } else {
            entries.push(KeyEntry {
                pubkey: meta.pubkey,
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
            });
        }
    };

    for ix in instructions {
        for meta in &ix.accounts {
            upsert(meta);
        }
        upsert(&AccountMeta::readonly(ix.program_id));
    }

    // Stable partition into the four runtime-mandated groups. The fee payer
    // sorts first inside the first group because it was inserted first.
    let mut ordered: Vec<&KeyEntry> = Vec::with_capacity(entries.len());
    for (want_signer, want_writable) in [(true, true), (true, false), (false, true), (false, false)]
    {
        ordered.extend(
            entries
                .iter()
                .filter(|e| e.is_signer == want_signer && e.is_writable == want_writable),
        );
    }

    let index_of = |pk: &Pubkey| -> u8 {
        ordered
            .iter()
            .position(|e| e.pubkey == *pk)
            .expect("all keys were collected") as u8
    };

    let num_required_signatures = ordered.iter().filter(|e| e.is_signer).count() as u8;
    let num_readonly_signed = ordered
        .iter()
        .filter(|e| e.is_signer && !e.is_writable)
        .count() as u8;
    let num_readonly_unsigned = ordered
        .iter()
        .filter(|e| !e.is_signer && !e.is_writable)
        .count() as u8;

    let mut out = Vec::with_capacity(256);
    out.push(num_required_signatures);
    out.push(num_readonly_signed);
    out.push(num_readonly_unsigned);
    shortvec_encode_len(&mut out, ordered.len() as u16);
    for e in &ordered {
        out.extend_from_slice(&e.pubkey.0);
    }
    out.extend_from_slice(recent_blockhash);
    shortvec_encode_len(&mut out, instructions.len() as u16);
    for ix in instructions {
        out.push(index_of(&ix.program_id));
        shortvec_encode_len(&mut out, ix.accounts.len() as u16);
        for meta in &ix.accounts {
            out.push(index_of(&meta.pubkey));
        }
        shortvec_encode_len(&mut out, ix.data.len() as u16);
        out.extend_from_slice(&ix.data);
    }
    out
}

/// Wrap a serialized message as a full transaction with zeroed signature
/// placeholders — the standard shape wallets and `solana transfer --sign-only`
/// tooling accept for offline signing.
pub fn serialize_unsigned_transaction(message: &[u8]) -> Vec<u8> {
    let num_signatures = *message.first().expect("message is never empty");
    let mut out = Vec::with_capacity(1 + num_signatures as usize * 64 + message.len());
    shortvec_encode_len(&mut out, num_signatures as u16);
    out.extend(std::iter::repeat_n(0u8, num_signatures as usize * 64));
    out.extend_from_slice(message);
    out
}

// --- parse (for approval-recheck) ---

#[derive(Debug)]
pub struct ParsedInstruction {
    pub program: Pubkey,
    pub account_indices: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct ParsedMessage {
    pub num_required_signatures: u8,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<ParsedInstruction>,
}

impl ParsedMessage {
    pub fn account(&self, ix: &ParsedInstruction, position: usize) -> Option<&Pubkey> {
        ix.account_indices
            .get(position)
            .and_then(|&i| self.account_keys.get(i as usize))
    }
}

pub fn parse_transaction(bytes: &[u8]) -> Result<ParsedMessage, String> {
    let mut cursor = 0usize;
    let sig_count = shortvec_decode_len(bytes, &mut cursor)?;
    cursor = cursor
        .checked_add(sig_count * 64)
        .filter(|&c| c <= bytes.len())
        .ok_or("transaction truncated inside signatures")?;
    parse_message(&bytes[cursor..])
}

pub fn parse_message(bytes: &[u8]) -> Result<ParsedMessage, String> {
    let mut cursor = 0usize;
    let take = |bytes: &[u8], cursor: &mut usize, n: usize| -> Result<Vec<u8>, String> {
        let end = cursor
            .checked_add(n)
            .filter(|&e| e <= bytes.len())
            .ok_or("message truncated")?;
        let out = bytes[*cursor..end].to_vec();
        *cursor = end;
        Ok(out)
    };

    let header = take(bytes, &mut cursor, 3)?;
    if header[0] & 0x80 != 0 {
        return Err(
            "versioned transaction detected; this suite builds and verifies legacy messages only"
                .into(),
        );
    }
    let key_count = shortvec_decode_len(bytes, &mut cursor)?;
    let mut account_keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let k = take(bytes, &mut cursor, 32)?;
        account_keys.push(Pubkey(k.try_into().expect("exactly 32 bytes")));
    }
    let blockhash: [u8; 32] = take(bytes, &mut cursor, 32)?
        .try_into()
        .expect("exactly 32 bytes");

    let ix_count = shortvec_decode_len(bytes, &mut cursor)?;
    let mut instructions = Vec::with_capacity(ix_count);
    for _ in 0..ix_count {
        let program_index = take(bytes, &mut cursor, 1)?[0] as usize;
        let program = *account_keys
            .get(program_index)
            .ok_or("instruction references a missing program key")?;
        let acct_count = shortvec_decode_len(bytes, &mut cursor)?;
        let account_indices = take(bytes, &mut cursor, acct_count)?;
        for &i in &account_indices {
            if i as usize >= account_keys.len() {
                return Err("instruction references a missing account key".into());
            }
        }
        let data_len = shortvec_decode_len(bytes, &mut cursor)?;
        let data = take(bytes, &mut cursor, data_len)?;
        instructions.push(ParsedInstruction {
            program,
            account_indices,
            data,
        });
    }

    Ok(ParsedMessage {
        num_required_signatures: header[0],
        account_keys,
        recent_blockhash: blockhash,
        instructions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::instruction::{advance_nonce_account, system_transfer};
    use crate::core::pubkey::{system_program, sysvar_recent_blockhashes};

    fn pk(n: u8) -> Pubkey {
        let mut b = [0u8; 32];
        b[0] = n;
        b[31] = n;
        Pubkey(b)
    }

    #[test]
    fn shortvec_vectors() {
        // Vectors from the Solana shortvec documentation.
        for (len, expected) in [
            (0u16, vec![0x00]),
            (5, vec![0x05]),
            (0x7f, vec![0x7f]),
            (0x80, vec![0x80, 0x01]),
            (0xff, vec![0xff, 0x01]),
            (0x100, vec![0x80, 0x02]),
            (0x7fff, vec![0xff, 0xff, 0x01]),
        ] {
            let mut out = Vec::new();
            shortvec_encode_len(&mut out, len);
            assert_eq!(out, expected, "encoding {len}");
            let mut cursor = 0;
            assert_eq!(
                shortvec_decode_len(&out, &mut cursor).unwrap(),
                len as usize
            );
            assert_eq!(cursor, expected.len());
        }
    }

    #[test]
    fn minimal_transfer_message_is_byte_exact() {
        let from = pk(1);
        let to = pk(2);
        let blockhash = [9u8; 32];
        let msg = compile_message(&from, &[system_transfer(&from, &to, 1)], &blockhash);

        let mut expected = vec![
            1, // one required signature (fee payer = sender)
            0, // no readonly signed
            1, // system program is readonly unsigned
            3, // three account keys
        ];
        expected.extend_from_slice(&from.0);
        expected.extend_from_slice(&to.0);
        expected.extend_from_slice(&system_program().0);
        expected.extend_from_slice(&blockhash);
        expected.push(1); // one instruction
        expected.push(2); // program id index (system program)
        expected.push(2); // two account indices
        expected.extend_from_slice(&[0, 1]); // from, to
        expected.push(12); // data length
        expected.extend_from_slice(&[2, 0, 0, 0]); // Transfer discriminant
        expected.extend_from_slice(&1u64.to_le_bytes());

        assert_eq!(msg, expected);
    }

    #[test]
    fn unsigned_transaction_has_zeroed_signature_slots() {
        let from = pk(1);
        let msg = compile_message(&from, &[system_transfer(&from, &pk(2), 7)], &[0u8; 32]);
        let tx = serialize_unsigned_transaction(&msg);
        assert_eq!(tx[0], 1); // one signature slot
        assert!(tx[1..65].iter().all(|&b| b == 0));
        assert_eq!(&tx[65..], &msg[..]);
    }

    #[test]
    fn compile_then_parse_roundtrip() {
        let authority = pk(1);
        let nonce = pk(3);
        let recipient = pk(2);
        let blockhash = [7u8; 32];
        let ixs = vec![
            advance_nonce_account(&nonce, &authority),
            system_transfer(&authority, &recipient, 42),
        ];
        let msg = compile_message(&authority, &ixs, &blockhash);
        let tx = serialize_unsigned_transaction(&msg);
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.num_required_signatures, 1);
        assert_eq!(parsed.recent_blockhash, blockhash);
        assert_eq!(parsed.instructions.len(), 2);

        let adv = &parsed.instructions[0];
        assert_eq!(adv.program, system_program());
        assert_eq!(adv.data, vec![4, 0, 0, 0]);
        assert_eq!(parsed.account(adv, 0), Some(&nonce));
        assert_eq!(parsed.account(adv, 1), Some(&sysvar_recent_blockhashes()));
        assert_eq!(parsed.account(adv, 2), Some(&authority));

        let tr = &parsed.instructions[1];
        assert_eq!(&tr.data[..4], &[2, 0, 0, 0]);
        assert_eq!(u64::from_le_bytes(tr.data[4..12].try_into().unwrap()), 42);
        assert_eq!(parsed.account(tr, 0), Some(&authority));
        assert_eq!(parsed.account(tr, 1), Some(&recipient));
    }

    #[test]
    fn parser_rejects_versioned_and_truncated_input() {
        assert!(parse_message(&[0x80, 0, 0, 0]).is_err());
        assert!(parse_transaction(&[1, 0, 0]).is_err());
        assert!(parse_message(&[1, 0, 1, 5, 1, 2]).is_err());
    }
}
