//! Legacy message compilation + unsigned transaction serialization.
//!
//! Produces the exact wire bytes `solana_sdk::Message::new_with_blockhash`
//! would, without the SDK: accounts deduped and ordered
//! (writable-signers, readonly-signers, writable-non-signers,
//! readonly-non-signers), compact-u16 arrays, and an all-zero signature
//! placeholder block so wallets/hosts can sign the returned base64 directly.

use crate::encoding::{b64_encode, encode_compact_u16};
use crate::instruction::Instruction;
use crate::pubkey::Pubkey;

/// A compiled legacy message ready for wire serialization.
pub struct Message {
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    /// (program_id_index, account_indices, data)
    pub instructions: Vec<(u8, Vec<u8>, Vec<u8>)>,
}

/// Compile instructions into a legacy message. `payer` is forced to index 0.
/// `recent_blockhash` is either a live blockhash or, for durable-nonce
/// transactions, the nonce account's stored value (with AdvanceNonceAccount
/// as the first instruction).
pub fn compile_message(
    payer: Pubkey,
    instructions: &[Instruction],
    recent_blockhash: [u8; 32],
) -> Result<Message, String> {
    if instructions.is_empty() {
        return Err("no instructions".into());
    }

    // Gather (key, is_signer, is_writable), merging duplicates with OR.
    let mut metas: Vec<(Pubkey, bool, bool)> = vec![(payer, true, true)];
    let mut upsert = |key: Pubkey, signer: bool, writable: bool| {
        if let Some(m) = metas.iter_mut().find(|m| m.0 == key) {
            m.1 |= signer;
            m.2 |= writable;
        } else {
            metas.push((key, signer, writable));
        }
    };
    for ix in instructions {
        upsert(ix.program_id, false, false);
        for a in &ix.accounts {
            upsert(a.pubkey, a.is_signer, a.is_writable);
        }
    }

    // Order: writable signers, readonly signers, writable non-signers,
    // readonly non-signers. Payer stays first (it is a writable signer and
    // sort_by_key is stable).
    let mut ordered = metas.clone();
    ordered.sort_by_key(|(_, signer, writable)| match (signer, writable) {
        (true, true) => 0u8,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    });

    let num_required_signatures = ordered.iter().filter(|m| m.1).count() as u8;
    let num_readonly_signed = ordered.iter().filter(|m| m.1 && !m.2).count() as u8;
    let num_readonly_unsigned = ordered.iter().filter(|m| !m.1 && !m.2).count() as u8;
    let account_keys: Vec<Pubkey> = ordered.iter().map(|m| m.0).collect();

    let index_of = |key: &Pubkey| -> Result<u8, String> {
        account_keys
            .iter()
            .position(|k| k == key)
            .map(|i| i as u8)
            .ok_or_else(|| "account not in message".to_string())
    };

    let mut compiled = Vec::new();
    for ix in instructions {
        let prog = index_of(&ix.program_id)?;
        let accounts = ix
            .accounts
            .iter()
            .map(|a| index_of(&a.pubkey))
            .collect::<Result<Vec<u8>, _>>()?;
        compiled.push((prog, accounts, ix.data.clone()));
    }

    Ok(Message {
        num_required_signatures,
        num_readonly_signed,
        num_readonly_unsigned,
        account_keys,
        recent_blockhash,
        instructions: compiled,
    })
}

/// Serialize the message body (the bytes that get signed).
pub fn serialize_message(msg: &Message) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.push(msg.num_required_signatures);
    out.push(msg.num_readonly_signed);
    out.push(msg.num_readonly_unsigned);
    encode_compact_u16(msg.account_keys.len() as u16, &mut out);
    for key in &msg.account_keys {
        out.extend_from_slice(&key.0);
    }
    out.extend_from_slice(&msg.recent_blockhash);
    encode_compact_u16(msg.instructions.len() as u16, &mut out);
    for (prog, accounts, data) in &msg.instructions {
        out.push(*prog);
        encode_compact_u16(accounts.len() as u16, &mut out);
        out.extend_from_slice(accounts);
        encode_compact_u16(data.len() as u16, &mut out);
        out.extend_from_slice(data);
    }
    out
}

/// Full unsigned transaction: compact-u16 signature count + zeroed signatures
/// + message body, base64-encoded — importable by Phantom/Squads/solana CLI.
pub fn unsigned_transaction_base64(msg: &Message) -> String {
    let mut out = Vec::with_capacity(1 + 64 * msg.num_required_signatures as usize + 256);
    encode_compact_u16(msg.num_required_signatures as u16, &mut out);
    out.extend(std::iter::repeat_n(
        0u8,
        64 * msg.num_required_signatures as usize,
    ));
    out.extend_from_slice(&serialize_message(msg));
    b64_encode(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::{advance_nonce_account, system_transfer};
    use crate::pubkey::program_ids;

    fn key(n: u8) -> Pubkey {
        let mut b = [0u8; 32];
        b[0] = n;
        b[31] = n;
        Pubkey(b)
    }

    #[test]
    fn payer_is_first_and_counts_are_right() {
        let payer = key(1);
        let to = key(2);
        let msg = compile_message(payer, &[system_transfer(payer, to, 100)], [7u8; 32]).unwrap();
        assert_eq!(msg.account_keys[0], payer);
        assert_eq!(msg.num_required_signatures, 1);
        assert_eq!(msg.num_readonly_signed, 0);
        // system program is the only readonly unsigned key
        assert_eq!(msg.num_readonly_unsigned, 1);
        assert_eq!(msg.account_keys.len(), 3);
    }

    #[test]
    fn nonce_tx_puts_advance_first() {
        let payer = key(1);
        let nonce_acct = key(3);
        let to = key(2);
        let ixs = [
            advance_nonce_account(nonce_acct, payer),
            system_transfer(payer, to, 100),
        ];
        let msg = compile_message(payer, &ixs, [9u8; 32]).unwrap();
        // First compiled instruction is AdvanceNonceAccount (data [4,0,0,0]).
        assert_eq!(msg.instructions[0].2, vec![4, 0, 0, 0]);
        // Nonce account is writable non-signer; payer authority signs.
        assert_eq!(msg.num_required_signatures, 1);
    }

    #[test]
    fn wire_bytes_shape() {
        let payer = key(1);
        let to = key(2);
        let msg = compile_message(payer, &[system_transfer(payer, to, 5)], [0u8; 32]).unwrap();
        let bytes = serialize_message(&msg);
        // header(3) + veclen(1) + 3*32 keys + 32 blockhash + ixs...
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[3], 3); // 3 account keys, compact-u16 single byte
        assert_eq!(&bytes[4..36], &payer.0);

        let b64 = unsigned_transaction_base64(&msg);
        let raw = crate::encoding::b64_decode(&b64).unwrap();
        // 1 sig slot: compact len 1 + 64 zero bytes + message
        assert_eq!(raw[0], 1);
        assert!(raw[1..65].iter().all(|b| *b == 0));
        assert_eq!(&raw[65..], &bytes[..]);
    }

    #[test]
    fn dedupes_accounts() {
        let payer = key(1);
        let msg = compile_message(
            payer,
            &[
                system_transfer(payer, key(2), 1),
                system_transfer(payer, key(2), 2),
            ],
            [0u8; 32],
        )
        .unwrap();
        assert_eq!(msg.account_keys.len(), 3); // payer, key2, system — deduped
        let _ = program_ids::SYSTEM;
    }
}
