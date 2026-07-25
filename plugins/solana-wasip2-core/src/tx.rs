//! Unsigned Solana legacy transaction assembly — no `solana-sdk`, which does
//! not compile inside a `wasm32-wasip2` WIT component.
//!
//! Everything here is the wire format written out longhand: compact-u16
//! vectors, the 3-byte message header, and an all-zero signature slot so hosts
//! and wallets recognise the transaction as unsigned and require an approval
//! before it can go anywhere.
//!
//! **This module never signs and never sends.** It produces bytes for a human
//! or a host permission gate to approve. That is the property that makes it
//! safe to share between plugins, and it should not be relaxed.
//!
//! Generalised from `depin-attest`'s proven memo builder. `build_unsigned_tx`
//! is the general path; [`build_unsigned_memo_tx`] is the original special case
//! expressed in terms of it, and a test asserts the two produce **byte-identical**
//! output for the memo layout — the extraction is only correct if the proven
//! bytes are unchanged.

use crate::pubkey::{self, Pubkey};
use crate::shortvec;

/// SPL Memo v2 program id.
pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// The memo program's own data cap. Exceeding it is rejected here, with a clear
/// message, rather than after a human has already approved a doomed transaction.
pub const MEMO_MAX_BYTES: usize = 566;

/// The 3-byte legacy message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
}

/// One instruction, with accounts referenced by index into the message's key list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub program_id_index: u8,
    pub account_indices: Vec<u8>,
    pub data: Vec<u8>,
}

/// Serialize an unsigned legacy transaction.
///
/// Every index is validated against `account_keys` before a byte is written, so
/// a malformed instruction is an error rather than a transaction that is
/// accepted locally and rejected (or worse, misinterpreted) on chain.
pub fn build_unsigned_tx(
    header: MessageHeader,
    account_keys: &[Pubkey],
    recent_blockhash: &Pubkey,
    instructions: &[Instruction],
) -> Result<Vec<u8>, String> {
    if account_keys.is_empty() {
        return Err("transaction needs at least one account key".into());
    }
    let n_keys = account_keys.len();
    if n_keys > u16::MAX as usize {
        return Err(format!("{n_keys} account keys exceeds the compact-u16 limit"));
    }
    if header.num_required_signatures == 0 {
        return Err("a transaction with zero required signatures cannot be approved".into());
    }
    let signed = header.num_required_signatures as usize;
    if signed > n_keys {
        return Err(format!(
            "header requires {signed} signatures but only {n_keys} account keys are present"
        ));
    }
    if header.num_readonly_signed as usize > signed {
        return Err("more readonly-signed accounts than signed accounts".into());
    }
    if header.num_readonly_unsigned as usize > n_keys - signed {
        return Err("more readonly-unsigned accounts than unsigned accounts".into());
    }
    if instructions.is_empty() {
        return Err("refusing to build a transaction with no instructions".into());
    }
    if instructions.len() > u16::MAX as usize {
        return Err("too many instructions".into());
    }
    for (i, ix) in instructions.iter().enumerate() {
        if ix.program_id_index as usize >= n_keys {
            return Err(format!(
                "instruction {i}: program_id_index {} is out of range ({n_keys} keys)",
                ix.program_id_index
            ));
        }
        for &a in &ix.account_indices {
            if a as usize >= n_keys {
                return Err(format!(
                    "instruction {i}: account index {a} is out of range ({n_keys} keys)"
                ));
            }
        }
        if ix.account_indices.len() > u16::MAX as usize || ix.data.len() > u16::MAX as usize {
            return Err(format!("instruction {i}: field exceeds the compact-u16 limit"));
        }
    }

    let mut msg = Vec::with_capacity(3 + 3 + n_keys * 32 + 32 + 64 * instructions.len());
    msg.extend_from_slice(&[
        header.num_required_signatures,
        header.num_readonly_signed,
        header.num_readonly_unsigned,
    ]);
    shortvec::push(&mut msg, n_keys as u16);
    for k in account_keys {
        msg.extend_from_slice(k);
    }
    msg.extend_from_slice(recent_blockhash);
    shortvec::push(&mut msg, instructions.len() as u16);
    for ix in instructions {
        msg.push(ix.program_id_index);
        shortvec::push(&mut msg, ix.account_indices.len() as u16);
        msg.extend_from_slice(&ix.account_indices);
        shortvec::push(&mut msg, ix.data.len() as u16);
        msg.extend_from_slice(&ix.data);
    }

    // Transaction = compact-u16 signature count + that many zeroed slots + message.
    let sigs = header.num_required_signatures as usize;
    let mut tx = Vec::with_capacity(3 + 64 * sigs + msg.len());
    shortvec::push(&mut tx, sigs as u16);
    tx.extend(std::iter::repeat(0u8).take(64 * sigs));
    tx.extend_from_slice(&msg);
    Ok(tx)
}

/// Unsigned legacy transaction carrying a single attributable memo.
///
/// `fee_payer` is the one required signer *and* the account the memo program
/// lists, which is what makes the memo attributable — a verifier can see the
/// attestation could only have landed with that key's signature.
pub fn build_unsigned_memo_tx(
    fee_payer: &Pubkey,
    recent_blockhash: &Pubkey,
    memo: &[u8],
) -> Result<Vec<u8>, String> {
    if memo.is_empty() {
        return Err("refusing to build a transaction with an empty memo".into());
    }
    if memo.len() > MEMO_MAX_BYTES {
        return Err(format!(
            "memo is {} bytes; the memo program caps at {MEMO_MAX_BYTES}",
            memo.len()
        ));
    }
    let memo_program = pubkey::decode(MEMO_PROGRAM_ID)?;
    build_unsigned_tx(
        MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1,
        },
        &[*fee_payer, memo_program],
        recent_blockhash,
        &[Instruction {
            program_id_index: 1,
            account_indices: vec![0],
            data: memo.to_vec(),
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact layout assertion carried over from depin-attest. If this
    /// changes, the extraction has broken bytes that are already on mainnet.
    #[test]
    fn unsigned_memo_tx_layout_is_exact() {
        let payer = [7u8; 32];
        let hash = [9u8; 32];
        let tx = build_unsigned_memo_tx(&payer, &hash, b"hi").unwrap();
        assert_eq!(tx[0], 1);
        assert!(tx[1..65].iter().all(|&b| b == 0));
        assert_eq!(&tx[65..68], &[1, 0, 1]);
        assert_eq!(tx[68], 2);
        assert_eq!(&tx[69..101], &payer);
        assert_eq!(&tx[101..133], &pubkey::decode(MEMO_PROGRAM_ID).unwrap());
        assert_eq!(&tx[133..165], &hash);
        assert_eq!(&tx[165..], &[1, 1, 1, 0, 2, b'h', b'i']);
    }

    /// The whole point of the extraction: the general builder must reproduce
    /// the special case byte for byte.
    #[test]
    fn general_builder_matches_memo_special_case() {
        let payer = [3u8; 32];
        let hash = [4u8; 32];
        let memo = b"attestation #1";
        let special = build_unsigned_memo_tx(&payer, &hash, memo).unwrap();
        let general = build_unsigned_tx(
            MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed: 0,
                num_readonly_unsigned: 1,
            },
            &[payer, pubkey::decode(MEMO_PROGRAM_ID).unwrap()],
            &hash,
            &[Instruction {
                program_id_index: 1,
                account_indices: vec![0],
                data: memo.to_vec(),
            }],
        )
        .unwrap();
        assert_eq!(special, general);
    }

    #[test]
    fn oversized_and_empty_memos_fail_closed() {
        let payer = [1u8; 32];
        let hash = [2u8; 32];
        assert!(build_unsigned_memo_tx(&payer, &hash, &[]).is_err());
        assert!(build_unsigned_memo_tx(&payer, &hash, &vec![b'x'; MEMO_MAX_BYTES + 1]).is_err());
        assert!(build_unsigned_memo_tx(&payer, &hash, &vec![b'x'; MEMO_MAX_BYTES]).is_ok());
    }

    #[test]
    fn out_of_range_indices_are_rejected() {
        let h = MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1,
        };
        let keys = [[1u8; 32], [2u8; 32]];
        let hash = [0u8; 32];
        let bad_program = Instruction {
            program_id_index: 5,
            account_indices: vec![0],
            data: vec![1],
        };
        let bad_account = Instruction {
            program_id_index: 1,
            account_indices: vec![9],
            data: vec![1],
        };
        assert!(build_unsigned_tx(h, &keys, &hash, &[bad_program]).is_err());
        assert!(build_unsigned_tx(h, &keys, &hash, &[bad_account]).is_err());
    }

    #[test]
    fn inconsistent_headers_are_rejected() {
        let keys = [[1u8; 32]];
        let hash = [0u8; 32];
        let ix = Instruction {
            program_id_index: 0,
            account_indices: vec![0],
            data: vec![1],
        };
        // zero signatures — nothing could ever approve this
        assert!(build_unsigned_tx(
            MessageHeader { num_required_signatures: 0, num_readonly_signed: 0, num_readonly_unsigned: 0 },
            &keys, &hash, &[ix.clone()]
        )
        .is_err());
        // more signers than keys
        assert!(build_unsigned_tx(
            MessageHeader { num_required_signatures: 3, num_readonly_signed: 0, num_readonly_unsigned: 0 },
            &keys, &hash, &[ix.clone()]
        )
        .is_err());
        // readonly-signed exceeds signed
        assert!(build_unsigned_tx(
            MessageHeader { num_required_signatures: 1, num_readonly_signed: 2, num_readonly_unsigned: 0 },
            &keys, &hash, &[ix]
        )
        .is_err());
    }

    #[test]
    fn empty_instruction_list_is_rejected() {
        assert!(build_unsigned_tx(
            MessageHeader { num_required_signatures: 1, num_readonly_signed: 0, num_readonly_unsigned: 0 },
            &[[1u8; 32]], &[0u8; 32], &[]
        )
        .is_err());
    }

    #[test]
    fn multi_signature_slots_are_all_zeroed() {
        let keys = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let ix = Instruction { program_id_index: 2, account_indices: vec![0, 1], data: vec![9] };
        let tx = build_unsigned_tx(
            MessageHeader { num_required_signatures: 2, num_readonly_signed: 0, num_readonly_unsigned: 1 },
            &keys, &[5u8; 32], &[ix],
        )
        .unwrap();
        assert_eq!(tx[0], 2, "signature count");
        assert!(tx[1..129].iter().all(|&b| b == 0), "both slots zeroed");
    }
}
