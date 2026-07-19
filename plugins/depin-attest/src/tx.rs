//! Hand-rolled Solana legacy transaction construction — no solana-sdk, which
//! does not compile inside a wasm32-wasip2 WIT component (see README field
//! notes). Everything here is the wire format from the Solana docs, written
//! out longhand: compact-u16 vectors, the 3-byte message header, and an
//! all-zero signature slot so wallets recognize the transaction as unsigned.

use base64::Engine;
use sha2::{Digest, Sha256};

/// SPL Memo v2 program id.
pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// Decode a base58 pubkey, insisting on exactly 32 bytes.
pub fn decode_pubkey(s: &str) -> Result<[u8; 32], String> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| format!("'{s}' is not valid base58: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("'{s}' is not a 32-byte pubkey"))?;
    Ok(arr)
}

/// Solana compact-u16 ("shortvec") length encoding.
fn push_compact_u16(out: &mut Vec<u8>, mut n: u16) {
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

/// Serialize an unsigned legacy transaction carrying a single signed memo.
///
/// Layout: `fee_payer` is the one required signer and also the account the
/// memo program lists, which makes the memo *attributable* — verifiers see the
/// attestation could only have landed with the device key's signature.
/// The signature slot is all zeroes; whoever approves signs and submits.
pub fn build_unsigned_memo_tx(
    fee_payer: &[u8; 32],
    recent_blockhash: &[u8; 32],
    memo: &[u8],
) -> Result<Vec<u8>, String> {
    if memo.is_empty() {
        return Err("refusing to build a transaction with an empty memo".into());
    }
    if memo.len() > 566 {
        // Memo program's own limit; fail here with a clear message rather
        // than letting the chain reject the human-approved transaction.
        return Err(format!(
            "memo is {} bytes; the memo program caps at 566",
            memo.len()
        ));
    }
    let memo_program = decode_pubkey(MEMO_PROGRAM_ID)?;

    let mut msg = Vec::with_capacity(3 + 2 + 64 + 32 + 8 + memo.len());
    // Header: 1 required signature, 0 readonly signed, 1 readonly unsigned.
    msg.extend_from_slice(&[1, 0, 1]);
    // Account keys: [fee_payer (writable signer), memo program (readonly)].
    push_compact_u16(&mut msg, 2);
    msg.extend_from_slice(fee_payer);
    msg.extend_from_slice(&memo_program);
    // Recent blockhash.
    msg.extend_from_slice(recent_blockhash);
    // Instructions: one memo, program index 1, signing account index 0.
    push_compact_u16(&mut msg, 1);
    msg.push(1); // program id index
    push_compact_u16(&mut msg, 1);
    msg.push(0); // account index: the fee payer signs the memo
    push_compact_u16(&mut msg, memo.len() as u16);
    msg.extend_from_slice(memo);

    // Transaction = signatures (one, zeroed) + message.
    let mut tx = Vec::with_capacity(1 + 64 + msg.len());
    push_compact_u16(&mut tx, 1);
    tx.extend_from_slice(&[0u8; 64]);
    tx.extend_from_slice(&msg);
    Ok(tx)
}

pub fn to_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// First 8 bytes of sha256, hex — links attestation N to the on-chain
/// signature of attestation N-1 (tamper-evident chain, see att.rs).
pub fn short_hash_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_u16_matches_known_vectors() {
        // From the Solana shortvec spec.
        for (n, expect) in [
            (0u16, vec![0x00]),
            (5, vec![0x05]),
            (0x7f, vec![0x7f]),
            (0x80, vec![0x80, 0x01]),
            (0xff, vec![0xff, 0x01]),
            (0x100, vec![0x80, 0x02]),
            (0x3fff, vec![0xff, 0x7f]),
        ] {
            let mut out = Vec::new();
            push_compact_u16(&mut out, n);
            assert_eq!(out, expect, "encoding of {n}");
        }
    }

    #[test]
    fn unsigned_memo_tx_layout_is_exact() {
        let payer = [7u8; 32];
        let hash = [9u8; 32];
        let tx = build_unsigned_memo_tx(&payer, &hash, b"hi").unwrap();
        // 1 sig count + 64 zero sig
        assert_eq!(tx[0], 1);
        assert!(tx[1..65].iter().all(|&b| b == 0));
        // header
        assert_eq!(&tx[65..68], &[1, 0, 1]);
        // 2 accounts: payer then memo program
        assert_eq!(tx[68], 2);
        assert_eq!(&tx[69..101], &payer);
        assert_eq!(
            &tx[101..133],
            &decode_pubkey(MEMO_PROGRAM_ID).unwrap()
        );
        // blockhash
        assert_eq!(&tx[133..165], &hash);
        // 1 instruction: program idx 1, 1 account (idx 0), data "hi"
        assert_eq!(&tx[165..], &[1, 1, 1, 0, 2, b'h', b'i']);
    }

    #[test]
    fn oversized_memo_fails_closed() {
        let payer = [1u8; 32];
        let hash = [2u8; 32];
        let big = vec![b'x'; 567];
        assert!(build_unsigned_memo_tx(&payer, &hash, &big).is_err());
    }

    #[test]
    fn bad_pubkeys_are_rejected() {
        assert!(decode_pubkey("not-base58-0OIl").is_err());
        assert!(decode_pubkey("abc").is_err()); // too short
    }
}
