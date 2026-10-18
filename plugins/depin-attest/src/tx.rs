//! Minimal Solana versioned (v0) transaction serializer. No `solana-sdk` —
//! just the wire format: `[u8 signature-count shortvec][0x80 version prefix]
//! [MessageV0]`. The transaction is built with zero signatures; a human signs
//! it out-of-band with a real wallet before it is ever submitted.

use crate::memo::{CompiledInstruction, MEMO_PROGRAM_ID};

pub struct UnsignedTx {
    /// Placeholder fee-payer pubkey; the signing wallet fills in the real one.
    pub fee_payer: [u8; 32],
    pub recent_blockhash: [u8; 32],
    pub instruction: CompiledInstruction,
}

/// Serialize a `compact-u16` (Solana's shortvec length prefix).
fn compact_u16(n: u16) -> Vec<u8> {
    let mut out = Vec::new();
    let mut val = n;
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if val == 0 {
            break;
        }
    }
    out
}

/// Serialize an [`UnsignedTx`] to the raw versioned-transaction byte format.
pub fn serialize(tx: &UnsignedTx) -> Vec<u8> {
    let mut msg = Vec::new();

    // MessageHeader: 0 required signatures, 0 readonly-signed, 1 readonly-unsigned
    // (the memo program account).
    msg.extend_from_slice(&[0u8, 0u8, 1u8]);

    // account_keys: [fee_payer(placeholder), memo_program]
    msg.extend(compact_u16(2));
    msg.extend_from_slice(&tx.fee_payer);
    msg.extend_from_slice(&MEMO_PROGRAM_ID);

    // recent_blockhash
    msg.extend_from_slice(&tx.recent_blockhash);

    // instructions (exactly one: the memo)
    msg.extend(compact_u16(1));
    msg.push(tx.instruction.program_id_index);
    msg.extend(compact_u16(tx.instruction.accounts.len() as u16));
    msg.extend_from_slice(&tx.instruction.accounts);
    msg.extend(compact_u16(tx.instruction.data.len() as u16));
    msg.extend_from_slice(&tx.instruction.data);

    // address_table_lookups (v0, none used here)
    msg.extend(compact_u16(0));

    // Wrap as versioned transaction: [signatures shortvec][version prefix][message]
    let mut out = Vec::new();
    out.extend(compact_u16(0)); // 0 signatures — nothing signed yet
    out.push(0x80); // version prefix: v0 message
    out.extend_from_slice(&msg);
    out
}

/// Standard base64 encoding (RFC 4648), no external dependency.
pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);

        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}
