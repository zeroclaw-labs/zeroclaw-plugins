//! Pure v0 (versioned) message serialization for Solana transactions.
//!
//! No wasm dependency, no I/O, no `solana-*` crates: this module owns minimal
//! plain types and a hand-rolled encoder so it compiles for `wasm32-wasip2`
//! (where the standard Solana transaction stack does not) and tests on the host
//! with `cargo test`. `#![forbid(unsafe_code)]` is enforced crate-wide.
//!
//! Byte-for-byte equivalence with the official `solana-message` serializer is a
//! regression test, not an aspiration: see `tests/encode_differential.rs`, which
//! compiles the same real Jupiter route with the Anza crates and asserts equal
//! bytes. The encoder was validated against a live mainnet route (246-address
//! ALT compressed to 9 static keys + 1 lookup, 505 bytes exact) before this
//! module existed.

#![forbid(unsafe_code)]

/// A 32-byte account address. We keep our own alias so the wasm build carries no
/// `solana-pubkey` dependency; base58 <-> bytes conversion lives in `crate::b58`.
pub type Pubkey = [u8; 32];

/// The three counts at the head of a compiled message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

/// An instruction after account addresses have been replaced by indices into the
/// message's combined (static + looked-up) address list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledInstruction {
    /// Index of the program id in the static account keys.
    pub program_id_index: u8,
    /// Indices (into the combined address list) of the instruction's accounts.
    pub accounts: Vec<u8>,
    /// Opaque instruction data.
    pub data: Vec<u8>,
}

/// A reference to addresses loaded from one on-chain address lookup table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAddressTableLookup {
    pub account_key: Pubkey,
    /// Indices into the table of the writable addresses this message loads.
    pub writable_indexes: Vec<u8>,
    /// Indices into the table of the read-only addresses this message loads.
    pub readonly_indexes: Vec<u8>,
}

/// A compiled v0 message, ready to serialize into the bytes a signer signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V0Message {
    pub header: MessageHeader,
    /// Addresses that appear directly in the message (signers first).
    pub static_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
    pub address_table_lookups: Vec<MessageAddressTableLookup>,
}

/// Solana `short_vec` / compact-u16: 1-3 bytes, 7 data bits each, high bit is a
/// continuation flag. Values above `u16::MAX` cannot occur in a valid message
/// (account/instruction counts are bounded well below that), so a `u16` domain
/// is exact. Proven roundtrip in `crate::proofs` (P6).
pub fn write_compact_u16(out: &mut Vec<u8>, mut v: u16) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

/// Decode a compact-u16 from `bytes` starting at `pos`, returning the value and
/// the number of bytes consumed. Rejects overlong encodings (a value that fits
/// in fewer bytes must not be padded) and truncated input.
pub fn read_compact_u16(bytes: &[u8], pos: usize) -> Result<(u16, usize), &'static str> {
    let mut value: u32 = 0;
    let mut consumed = 0usize;
    loop {
        let byte = *bytes.get(pos + consumed).ok_or("compact-u16: truncated")?;
        let has_more = byte & 0x80 != 0;
        let bits = (byte & 0x7f) as u32;
        value |= bits << (7 * consumed);
        consumed += 1;
        if !has_more {
            // reject overlong: the final group must be non-zero unless it's the
            // only group, and the value must fit in u16.
            if consumed > 1 && bits == 0 {
                return Err("compact-u16: overlong encoding");
            }
            if value > u16::MAX as u32 {
                return Err("compact-u16: exceeds u16");
            }
            return Ok((value as u16, consumed));
        }
        if consumed == 3 {
            return Err("compact-u16: too long");
        }
    }
}

/// Serialize a compiled v0 message into the exact bytes a signer signs.
///
/// Layout (Solana v0): `0x80` version prefix, 3-byte header, compact array of
/// static keys, 32-byte recent blockhash, compact array of compiled
/// instructions, compact array of address-table lookups. Byte-identical to
/// `solana_message::VersionedMessage::V0(_).serialize()` (regression-tested).
pub fn serialize_v0(msg: &V0Message) -> Vec<u8> {
    // Version prefix (high bit set marks a versioned message; low 7 bits = 0)
    // followed by the 3-byte header.
    let mut out = vec![
        0x80,
        msg.header.num_required_signatures,
        msg.header.num_readonly_signed_accounts,
        msg.header.num_readonly_unsigned_accounts,
    ];

    write_compact_u16(&mut out, msg.static_keys.len() as u16);
    for k in &msg.static_keys {
        out.extend_from_slice(k);
    }

    out.extend_from_slice(&msg.recent_blockhash);

    write_compact_u16(&mut out, msg.instructions.len() as u16);
    for ix in &msg.instructions {
        out.push(ix.program_id_index);
        write_compact_u16(&mut out, ix.accounts.len() as u16);
        out.extend_from_slice(&ix.accounts);
        write_compact_u16(&mut out, ix.data.len() as u16);
        out.extend_from_slice(&ix.data);
    }

    write_compact_u16(&mut out, msg.address_table_lookups.len() as u16);
    for lut in &msg.address_table_lookups {
        out.extend_from_slice(&lut.account_key);
        write_compact_u16(&mut out, lut.writable_indexes.len() as u16);
        out.extend_from_slice(&lut.writable_indexes);
        write_compact_u16(&mut out, lut.readonly_indexes.len() as u16);
        out.extend_from_slice(&lut.readonly_indexes);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_u16_roundtrip_boundaries() {
        for v in [0u16, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0xffff] {
            let mut buf = Vec::new();
            write_compact_u16(&mut buf, v);
            let (got, n) = read_compact_u16(&buf, 0).unwrap();
            assert_eq!(got, v);
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn compact_u16_rejects_overlong() {
        // 0x80 0x00 encodes 0 in two bytes: overlong, must be rejected.
        assert!(read_compact_u16(&[0x80, 0x00], 0).is_err());
    }
}
