//! Solana's `compact-u16` ("shortvec") length prefix.
//!
//! Every array in a transaction/message (account keys, instructions, signatures)
//! is prefixed with its length in this format: a little-endian base-128 varint
//! capped at three bytes, because the value it encodes never exceeds `u16::MAX`.
//! This is the single encoding detail that trips up hand-rolled transaction
//! builders, so it lives alone, with tests against the canonical boundaries.

use crate::error::CoreError;

/// Append the compact-u16 encoding of `len` to `out`.
pub fn encode_len(out: &mut Vec<u8>, len: usize) {
    debug_assert!(len <= u16::MAX as usize, "shortvec length exceeds u16");
    let mut rem = len as u16;
    loop {
        let mut byte = (rem & 0x7f) as u8;
        rem >>= 7;
        if rem == 0 {
            out.push(byte);
            break;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

/// Read a compact-u16 from `data` starting at `*pos`, advancing `*pos`.
pub fn decode_len(data: &[u8], pos: &mut usize) -> Result<usize, CoreError> {
    let mut value: usize = 0;
    let mut shift = 0;
    loop {
        let byte = *data
            .get(*pos)
            .ok_or_else(|| CoreError::Layout("shortvec: unexpected end".into()))?;
        *pos += 1;
        value |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 14 {
            return Err(CoreError::Layout("shortvec: too long for u16".into()));
        }
    }
    Ok(value)
}

/// Convenience: the encoding as a fresh `Vec`.
pub fn encoded_len(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(3);
    encode_len(&mut v, len);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_encodings() {
        assert_eq!(encoded_len(0), vec![0x00]);
        assert_eq!(encoded_len(1), vec![0x01]);
        assert_eq!(encoded_len(127), vec![0x7f]);
        assert_eq!(encoded_len(128), vec![0x80, 0x01]);
        assert_eq!(encoded_len(16383), vec![0xff, 0x7f]);
        assert_eq!(encoded_len(16384), vec![0x80, 0x80, 0x01]);
        assert_eq!(encoded_len(65535), vec![0xff, 0xff, 0x03]);
    }

    #[test]
    fn roundtrip_all_boundaries() {
        for &n in &[0usize, 1, 127, 128, 255, 16383, 16384, 65535] {
            let enc = encoded_len(n);
            let mut pos = 0;
            assert_eq!(decode_len(&enc, &mut pos).unwrap(), n);
            assert_eq!(pos, enc.len());
        }
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(decode_len(&[0x80], &mut 0).is_err());
    }
}
