//! Solana "shortvec" compact-u16 length encoding, used in serialized
//! transactions for account/instruction/signature counts.

/// Encode a u16 as compact-u16 (1..3 bytes, little-endian 7-bit groups).
pub fn encode_len(mut n: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(3);
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            return out;
        }
    }
}

/// Decode a compact-u16 from the front of `bytes`.
/// Returns `(value, bytes_consumed)` or `None` on malformed/overflowing input.
pub fn decode_len(bytes: &[u8]) -> Option<(u16, usize)> {
    let mut value: u32 = 0;
    for (i, &b) in bytes.iter().enumerate().take(3) {
        value |= ((b & 0x7f) as u32) << (7 * i);
        if b & 0x80 == 0 {
            if value > u16::MAX as u32 {
                return None;
            }
            return Some((value as u16, i + 1));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &[(u16, &[u8])] = &[
        (0x0000, &[0x00]),
        (0x0005, &[0x05]),
        (0x007f, &[0x7f]),
        (0x0080, &[0x80, 0x01]),
        (0x00ff, &[0xff, 0x01]),
        (0x0100, &[0x80, 0x02]),
        (0x7fff, &[0xff, 0xff, 0x01]),
        (0xffff, &[0xff, 0xff, 0x03]),
    ];

    #[test]
    fn golden_encode() {
        for (n, bytes) in VECTORS {
            assert_eq!(encode_len(*n), *bytes, "encode {n:#x}");
        }
    }

    #[test]
    fn golden_decode() {
        for (n, bytes) in VECTORS {
            assert_eq!(decode_len(bytes), Some((*n, bytes.len())), "decode {n:#x}");
        }
    }

    #[test]
    fn roundtrip_all_u16() {
        for n in [0u16, 1, 127, 128, 255, 256, 16383, 16384, 65535] {
            let e = encode_len(n);
            assert_eq!(decode_len(&e), Some((n, e.len())));
        }
    }

    #[test]
    fn malformed_fails_closed() {
        assert_eq!(decode_len(&[]), None);
        assert_eq!(decode_len(&[0x80]), None); // dangling continuation
        assert_eq!(decode_len(&[0x80, 0x80]), None);
        assert_eq!(decode_len(&[0xff, 0xff, 0x04]), None); // > u16::MAX
    }
}
