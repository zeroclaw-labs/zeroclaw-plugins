//! Wire-format primitives: compact-u16 ("short vec") and base64.

/// Append a compact-u16 (Solana "short vec" length prefix): 7 bits per byte,
/// little-endian, high bit = continuation. Test vectors from
/// `solana-sdk/short-vec` are in the unit tests.
pub fn push_compact_u16(n: u16, out: &mut Vec<u8>) {
    let mut rem = n;
    loop {
        let mut b = (rem & 0x7f) as u8;
        rem >>= 7;
        if rem == 0 {
            out.push(b);
            break;
        }
        b |= 0x80;
        out.push(b);
    }
}

/// Read a compact-u16, returning (value, bytes consumed). Fails on overflow
/// or truncation.
pub fn read_compact_u16(data: &[u8]) -> Option<(u16, usize)> {
    let mut value: u32 = 0;
    for (i, &b) in data.iter().enumerate().take(3) {
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

/// Standard base64 (with padding). Hand-rolled to keep the dependency tree at
/// zero; the alphabet is RFC 4648.
pub fn base64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
}

/// Decode standard base64 (padding required). Strict; returns None on any
/// invalid character or length.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        if pad > 2 || chunk[..4 - pad].iter().any(|&c| val(c).is_none()) {
            return None;
        }
        // '=' only allowed at the end of the chunk
        if chunk[..4 - pad].contains(&b'=') {
            return None;
        }
        let n = chunk[..4 - pad]
            .iter()
            .map(|&c| val(c).unwrap())
            .fold(0u32, |acc, v| (acc << 6) | v)
            << (6 * pad);
        let full = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&full[..3 - pad]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors from solana-sdk short-vec/src/lib.rs tests.
    #[test]
    fn compact_u16_vectors() {
        let cases: [(u16, &[u8]); 5] = [
            (0x0000, &[0x00]),
            (0x007f, &[0x7f]),
            (0x0080, &[0x80, 0x01]),
            (0x00ff, &[0xff, 0x01]),
            (0x7fff, &[0xff, 0xff, 0x01]),
        ];
        for (n, expect) in cases {
            let mut out = Vec::new();
            push_compact_u16(n, &mut out);
            assert_eq!(out, expect, "encode {n:#x}");
            assert_eq!(
                read_compact_u16(expect),
                Some((n, expect.len())),
                "decode {n:#x}"
            );
        }
    }

    #[test]
    fn compact_u16_truncated() {
        assert_eq!(read_compact_u16(&[0x80]), None);
    }

    #[test]
    fn base64_roundtrip() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(base64_decode(&base64_encode(data)).unwrap(), data);
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_rejects_garbage() {
        assert!(base64_decode("!!!!").is_none());
        assert!(base64_decode("abc").is_none());
        assert!(base64_decode("a=bc").is_none());
    }
}
