//! Standard base64 (RFC 4648, `+/` alphabet, `=` padding), hand-rolled.
//!
//! Needed on two paths: decoding account data the RPC returns as
//! `["<base64>", "base64"]`, and encoding the unsigned transaction we hand back
//! to the approval gate. Kept dependency-free for the same reason as base58.

use crate::error::CoreError;

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard base64 with `=` padding.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard base64. Tolerates missing padding but not stray characters
/// (other than trailing `=`), which keeps RPC payload decoding strict.
pub fn decode(input: &str) -> Result<Vec<u8>, CoreError> {
    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        let mut valid = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = value(c).ok_or_else(|| {
                CoreError::Base64(format!("bad char '{}'", c as char))
            })?;
            n |= v << (18 - 6 * i);
            valid += 1;
        }
        if valid >= 2 {
            out.push((n >> 16) as u8);
        }
        if valid >= 3 {
            out.push((n >> 8) as u8);
        }
        if valid >= 4 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (bytes, s) in cases {
            assert_eq!(&encode(bytes), s);
            assert_eq!(&decode(s).unwrap(), bytes);
        }
    }

    #[test]
    fn roundtrip_binary() {
        let data: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode(&encode(&data)).unwrap(), data);
    }

    #[test]
    fn rejects_bad_char() {
        assert!(decode("Zm9v*g==").is_err());
    }
}
