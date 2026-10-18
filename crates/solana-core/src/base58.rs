//! Base58 (Bitcoin/Solana alphabet), hand-rolled.
//!
//! `solana-sdk` pulls in `bs58` transitively, but we want the core to have a
//! minimal, auditable dependency surface — a reviewer can read this file in one
//! sitting. The algorithm is the standard "big-integer in base 256 → base 58"
//! long-division, with leading zero bytes preserved as leading `1`s.

use crate::error::CoreError;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Reverse lookup table: ASCII byte -> base58 digit value, or 0xFF if the byte
/// is not part of the alphabet. Built at first use.
fn decode_table() -> [u8; 128] {
    let mut table = [0xFFu8; 128];
    let mut i = 0usize;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
}

/// Encode bytes to a base58 string.
pub fn encode(input: &[u8]) -> String {
    // Count leading zeros; each maps to a leading '1'.
    let zeros = input.iter().take_while(|&&b| b == 0).count();

    // Base-256 -> base-58 by repeated division. `digits` holds base58 values,
    // least-significant first.
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 2);
    for &byte in &input[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    if out.is_empty() {
        out.push('1');
    }
    out
}

/// Decode a base58 string to bytes.
pub fn decode(input: &str) -> Result<Vec<u8>, CoreError> {
    if input.is_empty() {
        return Err(CoreError::Base58("empty string".into()));
    }
    let table = decode_table();
    let bytes = input.as_bytes();
    let zeros = bytes.iter().take_while(|&&b| b == b'1').count();

    // base-58 -> base-256 by repeated multiply-add.
    let mut result: Vec<u8> = Vec::with_capacity(input.len());
    for &c in &bytes[zeros..] {
        if c >= 128 {
            return Err(CoreError::Base58(format!("non-ascii byte 0x{c:02x}")));
        }
        let val = table[c as usize];
        if val == 0xFF {
            return Err(CoreError::Base58(format!("bad char '{}'", c as char)));
        }
        let mut carry = val as u32;
        for b in result.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            result.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = Vec::with_capacity(zeros + result.len());
    out.extend(std::iter::repeat_n(0u8, zeros));
    out.extend(result.iter().rev());
    Ok(out)
}

/// Decode and require exactly 32 bytes (a pubkey / hash).
pub fn decode_32(input: &str) -> Result<[u8; 32], CoreError> {
    let v = decode(input)?;
    if v.len() != 32 {
        return Err(CoreError::BadPubkey(format!(
            "expected 32 bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors_roundtrip() {
        // (bytes, base58) pairs from the Bitcoin base58 test vectors.
        let cases: &[(&[u8], &str)] = &[
            (&[], "1"),
            (&[0], "1"),
            (&[0, 0, 0], "111"),
            (&[1], "2"),
            (&[255], "5Q"),
            (&[0, 1], "12"),
            (b"hello world", "StV1DL6CwTryKyV"),
        ];
        for (bytes, s) in cases {
            assert_eq!(&encode(bytes), s, "encode {bytes:?}");
        }
        // decode is the inverse for the non-empty cases.
        assert_eq!(decode("2").unwrap(), vec![1]);
        assert_eq!(decode("StV1DL6CwTryKyV").unwrap(), b"hello world");
    }

    #[test]
    fn system_program_is_32_zero_bytes() {
        // The System program id is 32 zero bytes -> 32 '1's. This is a great
        // canary: it exercises leading-zero handling on both sides.
        let id = "11111111111111111111111111111111";
        assert_eq!(decode_32(id).unwrap(), [0u8; 32]);
        assert_eq!(encode(&[0u8; 32]), id);
    }

    #[test]
    fn real_pubkey_roundtrips() {
        // USDC mint. Any typo in encode/decode changes the string.
        let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let bytes = decode_32(usdc).unwrap();
        assert_eq!(encode(&bytes), usdc);
    }

    #[test]
    fn rejects_non_alphabet() {
        // '0', 'O', 'I', 'l' are not in the base58 alphabet.
        assert!(decode("0OIl").is_err());
        assert!(matches!(decode(""), Err(CoreError::Base58(_))));
    }

    #[test]
    fn wrong_length_rejected_by_decode_32() {
        assert!(matches!(decode_32("2"), Err(CoreError::BadPubkey(_))));
    }
}
