//! Wire-format primitives: compact-u16 (a.k.a. shortvec) and base64 helpers.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::{Digest, Sha256};

/// sha256 over concatenated chunks.
pub fn sha256(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

pub fn base58_encode(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

/// Append a compact-u16 length prefix (Solana's shortvec encoding).
pub fn push_compact_u16(out: &mut Vec<u8>, mut value: u16) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

pub fn to_base64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn from_base64(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s.trim())
        .map_err(|e| format!("invalid base64: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compact(v: u16) -> Vec<u8> {
        let mut out = Vec::new();
        push_compact_u16(&mut out, v);
        out
    }

    #[test]
    fn compact_u16_matches_solana_shortvec() {
        // Reference vectors from solana-sdk's short_vec tests.
        assert_eq!(compact(0), vec![0x00]);
        assert_eq!(compact(5), vec![0x05]);
        assert_eq!(compact(0x7f), vec![0x7f]);
        assert_eq!(compact(0x80), vec![0x80, 0x01]);
        assert_eq!(compact(0xff), vec![0xff, 0x01]);
        assert_eq!(compact(0x100), vec![0x80, 0x02]);
        assert_eq!(compact(0x7fff), vec![0xff, 0xff, 0x01]);
        assert_eq!(compact(0xffff), vec![0xff, 0xff, 0x03]);
    }

    #[test]
    fn base64_round_trip() {
        let data = b"zeroclaw".to_vec();
        assert_eq!(from_base64(&to_base64(&data)).unwrap(), data);
        assert!(from_base64("!!not base64!!").is_err());
    }
}
