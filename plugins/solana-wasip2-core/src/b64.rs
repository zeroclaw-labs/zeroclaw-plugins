//! base64 for account data and transaction payloads.
//!
//! A thin wrapper so callers never have to import the `Engine` trait or pick an
//! alphabet — Solana's JSON-RPC uses standard base64 with padding everywhere,
//! and a plugin that reaches for URL-safe by accident gets silent corruption.

use base64::Engine;

/// Encode with the standard, padded alphabet — what Solana's RPC expects.
pub fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode standard, padded base64. Errors rather than returning partial data.
pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("invalid base64: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        for case in [b"".as_slice(), b"f", b"fo", b"foo", b"foob", &[0u8; 32], &[0xffu8; 165]] {
            assert_eq!(decode(&encode(case)).unwrap(), case, "roundtrip {case:?}");
        }
    }

    #[test]
    fn encodes_known_vector() {
        // RFC 4648 test vector; padding must be present.
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode(b"fo"), "Zm8=");
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode("!!!not base64!!!").is_err());
    }
}
