//! Base58 <-> 32-byte pubkey helpers. Pure, no wasm dependency.

#![forbid(unsafe_code)]

use crate::encode::Pubkey;

/// Decode a base58 string into a 32-byte pubkey. Rejects wrong-length input.
pub fn decode_pubkey(s: &str) -> Result<Pubkey, String> {
    let v = bs58::decode(s)
        .into_vec()
        .map_err(|e| format!("invalid base58: {e}"))?;
    Pubkey::try_from(v.as_slice()).map_err(|_| format!("pubkey must be 32 bytes, got {}", v.len()))
}

/// Encode a 32-byte pubkey as base58.
pub fn encode_pubkey(k: &Pubkey) -> String {
    bs58::encode(k).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_known_pubkey() {
        // Wrapped SOL mint.
        let s = "So11111111111111111111111111111111111111112";
        let k = decode_pubkey(s).unwrap();
        assert_eq!(encode_pubkey(&k), s);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(decode_pubkey("abc").is_err());
    }
}
