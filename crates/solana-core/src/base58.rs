//! Base58 address handling. Solana addresses are base58-encoded 32-byte keys;
//! `solana-sdk` is the usual source of this, but it will not build for
//! `wasm32-wasip2` in a component, so we wrap `bs58` directly.

use crate::Pubkey;

/// Encode a 32-byte key as its canonical base58 address string.
pub fn encode(key: &Pubkey) -> String {
    bs58::encode(key).into_string()
}

/// Decode a base58 address into a 32-byte key.
///
/// Returns `Err` (never panics) if the input is not valid base58 or does not
/// decode to exactly 32 bytes, so a hallucinated or malformed "address" from the
/// model is rejected rather than acted on.
pub fn decode(addr: &str) -> Result<Pubkey, String> {
    let bytes = bs58::decode(addr.trim())
        .into_vec()
        .map_err(|e| format!("invalid base58 address: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "address decodes to {} bytes, expected 32",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// True if `addr` is a syntactically valid Solana address (base58, 32 bytes).
pub fn is_valid(addr: &str) -> bool {
    decode(addr).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_the_system_program() {
        let sys = crate::programs::SYSTEM;
        let key = decode(sys).unwrap();
        assert_eq!(key, [0u8; 32]);
        assert_eq!(encode(&key), sys);
    }

    #[test]
    fn round_trips_the_token_program() {
        let key = decode(crate::programs::SPL_TOKEN).unwrap();
        assert_eq!(encode(&key), crate::programs::SPL_TOKEN);
    }

    #[test]
    fn rejects_non_base58() {
        assert!(decode("not a real address 0OIl").is_err());
        assert!(!is_valid("0OIl"));
    }

    #[test]
    fn rejects_wrong_length() {
        // Valid base58 but only a few bytes.
        assert!(decode("abc").is_err());
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let sys = crate::programs::SYSTEM;
        assert!(decode(&format!("  {sys}\n")).is_ok());
    }
}
