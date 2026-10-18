//! base58 pubkeys, decoded strictly.
//!
//! This is the boundary where untrusted input becomes a 32-byte key, so it is
//! the boundary that has to be pedantic. `token-risk-check` validates a
//! caller-supplied mint here *before any request is built*, which is what stops
//! a prompt-injected argument from smuggling a URL or RPC parameters into an
//! outbound call — the decode fails first, so nothing is ever constructed.

/// A 32-byte Solana public key.
pub type Pubkey = [u8; 32];

/// Decode a base58 pubkey, insisting on exactly 32 bytes.
///
/// Rejects: invalid base58 alphabet, and anything that does not decode to
/// exactly 32 bytes. There is deliberately no lenient variant.
pub fn decode(s: &str) -> Result<Pubkey, String> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| format!("'{s}' is not valid base58: {e}"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("'{s}' decodes to {len} bytes, not a 32-byte pubkey"))
}

/// Encode 32 bytes back to base58.
pub fn encode(key: &Pubkey) -> String {
    bs58::encode(key).into_string()
}

/// Validate without keeping the bytes — for argument checks at an API edge.
pub fn is_valid(s: &str) -> bool {
    decode(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Well-known mainnet addresses, used as fixed points.
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
    const SYSTEM: &str = "11111111111111111111111111111111";

    #[test]
    fn roundtrips_known_addresses() {
        for a in [USDC, MEMO, SYSTEM] {
            let k = decode(a).unwrap_or_else(|e| panic!("{a}: {e}"));
            assert_eq!(encode(&k), a, "roundtrip {a}");
        }
    }

    #[test]
    fn system_program_is_all_zeroes() {
        // '1' is base58 zero; the system program id is 32 zero bytes.
        assert_eq!(decode(SYSTEM).unwrap(), [0u8; 32]);
    }

    #[test]
    fn rejects_bad_input() {
        // 0, O, I and l are not in the base58 alphabet.
        assert!(decode("not-base58-0OIl").is_err());
        // Valid base58, wrong length.
        assert!(decode("abc").is_err());
        assert!(decode("").is_err());
        // A 64-byte value (e.g. a signature) is not a pubkey.
        let sig = bs58::encode([7u8; 64]).into_string();
        assert!(decode(&sig).is_err());
    }

    #[test]
    fn error_message_names_the_actual_length() {
        let err = decode("abc").unwrap_err();
        assert!(err.contains("not a 32-byte pubkey"), "unhelpful error: {err}");
    }

    #[test]
    fn is_valid_matches_decode() {
        assert!(is_valid(USDC));
        assert!(!is_valid("abc"));
    }
}
