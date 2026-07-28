//! sha256 helpers used to build tamper-evident chains.
//!
//! `depin-attest` links attestation N to the on-chain signature of attestation
//! N-1 with a truncated digest, so a verifier can walk the chain and detect a
//! gap or a rewrite without trusting the reporter.

use sha2::{Digest, Sha256};

/// Full sha256 digest.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// Lowercase hex of the full digest.
pub fn sha256_hex(input: &[u8]) -> String {
    sha256(input).iter().map(|b| format!("{b:02x}")).collect()
}

/// First 8 bytes of sha256 as hex (16 chars) — the chain link format.
///
/// Truncation is deliberate: this rides inside a 566-byte memo, and 64 bits of
/// second-preimage resistance is the accepted trade for a link whose purpose is
/// tamper *evidence*, not collision-proof identity.
pub fn short_hash_hex(input: &str) -> String {
    sha256(input.as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_sha256_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn short_hash_is_the_digest_prefix() {
        let full = sha256_hex(b"attestation");
        assert_eq!(short_hash_hex("attestation"), full[..16]);
        assert_eq!(short_hash_hex("attestation").len(), 16);
    }

    #[test]
    fn different_inputs_differ() {
        assert_ne!(short_hash_hex("a"), short_hash_hex("b"));
    }
}
