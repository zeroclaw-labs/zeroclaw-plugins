//! Deterministic Solana Pay reference derivation.
//!
//! ```text
//! reference = bs58(sha256(b"zc-inv-v1" || invoice_id || b"|" || merchant)[0..32])
//! ```
//!
//! The hash is already 32 bytes; we take the full SHA-256 digest so the
//! reference is a valid 32-byte pubkey-shaped account id for
//! `getSignaturesForAddress`.

use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"zc-inv-v1";

/// Derive a deterministic base58 reference for an invoice.
pub fn derive_reference(invoice_id: &str, merchant: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(invoice_id.as_bytes());
    hasher.update(b"|");
    hasher.update(merchant.as_bytes());
    let digest = hasher.finalize();
    // SHA-256 is 32 bytes; [0..32] is the full digest.
    bs58::encode(&digest[..32]).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_is_deterministic() {
        let a = derive_reference("inv-001", "11111111111111111111111111111112");
        let b = derive_reference("inv-001", "11111111111111111111111111111112");
        assert_eq!(a, b);
        // Different inputs → different refs
        let c = derive_reference("inv-002", "11111111111111111111111111111112");
        assert_ne!(a, c);
        let d = derive_reference("inv-001", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        assert_ne!(a, d);
    }

    #[test]
    fn reference_is_valid_base58_32_bytes() {
        let r = derive_reference("inv-001", "11111111111111111111111111111112");
        let bytes = bs58::decode(&r).into_vec().unwrap();
        assert_eq!(bytes.len(), 32);
    }
}
