//! Pure, host-testable Solana verification primitives — no wasm dependency.
//!
//! These are the offline, pure-compute checks a ZeroClaw agent can run without any
//! network egress (the `tool-plugin` WIT world grants no outbound HTTP). They cover the
//! things an agent handling Solana data actually needs to *trust*:
//!   * `merkle_verify` — fold a keccak-256 Merkle proof to an anchored root. This is the
//!     exact primitive TxODDS uses for on-chain score/settlement proofs, and the reason
//!     we can build a genuinely useful verifier: a proof either folds to the root or it
//!     does not, with no oracle to trust.
//!   * `ed25519_verify` — verify a Solana ed25519 signature over a message.
//!   * base58 <-> bytes for Solana pubkeys/signatures, and hex helpers.
//!
//! The same logic compiles to `wasm32-wasip2` for the component and runs under a plain
//! `cargo test` on the host.

use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

/// A single Merkle proof node: the sibling hash and which side it is on.
#[derive(Clone, Copy, Debug)]
pub struct ProofNode {
    pub hash: [u8; 32],
    /// true  → sibling is the RIGHT child: parent = H(node ‖ sibling)
    /// false → sibling is the LEFT  child: parent = H(sibling ‖ node)
    pub is_right_sibling: bool,
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Fold `leaf` up through `proof` and return whether it reaches `root`.
///
/// Matches the fold rule the TxODDS on-chain program uses (`settle/merkle.py` in our
/// settlement engine): keccak-256, sibling-side flag decides concatenation order.
pub fn merkle_fold(leaf: [u8; 32], proof: &[ProofNode], hasher: fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
    let mut node = leaf;
    for sib in proof {
        let mut buf = [0u8; 64];
        if sib.is_right_sibling {
            buf[..32].copy_from_slice(&node);
            buf[32..].copy_from_slice(&sib.hash);
        } else {
            buf[..32].copy_from_slice(&sib.hash);
            buf[32..].copy_from_slice(&node);
        }
        node = hasher(&buf);
    }
    node
}

/// Verify a keccak-256 Merkle proof folds `leaf` to `root`.
pub fn merkle_verify(leaf: [u8; 32], proof: &[ProofNode], root: [u8; 32]) -> bool {
    merkle_fold(leaf, proof, keccak256) == root
}

/// Verify an ed25519 signature (Solana's signature scheme) over `message`.
pub fn ed25519_verify(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let vk = match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(message, &sig).is_ok()
}

// ── encoding helpers ────────────────────────────────────────────────────────
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("bad hex: {e}"))
}

pub fn to_hex(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn b58_decode(s: &str) -> Result<Vec<u8>, String> {
    bs58::decode(s).into_vec().map_err(|e| format!("bad base58: {e}"))
}

pub fn b58_encode(b: &[u8]) -> String {
    bs58::encode(b).into_string()
}

pub fn hex32(s: &str) -> Result<[u8; 32], String> {
    let v = from_hex(s)?;
    v.try_into().map_err(|_| "expected 32 bytes".to_string())
}

pub fn b58_32(s: &str) -> Result<[u8; 32], String> {
    let v = b58_decode(s)?;
    v.try_into().map_err(|_| "expected a 32-byte pubkey".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(h: [u8; 32], right: bool) -> ProofNode {
        ProofNode { hash: h, is_right_sibling: right }
    }

    #[test]
    fn merkle_two_leaf_roundtrip() {
        let a = keccak256(b"leaf-a");
        let b = keccak256(b"leaf-b");
        // root = H(a ‖ b); a's sibling b is on the RIGHT
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&a);
        buf[32..].copy_from_slice(&b);
        let root = keccak256(&buf);
        assert!(merkle_verify(a, &[node(b, true)], root));
        assert!(merkle_verify(b, &[node(a, false)], root)); // b's sibling a on the LEFT
    }

    #[test]
    fn merkle_rejects_forged_leaf_and_wrong_side() {
        let a = keccak256(b"leaf-a");
        let b = keccak256(b"leaf-b");
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&a);
        buf[32..].copy_from_slice(&b);
        let root = keccak256(&buf);
        let forged = keccak256(b"leaf-evil");
        assert!(!merkle_verify(forged, &[node(b, true)], root)); // forged leaf
        assert!(!merkle_verify(a, &[node(b, false)], root)); // wrong sibling side
    }

    #[test]
    fn ed25519_verifies_and_rejects() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let msg = b"settle fixture 18209181";
        let sig = sk.sign(msg);
        assert!(ed25519_verify(&vk.to_bytes(), msg, &sig.to_bytes()));
        assert!(!ed25519_verify(&vk.to_bytes(), b"tampered", &sig.to_bytes()));
        let mut bad = sig.to_bytes();
        bad[0] ^= 0xff;
        assert!(!ed25519_verify(&vk.to_bytes(), msg, &bad));
    }

    #[test]
    fn base58_pubkey_roundtrip() {
        // TxODDS oracle program id
        let pk = "6pW64gN1s2uqjHkn1unFeEjAwJkPGHoppGvS715wyP2J";
        let raw = b58_32(pk).unwrap();
        assert_eq!(b58_encode(&raw), pk);
    }
}
