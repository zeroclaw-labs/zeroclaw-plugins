//! Merkle-fold conformance tests.
//!
//! The fold rule must match the TxODDS on-chain settlement primitive exactly:
//! keccak-256, and the sibling-side flag decides concatenation order. Every test
//! here pins one property an on-chain verifier depends on — a proof that folds to
//! the anchored root is accepted, anything else is not.

use solana_verify::verify::*;

fn n(h: [u8; 32], right: bool) -> ProofNode {
    ProofNode { hash: h, is_right_sibling: right }
}
fn h(s: &str) -> [u8; 32] {
    keccak256(s.as_bytes())
}
/// Reference parent hash, computed independently of `merkle_fold`.
fn parent(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&left);
    buf[32..].copy_from_slice(&right);
    keccak256(&buf)
}

// ── fold mechanics ──────────────────────────────────────────────────────────

#[test]
fn empty_proof_folds_to_the_leaf_itself() {
    let leaf = h("leaf");
    assert_eq!(merkle_fold(leaf, &[], keccak256), leaf);
}

#[test]
fn right_sibling_concatenates_node_then_sibling() {
    let leaf = h("a");
    let sib = h("b");
    assert_eq!(merkle_fold(leaf, &[n(sib, true)], keccak256), parent(leaf, sib));
}

#[test]
fn left_sibling_concatenates_sibling_then_node() {
    let leaf = h("a");
    let sib = h("b");
    assert_eq!(merkle_fold(leaf, &[n(sib, false)], keccak256), parent(sib, leaf));
}

#[test]
fn sibling_side_is_not_symmetric() {
    // Flipping the side flag must change the result — otherwise position in the
    // tree would be unconstrained and a proof could be replayed at another index.
    let leaf = h("a");
    let sib = h("b");
    assert_ne!(
        merkle_fold(leaf, &[n(sib, true)], keccak256),
        merkle_fold(leaf, &[n(sib, false)], keccak256)
    );
}

#[test]
fn depth_two_folds_in_order() {
    let leaf = h("a");
    let s1 = h("b");
    let s2 = h("cd");
    let expect = parent(parent(leaf, s1), s2);
    assert_eq!(merkle_fold(leaf, &[n(s1, true), n(s2, true)], keccak256), expect);
}

#[test]
fn depth_three_mixed_sides() {
    let leaf = h("a");
    let s1 = h("b");
    let s2 = h("cd");
    let s3 = h("efgh");
    // right, left, right
    let lvl1 = parent(leaf, s1);
    let lvl2 = parent(s2, lvl1);
    let expect = parent(lvl2, s3);
    assert_eq!(
        merkle_fold(leaf, &[n(s1, true), n(s2, false), n(s3, true)], keccak256),
        expect
    );
}

#[test]
fn depth_four_all_left_siblings() {
    let leaf = h("leaf");
    let sibs = [h("s1"), h("s2"), h("s3"), h("s4")];
    let mut expect = leaf;
    for s in sibs {
        expect = parent(s, expect);
    }
    let proof: Vec<ProofNode> = sibs.iter().map(|s| n(*s, false)).collect();
    assert_eq!(merkle_fold(leaf, &proof, keccak256), expect);
}

#[test]
fn depth_four_all_right_siblings() {
    let leaf = h("leaf");
    let sibs = [h("s1"), h("s2"), h("s3"), h("s4")];
    let mut expect = leaf;
    for s in sibs {
        expect = parent(expect, s);
    }
    let proof: Vec<ProofNode> = sibs.iter().map(|s| n(*s, true)).collect();
    assert_eq!(merkle_fold(leaf, &proof, keccak256), expect);
}

#[test]
fn fold_is_deterministic_across_calls() {
    let leaf = h("a");
    let proof = [n(h("b"), true), n(h("c"), false)];
    assert_eq!(
        merkle_fold(leaf, &proof, keccak256),
        merkle_fold(leaf, &proof, keccak256)
    );
}

#[test]
fn changing_the_leaf_changes_the_root() {
    let proof = [n(h("b"), true)];
    assert_ne!(
        merkle_fold(h("a"), &proof, keccak256),
        merkle_fold(h("a2"), &proof, keccak256)
    );
}

#[test]
fn changing_a_sibling_changes_the_root() {
    let leaf = h("a");
    assert_ne!(
        merkle_fold(leaf, &[n(h("b"), true)], keccak256),
        merkle_fold(leaf, &[n(h("b2"), true)], keccak256)
    );
}

#[test]
fn reordering_siblings_changes_the_root() {
    let leaf = h("a");
    let s1 = h("s1");
    let s2 = h("s2");
    assert_ne!(
        merkle_fold(leaf, &[n(s1, true), n(s2, true)], keccak256),
        merkle_fold(leaf, &[n(s2, true), n(s1, true)], keccak256)
    );
}

#[test]
fn hasher_choice_changes_the_root() {
    // The on-chain root is keccak-anchored; folding with sha256 must not collide.
    let leaf = h("a");
    let proof = [n(h("b"), true)];
    assert_ne!(
        merkle_fold(leaf, &proof, keccak256),
        merkle_fold(leaf, &proof, sha256)
    );
}

#[test]
fn sha256_fold_is_self_consistent() {
    let leaf = sha256(b"a");
    let sib = sha256(b"b");
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&leaf);
    buf[32..].copy_from_slice(&sib);
    assert_eq!(merkle_fold(leaf, &[n(sib, true)], sha256), sha256(&buf));
}

// ── verification verdicts ───────────────────────────────────────────────────

#[test]
fn valid_proof_verifies() {
    let leaf = h("a");
    let sib = h("b");
    assert!(merkle_verify(leaf, &[n(sib, true)], parent(leaf, sib)));
}

#[test]
fn forged_leaf_is_rejected() {
    let leaf = h("a");
    let sib = h("b");
    let root = parent(leaf, sib);
    assert!(!merkle_verify(h("evil"), &[n(sib, true)], root));
}

#[test]
fn forged_root_is_rejected() {
    let leaf = h("a");
    let sib = h("b");
    assert!(!merkle_verify(leaf, &[n(sib, true)], h("not-the-root")));
}

#[test]
fn wrong_sibling_side_is_rejected() {
    let leaf = h("a");
    let sib = h("b");
    let root = parent(leaf, sib); // leaf is LEFT, so sibling is a RIGHT sibling
    assert!(!merkle_verify(leaf, &[n(sib, false)], root));
}

#[test]
fn truncated_proof_is_rejected() {
    let leaf = h("a");
    let s1 = h("s1");
    let s2 = h("s2");
    let root = parent(parent(leaf, s1), s2);
    assert!(!merkle_verify(leaf, &[n(s1, true)], root));
}

#[test]
fn extended_proof_is_rejected() {
    let leaf = h("a");
    let s1 = h("s1");
    let root = parent(leaf, s1);
    assert!(!merkle_verify(leaf, &[n(s1, true), n(h("extra"), true)], root));
}

#[test]
fn empty_proof_only_verifies_against_the_leaf_as_root() {
    let leaf = h("a");
    assert!(merkle_verify(leaf, &[], leaf));
    assert!(!merkle_verify(leaf, &[], h("other")));
}

#[test]
fn zero_leaf_with_empty_proof_does_not_match_an_arbitrary_root() {
    // The prompt-injection shape: "trust me, it's settled" with a null proof.
    assert!(!merkle_verify([0u8; 32], &[], [0xde; 32]));
}

#[test]
fn sibling_swapped_with_leaf_is_rejected() {
    // An attacker who knows leaf+sibling can't just swap their roles.
    let leaf = h("a");
    let sib = h("b");
    let root = parent(leaf, sib);
    assert!(!merkle_verify(sib, &[n(leaf, true)], root));
}

#[test]
fn deep_valid_proof_verifies_end_to_end() {
    let leaf = h("target");
    let sibs = [
        n(h("s1"), true),
        n(h("s2"), false),
        n(h("s3"), true),
        n(h("s4"), false),
        n(h("s5"), true),
    ];
    let root = merkle_fold(leaf, &sibs, keccak256);
    assert!(merkle_verify(leaf, &sibs, root));
    // one flipped side anywhere breaks it
    let mut broken = sibs;
    broken[2].is_right_sibling = false;
    assert!(!merkle_verify(leaf, &broken, root));
}

// ── hash primitives ─────────────────────────────────────────────────────────

#[test]
fn keccak256_matches_known_empty_digest() {
    // Keccak-256("") — the canonical Ethereum/Solana-tooling value.
    assert_eq!(
        to_hex(&keccak256(b"")),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
}

#[test]
fn sha256_matches_known_empty_digest() {
    assert_eq!(
        to_hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn keccak256_matches_known_abc_digest() {
    assert_eq!(
        to_hex(&keccak256(b"abc")),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
}

#[test]
fn hashes_are_deterministic_and_differ_per_input() {
    assert_eq!(keccak256(b"x"), keccak256(b"x"));
    assert_ne!(keccak256(b"x"), keccak256(b"y"));
    assert_eq!(sha256(b"x"), sha256(b"x"));
    assert_ne!(sha256(b"x"), sha256(b"y"));
}

#[test]
fn keccak_and_sha256_never_agree_on_the_same_input() {
    for s in [b"".as_ref(), b"a".as_ref(), b"solana".as_ref()] {
        assert_ne!(keccak256(s), sha256(s));
    }
}
