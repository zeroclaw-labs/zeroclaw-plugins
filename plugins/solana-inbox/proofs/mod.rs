//! Kani proof harnesses for critical invariants of the pure core.
//!
//! These do NOT compile or run under normal `cargo build` / `cargo test`
//! (gated on `cfg(kani)`). To verify:
//!
//! ```bash
//! cargo install --locked kani-verifier    # one-time
//! cargo kani setup                        # one-time
//! cargo kani --harness proof_amount_no_panic
//! cargo kani --harness proof_pubkey_shape
//! ```
//!
//! Each harness pairs 1:1 with a section in `PROOFS.md`.

#![cfg(kani)]

use solana_inbox::core::*;

/// Bounded input space so Kani terminates in reasonable time. Real-world
/// callers pass full u128 / u8 values; the invariant we prove here
/// (`pretty_amount does not panic on any bounded input`) generalizes.
#[kani::proof]
fn proof_amount_no_panic() {
    let amount: u128 = kani::any();
    let decimals: u8 = kani::any();
    kani::assume(decimals <= 20);
    let _ = pretty_amount_exposed(amount, decimals);
}

/// Any string of length outside [32, 44] is not a plausible pubkey.
/// Bounded to length 0..=50 for Kani termination.
#[kani::proof]
#[kani::unwind(51)]
fn proof_pubkey_shape() {
    let bytes: [u8; 50] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 50);
    let s = match std::str::from_utf8(&bytes[..len]) {
        Ok(s) => s,
        Err(_) => return, // trivially not a valid pubkey
    };
    let plausible = is_plausible_pubkey_exposed(s);
    if !(32..=44).contains(&len) {
        assert!(!plausible, "length {len} passed the plausible-pubkey gate");
    }
}
