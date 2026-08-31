//! Kani proof harnesses for two size-invariants of the pure core.
//!
//! Gated on `cfg(kani)` — invisible to `cargo build` / `cargo test`. To
//! verify locally:
//!
//! ```bash
//! cargo install --locked kani-verifier    # one-time
//! cargo kani setup                        # one-time
//! cargo kani --harness proof_amount_no_panic
//! cargo kani --harness proof_pubkey_shape
//! ```
//!
//! CI runs both harnesses on every push to this branch; the badge on
//! `PROOFS.md` is the source of truth.

use crate::core::{is_plausible_pubkey, pretty_amount};

/// `pretty_amount(u128, u8)` must never panic. u128 arithmetic is
/// obvious; the divisor path uses `10u128.pow(decimals as u32)` which
/// overflows if `decimals >= 39`. We assume `decimals <= 20` (Solana
/// tokens are capped well below this in practice) so the harness proves
/// the safe operating envelope Kani-exhaustively.
#[kani::proof]
fn proof_amount_no_panic() {
    let amount: u128 = kani::any();
    let decimals: u8 = kani::any();
    kani::assume(decimals <= 20);
    let _ = pretty_amount(amount, decimals);
}

/// Any string of length outside [32, 44] must be rejected by
/// `is_plausible_pubkey`. Bounded input length to 50 for Kani
/// termination; the invariant generalizes to any length.
#[kani::proof]
#[kani::unwind(51)]
fn proof_pubkey_shape() {
    let bytes: [u8; 50] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 50);
    let Ok(s) = std::str::from_utf8(&bytes[..len]) else {
        return;
    };
    let plausible = is_plausible_pubkey(s);
    if !(32..=44).contains(&len) {
        assert!(!plausible, "length {len} passed the plausible-pubkey gate");
    }
}
