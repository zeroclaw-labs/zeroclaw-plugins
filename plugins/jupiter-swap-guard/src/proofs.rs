//! Kani proof harnesses over the pure scalar core. Compiled only under `cfg(kani)`
//! (`cargo kani`), never in normal or wasm builds.
//!
//! Scope is deliberate and honest: Kani excels at the bounded, integer-domain
//! properties, which is exactly where a silent arithmetic bug would let a
//! guardrail leak. String-domain properties (config parsing, `P8`) are covered by
//! unit + property tests instead — arbitrary-`String` reasoning is not Kani's
//! strength, and claiming otherwise would overstate the guarantee. `PROOFS.md`
//! records which tier covers which property.

#![allow(dead_code)]

use crate::encode::{read_compact_u16, write_compact_u16};
use crate::policy::{min_out_floor, priority_fee_lamports};

/// P2: the emitted `min_out` floor can never exceed the quote it is derived from,
/// for every quote and every slippage — a floor above the quote would let a swap
/// demand more than the route can deliver, or (worse) mask a manipulated quote.
/// Also proves the u128 arithmetic never panics.
#[cfg(kani)]
#[kani::proof]
fn min_out_never_exceeds_quote() {
    let quote: u64 = kani::any();
    let bps: u16 = kani::any();
    let floor = min_out_floor(quote, bps);
    assert!(floor <= quote);
}

/// P2 (boundary): zero slippage keeps the full quote; 100% slippage floors at 0.
#[cfg(kani)]
#[kani::proof]
fn min_out_boundaries() {
    let quote: u64 = kani::any();
    assert!(min_out_floor(quote, 0) == quote);
    let bps: u16 = kani::any();
    kani::assume(bps >= 10_000);
    assert!(min_out_floor(quote, bps) == 0);
}

/// D4: the priority-fee computation never panics and is zero exactly when the
/// product of unit-limit and price is zero — so a non-trivial fee can never be
/// mis-scored as zero and slip under the cap.
#[cfg(kani)]
#[kani::proof]
fn priority_fee_is_sound() {
    let limit: u32 = kani::any();
    let price: u64 = kani::any();
    let fee = priority_fee_lamports(limit, price);
    let product = limit as u128 * price as u128;
    if product == 0 {
        assert!(fee == 0);
    } else {
        assert!(fee >= 1);
        // ceil bound holds whenever the true fee fits in u64 (i.e. not saturated).
        if fee < u64::MAX {
            assert!((fee as u128) * 1_000_000 >= product);
        }
    }
}

/// P6: compact-u16 write then read is the identity for every u16, and the reader
/// consumes exactly the bytes the writer produced. A malleable length field would
/// let two different byte strings decode to the same message.
#[cfg(kani)]
#[kani::proof]
fn compact_u16_roundtrips() {
    let v: u16 = kani::any();
    let mut buf = Vec::new();
    write_compact_u16(&mut buf, v);
    let (got, consumed) = read_compact_u16(&buf, 0).unwrap();
    assert!(got == v);
    assert!(consumed == buf.len());
}

/// P7 (crash-safety): the compact-u16 reader never panics on arbitrary bounded
/// input — malformed instruction data must produce a clean error, not a fail-open
/// crash inside the host.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(5)]
fn compact_u16_read_never_panics() {
    let b0: u8 = kani::any();
    let b1: u8 = kani::any();
    let b2: u8 = kani::any();
    let bytes = [b0, b1, b2];
    // Must return (never panic); value/consumed unconstrained.
    let _ = read_compact_u16(&bytes, 0);
}
