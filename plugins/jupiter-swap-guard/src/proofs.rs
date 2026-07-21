//! Kani proof harnesses. Compiled only under `cfg(kani)` (`cargo kani`), never in
//! normal or wasm builds.
//!
//! Scope is deliberate and honest (see `PROOFS.md` for the tier of every
//! property). Kani here proves the two encoder-integrity properties that a
//! byte-manipulation bug would break — compact-u16 malleability and reader
//! crash-safety — exhaustively over their input domains. The arithmetic
//! guardrails (`min_out` floor, priority-fee ceil) are `u128`-division-heavy,
//! which CBMC bit-blasts into an intractable divider circuit regardless of input
//! bounds; those are covered by `proptest` (thousands of random cases) plus
//! boundary unit tests in `crate::policy`, and String-domain config parsing
//! (`P8`) by unit tests — claiming a full Kani proof of either would overstate
//! the guarantee.

#![allow(dead_code)]

use crate::encode::{read_compact_u16, write_compact_u16};

/// P6: compact-u16 write then read is the identity for every u16, and the reader
/// consumes exactly the bytes the writer produced. A malleable length field would
/// let two different byte strings decode to the same message.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(4)]
fn compact_u16_roundtrips() {
    let v: u16 = kani::any();
    let mut buf = Vec::with_capacity(3);
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
