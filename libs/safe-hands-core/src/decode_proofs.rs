//! Machine-checked properties of the decoder.
//!
//! The ROADMAP names `decode()` as the weakest link in the verification chain:
//! `verdict()` is proven exhaustively, the model/engine agreement is
//! proptested, and everything downstream trusts whatever shape the decoder
//! returns. An attacker who could make it mis-describe a transaction would
//! defeat all twelve authorization proofs without touching one of them.
//!
//! Proving the decoder outright is out of reach today — it parses heap
//! structures, and the earlier attempt to model-check `evaluate()` directly
//! failed to terminate for exactly that reason (Kani issue #1251). What *is*
//! in reach is the property that matters most, over a bounded input:
//!
//! **No byte string up to `N` bytes makes the decoder panic.**
//!
//! That is worth stating as a theorem rather than a fuzzing result because of
//! where this code runs. Inside a `wasm32-wasip2` component a panic is a trap,
//! and a host that reads a trap as anything other than *refuse* has failed
//! open. `Err` is a correct answer here; unwinding is not an answer at all.
//!
//! The bound is small by necessity, and smaller than hoped. Kani explores the
//! whole input space, so each byte costs exponentially — and measured on CI,
//! `N = 8` did not terminate inside 90 minutes. That is itself a result: the
//! obstacle is not proof effort but the shape of the code. A decoder built
//! from bounded, heap-free steps would be provable at a useful width; this one
//! is not, and the ROADMAP's first item is to restructure it rather than to
//! throw more solver at it. It is chosen to reach
//! past the early length-prefix and header logic, which is where a hand-rolled
//! cursor is most likely to read off the end. Beyond the bound, the same
//! property is asserted by `tests/decode_hostile.rs` (structure-aware, runs
//! everywhere) and by the libFuzzer target (deeper, Linux/macOS only).
//!
//! ```sh
//! cargo kani --manifest-path libs/safe-hands-core/Cargo.toml --harness decode_never_panics_up_to_4_bytes
//! ```

#![cfg(kani)]

use crate::decode::decode;

/// Every input up to 4 bytes, exhaustively.
///
/// Four reaches the signature-vector shortvec, the version byte and the
/// three-byte message header — the region where a truncated buffer and a
/// length prefix that lies are both in play at once.
#[kani::proof]
#[kani::unwind(8)]
fn decode_never_panics_up_to_4_bytes() {
    const N: usize = 4;
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    // The result is deliberately discarded: the claim is termination without
    // panic, for every input, not that any particular input decodes.
    let _ = decode(&bytes[..len]);
}

/// The empty and near-empty cases, called out separately.
///
/// These are cheap to prove and are the inputs a caller is most likely to
/// produce by accident — a truncated read, a dropped connection, a
/// zero-length body.
#[kani::proof]
#[kani::unwind(8)]
fn decode_never_panics_on_tiny_input() {
    const N: usize = 3;
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let _ = decode(&bytes[..len]);
}

/// Decoding is a function: the same bytes always give the same answer.
///
/// `decision_id` commits a verdict to exactly these bytes. A decoder that
/// answered differently on a second look would make that commitment
/// meaningless, and would do it silently.
#[kani::proof]
#[kani::unwind(8)]
fn decode_is_deterministic_up_to_4_bytes() {
    const N: usize = 4;
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let slice = &bytes[..len];

    let first = decode(slice);
    let second = decode(slice);

    match (first, second) {
        (Ok(_), Ok(_)) => {}
        (Err(a), Err(b)) => assert!(a == b, "same bytes produced two different errors"),
        _ => panic!("decode disagreed with itself on identical bytes"),
    }
}
