#![no_main]
//! Coverage-guided fuzzing of the transaction decoder.
//!
//! `decode` is the only place in Safe Hands that parses bytes an attacker
//! fully controls: shortvec lengths, a legacy bincode message, a hand-rolled
//! versioned-message cursor, and address-lookup-table indices. Everything
//! downstream — policy, intent binding, the Squads proposal — trusts whatever
//! shape this function returns.
//!
//! There is already a proptest property asserting it never panics on random
//! bytes. This goes further: libFuzzer mutates toward *new code paths*, so it
//! reaches deep parser states that uniform random bytes essentially never hit
//! (a plausible header followed by a hostile shortvec, a valid prefix with a
//! truncated tail, ALT indices pointing just past the end).
//!
//! Two properties are asserted:
//!
//! 1. **Never panic.** A panic inside a decoder is not a crash to be caught
//!    later — in the wasm component it is a trap, and a caller that reads a
//!    trap as anything other than "refuse" has failed open.
//! 2. **Decoding is deterministic.** The same bytes must always produce the
//!    same verdict-relevant facts. A decoder that answered differently on a
//!    second look would make the `decision_id` commitment meaningless, since
//!    that hash binds a verdict to exactly these bytes.

use libfuzzer_sys::fuzz_target;
use safe_hands_core::decode::decode;

fuzz_target!(|data: &[u8]| {
    let first = decode(data);

    // Determinism: the commitment in every decision receipt assumes these
    // bytes map to one and only one set of facts.
    let second = decode(data);

    match (first, second) {
        (Ok(a), Ok(b)) => {
            assert_eq!(
                a.serialized_message, b.serialized_message,
                "decode is not deterministic: same bytes, different message"
            );
            assert_eq!(
                a.facts.transfers.len(),
                b.facts.transfers.len(),
                "decode is not deterministic: same bytes, different transfer count"
            );
            assert_eq!(
                a.facts.signed, b.facts.signed,
                "decode is not deterministic: same bytes, different signed flag"
            );
            assert_eq!(
                a.blockhash, b.blockhash,
                "decode is not deterministic: same bytes, different blockhash"
            );
        }
        (Err(_), Err(_)) => {}
        (a, b) => panic!(
            "decode is not deterministic: same bytes, one call succeeded and the other did not \
             ({}, {})",
            a.is_ok(),
            b.is_ok()
        ),
    }
});
