//! Structure-aware hostile input for the decoder.
//!
//! `decode` is the only place in Safe Hands that parses bytes an attacker
//! fully controls, and the ROADMAP names it as the weakest link in the
//! verification chain: `verdict()` is proven exhaustively, the model/engine
//! agreement is proptested, and everything downstream trusts whatever shape
//! this function returns. An attacker who could make the decoder mis-describe
//! a transaction would defeat all twelve Kani proofs without touching them.
//!
//! There is already a libFuzzer target (`fuzz/fuzz_targets/decode.rs`). It is
//! better than this at finding deep states — and it cannot run on Windows at
//! all, because `cargo-fuzz` needs libFuzzer. A property that only some
//! contributors can execute is a property the project cannot rely on.
//!
//! So these start from *valid* transactions and damage them, rather than
//! drawing uniform random bytes. Random bytes essentially never produce a
//! plausible header followed by a hostile length; truncating and corrupting a
//! real message does, on every draw.
//!
//! Two invariants, asserted everywhere:
//!
//! 1. **Never panic.** Inside the wasm component a panic is a trap, and a
//!    caller that reads a trap as anything other than "refuse" has failed
//!    open. `Err` is a correct answer; unwinding is not.
//! 2. **Deterministic.** The same bytes must always decode to the same facts.
//!    `decision_id` commits a verdict to exactly these bytes, so a decoder
//!    that answered differently on a second look would make that commitment
//!    meaningless.

use proptest::prelude::*;
use safe_hands_core::codec::shortvec_encode;
use safe_hands_core::crypto::{ata_address, parse_pubkey};
use safe_hands_core::decode::decode;
use safe_hands_core::ix;
use solana_hash::Hash;
use solana_message::Message;
use solana_pubkey::Pubkey;

const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

fn proptest_cases() -> u32 {
    std::env::var("SH_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512)
}

/// A real, well-formed transfer message — the starting point for every
/// mutation below. Damaging something valid reaches parser states that random
/// bytes do not.
fn valid_message() -> Vec<u8> {
    let payer = parse_pubkey("AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9").expect("payer");
    let dest = parse_pubkey("9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu").expect("dest");
    let mint = parse_pubkey(USDC).expect("mint");
    let token_program = ix::spl_token_program();
    let ata = ata_address(&dest, &token_program, &mint);
    let source = Pubkey::new_from_array([7u8; 32]);

    let ixs = vec![
        ix::ata_create_idempotent(&payer, &ata, &dest, &mint, &token_program),
        ix::transfer_checked(&token_program, &source, &mint, &ata, &payer, 25_000_000, 6),
        ix::memo("invoice-412"),
    ];
    let mut msg = Message::new(&ixs, Some(&payer));
    msg.recent_blockhash = Hash::new_from_array([7u8; 32]);
    bincode::serialize(&msg).expect("serialize")
}

/// Decoding twice must agree. Returns the debug rendering so callers can
/// compare without `DecodedTx` needing `PartialEq`.
fn decode_twice_agrees(bytes: &[u8]) -> bool {
    let a = decode(bytes);
    let b = decode(bytes);
    match (a, b) {
        (Ok(x), Ok(y)) => format!("{x:?}") == format!("{y:?}"),
        (Err(x), Err(y)) => x == y,
        _ => false,
    }
}

#[test]
fn every_truncation_of_a_valid_message_is_refused_not_fatal() {
    let full = valid_message();
    // Every prefix, including empty. A cursor that reads one field past the
    // end shows up here and nowhere else.
    for cut in 0..full.len() {
        let slice = &full[..cut];
        let _ = decode(slice);
        assert!(
            decode_twice_agrees(slice),
            "truncation at {cut} decoded differently on a second look"
        );
    }
    // The untruncated message must still decode, or the test is vacuous.
    assert!(decode(&full).is_ok(), "the unmodified message must decode");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    /// Flip one byte of a valid message. Most draws land in a pubkey or an
    /// amount and decode fine; the interesting ones land in a length prefix,
    /// a program-id index, or the version byte.
    #[test]
    fn single_byte_corruption_never_panics(
        offset in 0usize..400,
        value in any::<u8>(),
    ) {
        let mut bytes = valid_message();
        if offset < bytes.len() {
            bytes[offset] = value;
        }
        let _ = decode(&bytes);
        prop_assert!(decode_twice_agrees(&bytes));
    }

    /// A plausible message prefixed by a shortvec claiming far more elements
    /// than the buffer can hold. This is the shape uniform random bytes almost
    /// never generate and the one a hand-written cursor is most likely to
    /// trust.
    #[test]
    fn hostile_shortvec_length_never_panics(claimed in 0u16..=u16::MAX) {
        let mut bytes = shortvec_encode(claimed as usize);
        bytes.extend_from_slice(&valid_message());
        let _ = decode(&bytes);
        prop_assert!(decode_twice_agrees(&bytes));
    }

    /// Versioned-transaction prefix byte, swept across every value. Only
    /// `0x80` is a v0 message; `0x81..=0xFF` set the version bit with a
    /// version the runtime does not define, and the low range is a legacy
    /// signature count.
    #[test]
    fn arbitrary_version_prefix_never_panics(prefix in any::<u8>()) {
        let mut bytes = vec![prefix];
        bytes.extend_from_slice(&valid_message());
        let _ = decode(&bytes);
        prop_assert!(decode_twice_agrees(&bytes));
    }

    /// Splice a run of arbitrary bytes into the middle of a valid message,
    /// keeping a well-formed head. Reaches states behind a successfully
    /// parsed header that a fully random buffer stops short of.
    #[test]
    fn spliced_garbage_after_a_valid_head_never_panics(
        at in 0usize..200,
        junk in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let mut bytes = valid_message();
        let at = at.min(bytes.len());
        bytes.splice(at..at, junk);
        let _ = decode(&bytes);
        prop_assert!(decode_twice_agrees(&bytes));
    }

    /// Fully arbitrary input, kept for the class the structured cases exclude
    /// by construction. Cheap, and the only one that can surprise us about
    /// the empty and near-empty cases.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode(&bytes);
        prop_assert!(decode_twice_agrees(&bytes));
    }
}
