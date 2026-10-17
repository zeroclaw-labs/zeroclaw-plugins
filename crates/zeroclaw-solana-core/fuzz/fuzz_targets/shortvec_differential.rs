#![no_main]

use libfuzzer_sys::fuzz_target;

// Differential fuzz target: our hand-rolled compact-u16 shortvec decoder
// must agree with the canonical `solana-short-vec` crate on every input,
// success or failure alike. This is the coverage-guided complement to the
// `shortvec_decode_agrees_with_canonical_crate_on_arbitrary_bytes` proptest
// in `transaction.rs` -- same property, explored by libFuzzer's mutation
// engine instead of proptest's random sampling.
fuzz_target!(|data: &[u8]| {
    let ours = zeroclaw_solana_core::transaction::decode_shortvec_len(data);
    let canonical = solana_short_vec::decode_shortu16_len(data);
    match (ours, canonical) {
        (Ok(ours), Ok(canonical)) => assert_eq!(
            ours, canonical,
            "value/length mismatch for {data:?}: ours={ours:?} canonical={canonical:?}"
        ),
        (Err(_), Err(())) => {} // both correctly rejected
        (ours, canonical) => panic!(
            "divergence for {data:?}: ours={ours:?}, canonical={canonical:?}"
        ),
    }
});
