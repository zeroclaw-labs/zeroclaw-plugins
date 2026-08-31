#![no_main]

use libfuzzer_sys::fuzz_target;

// Coverage-guided complement to the `mint_parsing_never_panics_on_arbitrary_bytes`
// proptest: no byte sequence handed to the zero-copy Token-2022 parser may
// ever panic, regardless of how libFuzzer mutates it. A `Result` (Ok or
// Err) is the only acceptable outcome.
fuzz_target!(|data: &[u8]| {
    let _ = zeroclaw_solana_core::rpc::parse_mint_risk_view(data);
});
