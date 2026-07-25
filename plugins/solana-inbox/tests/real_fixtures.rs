//! Structural-robustness tests over four real mainnet-beta transactions
//! captured on 2026-07-25. These prove the parser doesn't crash on the
//! kind of production JSON shapes the hand-crafted fixtures don't stress:
//!
//! - `real_meteora_dlmm.json`: 63 static accountKeys, Meteora DLMM +
//!   ComputeBudget + system-transfer instructions.
//! - `real_usdc_activity.json`: 40 accountKeys, ComputeBudget priorities,
//!   custom pool program, dense preTokenBalances/postTokenBalances arrays.
//! - `real_custom_program.json`: 50 accountKeys, only ComputeBudget +
//!   opaque custom program — a plausible "protocol update" tx with no
//!   memos and no watched-address involvement.
//! - `real_durable_nonce_lut.json`: uses a durable-nonce advance in a
//!   versioned tx with **address lookup tables**, so accountKeys is a
//!   mix of `source: "transaction"` static keys and LUT-loaded refs.
//!   This is the shape most likely to break a naïve parser.
//!
//! Fixture sources are documented in `tests/fixtures/README.md`. The
//! assertions here are intentionally minimal — the point is to prove
//! the parser is robust to real data, not to hard-code the exact events
//! any given block produced.

use std::fs;

use serde_json::Value;

use solana_inbox::core::{extract_inbounds, Inbound};

fn load(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing fixture {path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("invalid JSON in {path}: {e}"))
}

const ARBITRARY_WATCHED: &str = "So11111111111111111111111111111111111111112";

fn parse_all_with(fixture: &str, watched: &str, include_transfers: bool) -> Vec<Inbound> {
    let value = load(fixture);
    extract_inbounds(&value, "fixture-sig", watched, include_transfers, None)
}

#[test]
fn real_meteora_dlmm_tx_parses_without_panic() {
    // Not watched by our channel, so we should get zero events but no crash.
    let events = parse_all_with("real_meteora_dlmm.json", ARBITRARY_WATCHED, true);
    assert!(
        events.is_empty(),
        "unexpected events on unwatched address: {events:?}"
    );
}

#[test]
fn real_meteora_dlmm_watched_as_fee_payer_yields_no_memo_events() {
    // The fee-payer is a real address in this fixture. Confirm the parser
    // returns 0 memo events (this tx has none) even when the watched
    // address is a live participant.
    let events = parse_all_with(
        "real_meteora_dlmm.json",
        "A7FMMgue4aZmPLLoutVtbC7gJcyqkHybUieiaDg9aaVE",
        false,
    );
    assert!(
        events.iter().all(|e| !e.content.starts_with("[memo")),
        "unexpected memo events in tx that has none: {events:?}"
    );
}

#[test]
fn real_usdc_activity_dense_token_balances_do_not_panic() {
    // preTokenBalances/postTokenBalances has 9 entries; owner filter should
    // reject all of them against our arbitrary unrelated watched address.
    let events = parse_all_with("real_usdc_activity.json", ARBITRARY_WATCHED, true);
    assert!(events.is_empty());
}

#[test]
fn real_custom_program_parses_without_panic() {
    let events = parse_all_with("real_custom_program.json", ARBITRARY_WATCHED, true);
    assert!(events.is_empty());
}

#[test]
fn real_durable_nonce_with_lut_parses_without_panic() {
    // Versioned tx with address lookup tables and durable-nonce advance
    // — the historically breakage-prone combination.
    let events = parse_all_with("real_durable_nonce_lut.json", ARBITRARY_WATCHED, true);
    assert!(events.is_empty());
}

#[test]
fn every_real_fixture_extracts_fee_payer_from_object_shape() {
    // `encoding: "jsonParsed"` returns accountKeys as objects
    // `{pubkey, signer, writable, source}`, not bare strings. Confirm
    // the parser handles both by checking that the fee-payer address
    // makes it into the `sender` field when a synthetic memo is grafted
    // onto each real fixture.
    for fixture in [
        "real_meteora_dlmm.json",
        "real_usdc_activity.json",
        "real_custom_program.json",
        "real_durable_nonce_lut.json",
    ] {
        let mut value = load(fixture);
        // Graft a top-level memo instruction so we have something to
        // attribute; leaves the accountKeys shape untouched.
        let synthetic_memo = serde_json::json!({
            "program": "spl-memo",
            "programId": solana_inbox::core::SPL_MEMO_V2,
            "parsed": "grafted memo"
        });
        value["result"]["transaction"]["message"]["instructions"]
            .as_array_mut()
            .expect("instructions array present")
            .push(synthetic_memo);

        let events = extract_inbounds(&value, "graft", ARBITRARY_WATCHED, false, None);
        assert_eq!(events.len(), 1, "fixture {fixture} did not yield the grafted memo");
        assert!(
            !events[0].sender.is_empty() && events[0].sender != "unknown",
            "fixture {fixture} failed to extract a fee-payer from object-shaped accountKeys: sender={:?}",
            events[0].sender
        );
    }
}
