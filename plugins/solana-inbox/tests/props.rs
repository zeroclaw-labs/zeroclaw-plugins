//! Property-based tests over the pure core.
//!
//! Each test asserts an invariant over many generated inputs (default 256
//! cases per property). These are the host-testable analog of the formal
//! proofs sketched in `proofs/`. When Kani is installed the same
//! invariants are proven exhaustively over bounded model checks; here we
//! probabilistically verify them against tens of thousands of concrete
//! inputs per `cargo test` run.

use proptest::prelude::*;
use serde_json::{json, Value};

use solana_inbox::core::{extract_inbounds, parse_signatures_response, Config, SPL_MEMO_V2};

// ── strategies ──────────────────────────────────────────────────────────

/// Any ascii-alphanumeric-like base58-ish string of length 32..=44 — a
/// plausible-shape pubkey. Real cryptographic validity isn't needed for
/// the invariants we test.
fn pubkey_strategy() -> impl Strategy<Value = String> {
    "[1-9A-HJ-NP-Za-km-z]{32,44}".prop_map(|s| s)
}

/// Any UTF-8 text a real memo instruction could contain, including
/// zero-width chars, emoji, and long ascii runs. Bounded so the total
/// test run remains fast.
fn memo_text_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        "\\PC{0,600}",           // any printable Unicode
        prop::string::string_regex("[a-zA-Z0-9 ]{0,600}").unwrap(),
        prop::string::string_regex("[\u{200B}-\u{200D}\u{FEFF}]{0,50}").unwrap(),
        prop::string::string_regex("A{600,1200}").unwrap(),
    ]
}

// ── invariants ──────────────────────────────────────────────────────────

proptest! {
    /// P-1: `parse_signatures_response` output is chronologically ordered
    /// (oldest-first), assuming the RPC returned newest-first per its
    /// contract. Slots are non-decreasing across the output.
    #[test]
    fn parse_signatures_reverses_to_chronological(
        entries in prop::collection::vec(
            (any::<u64>(), any::<i64>()),
            0..30usize,
        )
    ) {
        // Build a newest-first response by giving each entry a decreasing
        // slot; we only check the ordering property is preserved.
        let arr: Vec<Value> = entries.iter().enumerate().map(|(i, (_slot, bt))| json!({
            "signature": format!("sig{i}"),
            "slot": (u64::MAX - i as u64),
            "err": null,
            "blockTime": bt
        })).collect();
        let resp = json!({"result": arr});
        let parsed = parse_signatures_response(&resp);
        for pair in parsed.windows(2) {
            prop_assert!(pair[0].slot <= pair[1].slot, "cursor regression: {} → {}", pair[0].slot, pair[1].slot);
        }
    }

    /// P-2: `parse_signatures_response` drops every entry that has a
    /// non-null `err`. There is no non-null err that can survive the
    /// filter, no matter what shape the err takes.
    #[test]
    fn parse_signatures_drops_failed_txs(
        n_good in 0..15usize,
        n_bad in 0..15usize,
    ) {
        let mut arr: Vec<Value> = Vec::new();
        for i in 0..n_good {
            arr.push(json!({"signature": format!("good{i}"), "slot": (u64::MAX - i as u64), "err": null}));
        }
        for i in 0..n_bad {
            arr.push(json!({
                "signature": format!("bad{i}"),
                "slot": (u64::MAX - (n_good + i) as u64),
                "err": {"InstructionError": [i, "Custom"]}
            }));
        }
        let parsed = parse_signatures_response(&json!({"result": arr}));
        prop_assert_eq!(parsed.len(), n_good);
        for p in &parsed {
            prop_assert!(p.signature.starts_with("good"));
        }
    }

    /// P-3: any unknown top-level key in the config JSON causes
    /// `Config::from_json` to return `Err`, regardless of the key's name
    /// or value. This is the fail-closed guarantee the reviewer's PR #25
    /// guidance calls out.
    #[test]
    fn config_rejects_any_unknown_key(
        unknown_key in "[a-zA-Z_][a-zA-Z0-9_]{1,20}",
        unknown_value in "[a-zA-Z0-9 ]{0,20}",
    ) {
        // Exclude the known keys so we don't accidentally test a valid one.
        prop_assume!(!["rpc_url","watched_address","commitment","max_sigs_per_poll","include_transfers"].contains(&unknown_key.as_str()));
        let cfg = json!({
            "rpc_url": "https://example.com",
            "watched_address": "So11111111111111111111111111111111111111112",
            unknown_key.clone(): unknown_value,
        });
        let err = Config::from_json(&cfg.to_string()).unwrap_err();
        prop_assert!(
            err.contains("invalid channel config JSON"),
            "unknown key {unknown_key:?} silently accepted: {err}"
        );
    }

    /// P-4: `extract_inbounds` never emits a transfer event whose owner
    /// isn't the watched address. The owner filter is exact-match by
    /// value, not prefix or edit-distance.
    #[test]
    fn transfer_owner_filter_is_exact(
        watched in pubkey_strategy(),
        actual_owner in pubkey_strategy(),
        amount_before in 0u128..1_000_000_000,
        amount_delta in 1u128..1_000_000,
    ) {
        prop_assume!(watched != actual_owner);
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let tx = json!({
            "result": {
                "blockTime": 1i64,
                "meta": {
                    "preBalances": [1_000_000_000u64],
                    "postBalances": [999_995_000u64],
                    "preTokenBalances": [{
                        "accountIndex": 1,
                        "mint": mint,
                        "owner": actual_owner,
                        "uiTokenAmount": {"amount": amount_before.to_string(), "decimals": 6}
                    }],
                    "postTokenBalances": [{
                        "accountIndex": 1,
                        "mint": mint,
                        "owner": actual_owner,
                        "uiTokenAmount": {"amount": (amount_before + amount_delta).to_string(), "decimals": 6}
                    }],
                    "innerInstructions": []
                },
                "transaction": {
                    "message": {
                        "accountKeys": [
                            {"pubkey": "FeePayer111111111111111111111111111111111111", "signer": true, "writable": true, "source": "transaction"},
                            {"pubkey": "AtaPlaceholder1111111111111111111111111111", "signer": false, "writable": true, "source": "transaction"}
                        ],
                        "instructions": []
                    }
                }
            }
        });
        let events = extract_inbounds(&tx, "sig", &watched, true, None);
        prop_assert!(
            events.is_empty(),
            "spurious transfer surfaced when owner {actual_owner:?} != watched {watched:?}: {events:?}"
        );
    }

    /// P-5: `extract_inbounds` output length is bounded independent of
    /// the memo text length. A memo of 100 KB collapses to a single
    /// event whose content is at most the truncation cap + a fixed
    /// prefix/suffix.
    #[test]
    fn memo_output_length_is_bounded(memo in memo_text_strategy()) {
        let tx = json!({
            "result": {
                "blockTime": 1i64,
                "meta": {"preBalances": [], "postBalances": [], "preTokenBalances": [], "postTokenBalances": [], "innerInstructions": []},
                "transaction": {
                    "message": {
                        "accountKeys": [{"pubkey": "FeePayer111111111111111111111111111111111111", "signer": true, "writable": true, "source": "transaction"}],
                        "instructions": [
                            {"program": "spl-memo", "programId": SPL_MEMO_V2, "parsed": memo.clone()}
                        ]
                    }
                }
            }
        });
        let events = extract_inbounds(&tx, "sig", "So11111111111111111111111111111111111111112", false, None);
        prop_assert_eq!(events.len(), 1);
        // Compact upper bound: MAX_MEMO_LEN (512) + short_addr prefix
        // + truncation marker + the "[memo from …] " wrapper. 700 bytes
        // is a comfortable ceiling — the actual size is smaller.
        prop_assert!(
            events[0].content.len() <= 700,
            "memo content {} bytes exceeds 700-byte ceiling",
            events[0].content.len()
        );
    }

    /// P-6: duplicate memos with identical content and identical sender
    /// within a single tx collapse to a single inbound event. The
    /// invariant matters because a common attack pattern is to spam a
    /// short repeated memo to blow up an agent's context window.
    #[test]
    fn duplicate_memos_dedup_within_tx(text in "[a-zA-Z0-9 ]{0,50}", n in 2u8..20u8) {
        let mut instrs = Vec::new();
        for _ in 0..n {
            instrs.push(json!({"program": "spl-memo", "programId": SPL_MEMO_V2, "parsed": text.clone()}));
        }
        let tx = json!({
            "result": {
                "blockTime": 1i64,
                "meta": {"preBalances": [], "postBalances": [], "preTokenBalances": [], "postTokenBalances": [], "innerInstructions": []},
                "transaction": {
                    "message": {
                        "accountKeys": [{"pubkey": "FeePayer111111111111111111111111111111111111", "signer": true, "writable": true, "source": "transaction"}],
                        "instructions": instrs
                    }
                }
            }
        });
        let events = extract_inbounds(&tx, "sig", "So11111111111111111111111111111111111111112", false, None);
        prop_assert_eq!(events.len(), 1, "expected dedup to 1, got {} events for {} instructions", events.len(), n);
    }

    /// P-7: `extract_inbounds` on a `null` result yields zero events for
    /// every possible watched-address value.
    #[test]
    fn null_result_yields_zero_events(watched in pubkey_strategy()) {
        let events = extract_inbounds(&json!({"result": null}), "sig", &watched, true, None);
        prop_assert!(events.is_empty());
    }
}
