//! Host-run integration tests for the `solana-inbox` pure core.
//!
//! Every test drives the exact same functions the wasm `poll_message`
//! entry point calls in `lib.rs::refill_from_rpc`. Fixtures are hand-built
//! from Solana's documented `getSignaturesForAddress` and `getTransaction`
//! (`encoding: "jsonParsed"`) response shapes so we never depend on live
//! RPC or on any Solana crate.

use serde_json::{json, Value};

use solana_inbox::core::{
    extract_inbounds, parse_signatures_response, Config, Inbound, SPL_MEMO_V1, SPL_MEMO_V2,
};

const WATCHED: &str = "So11111111111111111111111111111111111111112";
const SENDER: &str = "9aB1QqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaB";
const SIG: &str = "5t3ExAmpLe8YeEexAmpLeSignaturE9yYbcExAmpLe";

// ── config ───────────────────────────────────────────────────────────────

#[test]
fn config_parses_full_body() {
    let cfg = Config::from_json(
        &json!({
            "rpc_url": "https://example.com",
            "watched_address": WATCHED,
            "commitment": "processed",
            "max_sigs_per_poll": 50,
            "include_transfers": false
        })
        .to_string(),
    )
    .expect("well-formed config parses");
    assert_eq!(cfg.rpc_url, "https://example.com");
    assert_eq!(cfg.watched_address, WATCHED);
    assert_eq!(cfg.commitment, "processed");
    assert_eq!(cfg.max_sigs_per_poll, 50);
    assert!(!cfg.include_transfers);
}

#[test]
fn config_defaults_when_optional_fields_absent() {
    let cfg = Config::from_json(
        &json!({
            "rpc_url": "https://example.com",
            "watched_address": WATCHED
        })
        .to_string(),
    )
    .expect("minimal config parses");
    assert_eq!(cfg.commitment, "confirmed");
    assert_eq!(cfg.max_sigs_per_poll, 20);
    assert!(cfg.include_transfers);
}

#[test]
fn config_rejects_unknown_key_fail_closed() {
    // The reviewer's public guidance on PR #25: fail-closed on typos so
    // `max_amout` can't silently bypass a `max_amount` cap.
    let err = Config::from_json(
        &json!({
            "rpc_url": "https://example.com",
            "watched_address": WATCHED,
            "rpc_urll": "https://mistyped.example.com"
        })
        .to_string(),
    )
    .unwrap_err();
    assert!(err.contains("invalid channel config JSON"), "unexpected: {err}");
}

#[test]
fn config_rejects_missing_watched_address() {
    let err = Config::from_json(&json!({"rpc_url": "https://example.com"}).to_string()).unwrap_err();
    assert!(err.contains("watched_address"));
}

#[test]
fn config_rejects_bad_commitment() {
    let err = Config::from_json(
        &json!({
            "rpc_url": "https://example.com",
            "watched_address": WATCHED,
            "commitment": "eventually"
        })
        .to_string(),
    )
    .unwrap_err();
    assert!(err.contains("processed|confirmed|finalized"));
}

#[test]
fn config_rejects_bad_max_sigs() {
    let err = Config::from_json(
        &json!({
            "rpc_url": "https://example.com",
            "watched_address": WATCHED,
            "max_sigs_per_poll": 0
        })
        .to_string(),
    )
    .unwrap_err();
    assert!(err.contains("1..=100"));
}

#[test]
fn config_rejects_implausible_pubkey() {
    let err = Config::from_json(
        &json!({
            "rpc_url": "https://example.com",
            "watched_address": "not-a-pubkey"
        })
        .to_string(),
    )
    .unwrap_err();
    assert!(err.contains("plausible base58 Solana pubkey"));
}

#[test]
fn config_rejects_empty_object() {
    let err = Config::from_json("{}").unwrap_err();
    assert!(err.contains("watched_address"), "unexpected: {err}");
}

// ── getSignaturesForAddress parsing ──────────────────────────────────────

#[test]
fn signatures_response_reversed_to_chronological() {
    // RPC returns newest-first; the agent should see events in chronological
    // order, so parse_signatures_response reverses.
    let resp = json!({
        "result": [
            {"signature": "newest", "slot": 300, "err": null, "blockTime": 3},
            {"signature": "middle", "slot": 200, "err": null, "blockTime": 2},
            {"signature": "oldest", "slot": 100, "err": null, "blockTime": 1}
        ]
    });
    let sigs = parse_signatures_response(&resp);
    let ids: Vec<&str> = sigs.iter().map(|s| s.signature.as_str()).collect();
    assert_eq!(ids, vec!["oldest", "middle", "newest"]);
}

#[test]
fn signatures_response_drops_failed_transactions() {
    // Solana RPC returns newest-first. Our parser reverses to chronological.
    let resp = json!({
        "result": [
            {"signature": "good2", "slot": 102, "err": null},
            {"signature": "bad", "slot": 101, "err": {"InstructionError": [0, "Custom"]}},
            {"signature": "good1", "slot": 100, "err": null}
        ]
    });
    let sigs = parse_signatures_response(&resp);
    let ids: Vec<&str> = sigs.iter().map(|s| s.signature.as_str()).collect();
    assert_eq!(ids, vec!["good1", "good2"]);
}

#[test]
fn signatures_response_missing_or_empty_is_safe() {
    assert!(parse_signatures_response(&json!({})).is_empty());
    assert!(parse_signatures_response(&json!({"result": []})).is_empty());
    assert!(parse_signatures_response(&json!({"result": null})).is_empty());
}

// ── memo extraction ─────────────────────────────────────────────────────

fn tx_with_toplevel_memo(memo_program: &str, memo_text: &str) -> Value {
    json!({
        "result": {
            "blockTime": 1_700_000_000_i64,
            "meta": {
                "preBalances": [1_000_000_000_u64],
                "postBalances": [999_995_000_u64],
                "preTokenBalances": [],
                "postTokenBalances": [],
                "innerInstructions": []
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": SENDER, "signer": true, "writable": true, "source": "transaction"},
                        {"pubkey": WATCHED, "signer": false, "writable": false, "source": "transaction"},
                        {"pubkey": memo_program, "signer": false, "writable": false, "source": "transaction"}
                    ],
                    "instructions": [
                        {
                            "program": "spl-memo",
                            "programId": memo_program,
                            "parsed": memo_text
                        }
                    ]
                }
            }
        }
    })
}

#[test]
fn extracts_toplevel_memo_v2() {
    let tx = tx_with_toplevel_memo(SPL_MEMO_V2, "hello from chain");
    let events = extract_inbounds(&tx, SIG, WATCHED, true, None);
    let memos: Vec<&Inbound> = events
        .iter()
        .filter(|e| e.content.starts_with("[memo"))
        .collect();
    assert_eq!(memos.len(), 1);
    assert!(memos[0].content.contains("hello from chain"));
    assert_eq!(memos[0].sender, SENDER);
    assert_eq!(memos[0].reply_target, SENDER);
    assert_eq!(memos[0].timestamp_ms, 1_700_000_000_000);
}

#[test]
fn extracts_toplevel_memo_v1() {
    let tx = tx_with_toplevel_memo(SPL_MEMO_V1, "legacy memo");
    let events = extract_inbounds(&tx, SIG, WATCHED, false, None);
    assert_eq!(events.len(), 1);
    assert!(events[0].content.contains("legacy memo"));
}

#[test]
fn ignores_non_memo_program_instructions() {
    let tx = json!({
        "result": {
            "blockTime": 1,
            "meta": {"preBalances": [], "postBalances": [], "preTokenBalances": [], "postTokenBalances": [], "innerInstructions": []},
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": SENDER, "signer": true, "writable": true, "source": "transaction"}],
                    "instructions": [
                        {"program": "system", "programId": "11111111111111111111111111111111", "parsed": {"info": {}, "type": "transfer"}}
                    ]
                }
            }
        }
    });
    let events = extract_inbounds(&tx, SIG, WATCHED, false, None);
    assert!(events.is_empty());
}

#[test]
fn extracts_inner_instruction_memo() {
    let tx = json!({
        "result": {
            "blockTime": 1_700_000_100,
            "meta": {
                "preBalances": [], "postBalances": [],
                "preTokenBalances": [], "postTokenBalances": [],
                "innerInstructions": [{
                    "index": 0,
                    "instructions": [
                        {"program": "spl-memo", "programId": SPL_MEMO_V2, "parsed": "wrapped by Jupiter"}
                    ]
                }]
            },
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": SENDER, "signer": true, "writable": true, "source": "transaction"}],
                    "instructions": [
                        {"program": "system", "programId": "11111111111111111111111111111111", "parsed": {}}
                    ]
                }
            }
        }
    });
    let events = extract_inbounds(&tx, SIG, WATCHED, false, None);
    assert_eq!(events.len(), 1);
    assert!(events[0].content.contains("wrapped by Jupiter"));
}

#[test]
fn multiple_distinct_memos_all_delivered() {
    let tx = json!({
        "result": {
            "blockTime": 1,
            "meta": {"preBalances": [], "postBalances": [], "preTokenBalances": [], "postTokenBalances": [], "innerInstructions": []},
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": SENDER, "signer": true, "writable": true, "source": "transaction"}],
                    "instructions": [
                        {"program": "spl-memo", "programId": SPL_MEMO_V2, "parsed": "first"},
                        {"program": "spl-memo", "programId": SPL_MEMO_V2, "parsed": "second"}
                    ]
                }
            }
        }
    });
    let events = extract_inbounds(&tx, SIG, WATCHED, false, None);
    assert_eq!(events.len(), 2);
}

#[test]
fn duplicate_memos_deduplicated_in_one_tx() {
    let tx = json!({
        "result": {
            "blockTime": 1,
            "meta": {"preBalances": [], "postBalances": [], "preTokenBalances": [], "postTokenBalances": [], "innerInstructions": []},
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": SENDER, "signer": true, "writable": true, "source": "transaction"}],
                    "instructions": [
                        {"program": "spl-memo", "programId": SPL_MEMO_V2, "parsed": "duplicate"},
                        {"program": "spl-memo", "programId": SPL_MEMO_V2, "parsed": "duplicate"}
                    ]
                }
            }
        }
    });
    let events = extract_inbounds(&tx, SIG, WATCHED, false, None);
    assert_eq!(events.len(), 1);
}

#[test]
fn oversized_memo_is_truncated_not_dropped() {
    let long: String = "A".repeat(1000);
    let tx = tx_with_toplevel_memo(SPL_MEMO_V2, &long);
    let events = extract_inbounds(&tx, SIG, WATCHED, false, None);
    assert_eq!(events.len(), 1);
    assert!(events[0].content.contains("[truncated at 512 bytes]"));
    // Original memo was 1000 A's; content includes a prefix and the truncated
    // suffix, but no full 1000-char run of A's should survive.
    assert!(!events[0].content.contains(&"A".repeat(600)));
}

// ── transfer extraction ─────────────────────────────────────────────────

#[test]
fn extracts_incoming_sol_transfer() {
    let tx = json!({
        "result": {
            "blockTime": 1,
            "meta": {
                "preBalances":  [10_000_000_000_u64, 5_000_000_000_u64],
                "postBalances": [ 8_999_995_000_u64, 6_000_000_000_u64],
                "preTokenBalances": [],
                "postTokenBalances": [],
                "innerInstructions": []
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": SENDER, "signer": true, "writable": true, "source": "transaction"},
                        {"pubkey": WATCHED, "signer": false, "writable": true, "source": "transaction"}
                    ],
                    "instructions": []
                }
            }
        }
    });
    let events = extract_inbounds(&tx, SIG, WATCHED, true, None);
    let transfers: Vec<&Inbound> = events
        .iter()
        .filter(|e| e.content.contains("SOL"))
        .collect();
    assert_eq!(transfers.len(), 1);
    assert!(transfers[0].content.contains("SOL"));
    assert!(transfers[0].content.contains("[+1 SOL]"), "content was: {}", transfers[0].content);
    assert_eq!(transfers[0].sender, SENDER);
}

#[test]
fn include_transfers_false_suppresses_transfers_but_keeps_memos() {
    let tx = json!({
        "result": {
            "blockTime": 1,
            "meta": {
                "preBalances":  [10_000_000_000_u64, 5_000_000_000_u64],
                "postBalances": [ 8_999_995_000_u64, 6_000_000_000_u64],
                "preTokenBalances": [],
                "postTokenBalances": [],
                "innerInstructions": []
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": SENDER, "signer": true, "writable": true, "source": "transaction"},
                        {"pubkey": WATCHED, "signer": false, "writable": true, "source": "transaction"},
                        {"pubkey": SPL_MEMO_V2, "signer": false, "writable": false, "source": "transaction"}
                    ],
                    "instructions": [
                        {"program": "spl-memo", "programId": SPL_MEMO_V2, "parsed": "note"}
                    ]
                }
            }
        }
    });
    let events = extract_inbounds(&tx, SIG, WATCHED, false, None);
    assert_eq!(events.len(), 1);
    assert!(events[0].content.starts_with("[memo"));
}

#[test]
fn extracts_incoming_spl_transfer_direct_wallet_to_wallet() {
    // The classic case: Alice's ATA (source) fell by 25 USDC, Bob's ATA
    // (destination, our watched owner) rose by 25 USDC. `infer_spl_sender`
    // sees exactly one source with a matching delta and surfaces Alice
    // as the sender — not the fee-payer, not "unknown".
    let alice = "AliceOwner11111111111111111111111111111111";
    let usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let tx = json!({
        "result": {
            "blockTime": 1,
            "meta": {
                "preBalances":  [10_000_000_000_u64],
                "postBalances": [ 9_999_995_000_u64],
                "preTokenBalances": [
                    {
                        "accountIndex": 1,
                        "mint": usdc_mint,
                        "owner": alice,
                        "uiTokenAmount": {"amount": "1000000000", "decimals": 6}
                    },
                    {
                        "accountIndex": 2,
                        "mint": usdc_mint,
                        "owner": WATCHED,
                        "uiTokenAmount": {"amount": "100000000", "decimals": 6}
                    }
                ],
                "postTokenBalances": [
                    {
                        "accountIndex": 1,
                        "mint": usdc_mint,
                        "owner": alice,
                        "uiTokenAmount": {"amount": "975000000", "decimals": 6}
                    },
                    {
                        "accountIndex": 2,
                        "mint": usdc_mint,
                        "owner": WATCHED,
                        "uiTokenAmount": {"amount": "125000000", "decimals": 6}
                    }
                ],
                "innerInstructions": []
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": SENDER, "signer": true, "writable": true, "source": "transaction"},
                        {"pubkey": "AliceATA1111111111111111111111111111111111", "signer": false, "writable": true, "source": "transaction"},
                        {"pubkey": "WatchedATA111111111111111111111111111111111", "signer": false, "writable": true, "source": "transaction"}
                    ],
                    "instructions": []
                }
            }
        }
    });
    let events = extract_inbounds(&tx, SIG, WATCHED, true, None);
    let spl = events
        .iter()
        .find(|e| e.content.contains("mint EPjF"))
        .expect("expected SPL transfer event");
    assert!(spl.content.contains("[+25 mint EPjF"), "content was: {}", spl.content);
    assert_eq!(spl.sender, alice, "sender should be Alice (source ATA owner), not fee-payer");
}

#[test]
fn spl_swap_style_missing_source_reports_unknown_sender() {
    // A Jupiter/Meteora swap: the source ATA is not present in
    // preTokenBalances (or its owner is a pool account we don't want
    // to name). The correct answer is "unknown" — never a false
    // fee-payer attribution.
    let usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let tx = json!({
        "result": {
            "blockTime": 1,
            "meta": {
                "preBalances":  [10_000_000_000_u64],
                "postBalances": [ 9_999_995_000_u64],
                "preTokenBalances": [{
                    "accountIndex": 1,
                    "mint": usdc_mint,
                    "owner": WATCHED,
                    "uiTokenAmount": {"amount": "100000000", "decimals": 6}
                }],
                "postTokenBalances": [{
                    "accountIndex": 1,
                    "mint": usdc_mint,
                    "owner": WATCHED,
                    "uiTokenAmount": {"amount": "125000000", "decimals": 6}
                }],
                "innerInstructions": []
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": SENDER, "signer": true, "writable": true, "source": "transaction"},
                        {"pubkey": "WatchedATA111111111111111111111111111111111", "signer": false, "writable": true, "source": "transaction"}
                    ],
                    "instructions": []
                }
            }
        }
    });
    let events = extract_inbounds(&tx, SIG, WATCHED, true, None);
    let spl = events
        .iter()
        .find(|e| e.content.contains("mint EPjF"))
        .expect("expected SPL transfer event");
    assert_eq!(
        spl.sender, "unknown",
        "swap-style transfers with no matching source ATA must NOT falsely attribute to fee-payer; got: {}",
        spl.sender
    );
}

#[test]
fn spl_multi_source_aggregation_reports_unknown_sender() {
    // Two different sources both drained partial amounts that sum to
    // the watched credit. There is no unique sender, so `unknown` is
    // the honest answer.
    let alice = "AliceOwner11111111111111111111111111111111";
    let bob = "BobOwner1111111111111111111111111111111111";
    let usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let tx = json!({
        "result": {
            "blockTime": 1,
            "meta": {
                "preBalances":  [10_000_000_000_u64],
                "postBalances": [ 9_999_995_000_u64],
                "preTokenBalances": [
                    {"accountIndex": 1, "mint": usdc_mint, "owner": alice, "uiTokenAmount": {"amount": "1000000000", "decimals": 6}},
                    {"accountIndex": 2, "mint": usdc_mint, "owner": bob, "uiTokenAmount": {"amount": "1000000000", "decimals": 6}},
                    {"accountIndex": 3, "mint": usdc_mint, "owner": WATCHED, "uiTokenAmount": {"amount": "0", "decimals": 6}}
                ],
                "postTokenBalances": [
                    {"accountIndex": 1, "mint": usdc_mint, "owner": alice, "uiTokenAmount": {"amount": "990000000", "decimals": 6}},
                    {"accountIndex": 2, "mint": usdc_mint, "owner": bob, "uiTokenAmount": {"amount": "985000000", "decimals": 6}},
                    {"accountIndex": 3, "mint": usdc_mint, "owner": WATCHED, "uiTokenAmount": {"amount": "25000000", "decimals": 6}}
                ],
                "innerInstructions": []
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": SENDER, "signer": true, "writable": true, "source": "transaction"},
                        {"pubkey": "A1", "signer": false, "writable": true, "source": "transaction"},
                        {"pubkey": "A2", "signer": false, "writable": true, "source": "transaction"},
                        {"pubkey": "A3", "signer": false, "writable": true, "source": "transaction"}
                    ],
                    "instructions": []
                }
            }
        }
    });
    let events = extract_inbounds(&tx, SIG, WATCHED, true, None);
    let spl = events
        .iter()
        .find(|e| e.content.contains("mint EPjF"))
        .expect("expected SPL transfer event");
    // Neither source's individual delta equals the +25 credit (10 + 15).
    // The plugin correctly refuses to name one.
    assert_eq!(spl.sender, "unknown", "got: {}", spl.sender);
}

#[test]
fn spl_transfer_ignored_when_owner_is_not_watched() {
    let usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let someone_else = "OtherOwner11111111111111111111111111111111";
    let tx = json!({
        "result": {
            "blockTime": 1,
            "meta": {
                "preBalances":  [10_000_000_000_u64],
                "postBalances": [ 9_999_995_000_u64],
                "preTokenBalances": [{
                    "accountIndex": 1,
                    "mint": usdc_mint,
                    "owner": someone_else,
                    "uiTokenAmount": {"amount": "0", "decimals": 6}
                }],
                "postTokenBalances": [{
                    "accountIndex": 1,
                    "mint": usdc_mint,
                    "owner": someone_else,
                    "uiTokenAmount": {"amount": "1000000", "decimals": 6}
                }],
                "innerInstructions": []
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": SENDER, "signer": true, "writable": true, "source": "transaction"},
                        {"pubkey": "ATA11111111111111111111111111111111111111111", "signer": false, "writable": true, "source": "transaction"}
                    ],
                    "instructions": []
                }
            }
        }
    });
    let events = extract_inbounds(&tx, SIG, WATCHED, true, None);
    assert!(
        events.is_empty(),
        "no events should fire when the transfer goes to a different owner"
    );
}

// ── robustness ──────────────────────────────────────────────────────────

#[test]
fn missing_meta_yields_no_events_no_crash() {
    let tx = json!({
        "result": {
            "blockTime": 1,
            "transaction": {"message": {"accountKeys": [], "instructions": []}}
        }
    });
    let events = extract_inbounds(&tx, SIG, WATCHED, true, None);
    assert!(events.is_empty());
}

#[test]
fn null_result_yields_no_events() {
    let events = extract_inbounds(&json!({"result": null}), SIG, WATCHED, true, None);
    assert!(events.is_empty());
}

#[test]
fn block_time_fallback_used_when_tx_has_none() {
    let mut tx = tx_with_toplevel_memo(SPL_MEMO_V2, "no blockTime");
    tx["result"]["blockTime"] = json!(null);
    let events = extract_inbounds(&tx, SIG, WATCHED, false, Some(42));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].timestamp_ms, 42_000);
}
