//! One integration test that proves this crate is standalone-usable
//! (i.e. imports resolve without the consuming plugin's shim in the
//! path). Any regression in the public API surface fails to compile.

use serde_json::json;

use solana_inbox_core::{extract_inbounds, parse_signatures_response, Config, SPL_MEMO_V2};

#[test]
fn crate_is_standalone_usable_end_to_end() {
    let cfg = Config::from_json(
        &json!({
            "rpc_url": "https://example.com",
            "watched_address": "So11111111111111111111111111111111111111112"
        })
        .to_string(),
    )
    .expect("config parses");
    assert!(cfg.include_transfers);

    let sigs = parse_signatures_response(&json!({
        "result": [
            {"signature": "n2", "slot": 200, "err": null, "blockTime": 2},
            {"signature": "n1", "slot": 100, "err": null, "blockTime": 1}
        ]
    }));
    assert_eq!(sigs.len(), 2);
    assert_eq!(sigs[0].signature, "n1");
    assert_eq!(sigs[1].signature, "n2");

    let tx = json!({
        "result": {
            "blockTime": 3i64,
            "meta": {"preBalances": [], "postBalances": [], "preTokenBalances": [], "postTokenBalances": [], "innerInstructions": []},
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": "Sender11111111111111111111111111111111111111", "signer": true, "writable": true, "source": "transaction"}],
                    "instructions": [
                        {"program": "spl-memo", "programId": SPL_MEMO_V2, "parsed": "hello standalone"}
                    ]
                }
            }
        }
    });
    let events = extract_inbounds(&tx, "sigX", &cfg.watched_address, false, None);
    assert_eq!(events.len(), 1);
    assert!(events[0].content.contains("hello standalone"));
}
