use std::collections::HashMap;

use depin_uptime_watch::keys::Pubkey;
use depin_uptime_watch::rpc::HttpClient;
use depin_uptime_watch::watch::{execute, Verdict};
use depin_uptime_watch::{CoreError, CoreResult};
use serde_json::{json, Value};

const RPC_URL: &str = "https://rpc.test";
const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

#[derive(Default)]
struct MapHttp {
    responses: HashMap<String, Value>,
}

impl MapHttp {
    fn with_response(mut self, body: Value, response: Value) -> Self {
        self.responses.insert(fingerprint(RPC_URL, &body), response);
        self
    }
}

impl HttpClient for MapHttp {
    fn post_json(&self, url: &str, body: &Value) -> CoreResult<Value> {
        self.responses
            .get(&fingerprint(url, body))
            .cloned()
            .ok_or_else(|| CoreError::msg(format!("missing mock response for {url}: {body}")))
    }
}

fn fingerprint(url: &str, body: &Value) -> String {
    format!("{url}\n{body}")
}

fn payer() -> Pubkey {
    Pubkey::new([1u8; 32])
}

fn config() -> HashMap<String, String> {
    HashMap::from([
        ("rpc_url".to_string(), RPC_URL.to_string()),
        ("payer".to_string(), payer().to_base58()),
    ])
}

fn signatures_body(limit: usize) -> Value {
    signatures_body_before(limit, None)
}

fn signatures_body_before(limit: usize, before: Option<&str>) -> Value {
    let mut options = json!({ "limit": limit });
    if let Some(before) = before {
        options
            .as_object_mut()
            .unwrap()
            .insert("before".to_string(), json!(before));
    }
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [
            payer().to_base58(),
            options
        ]
    })
}

fn transaction_body(signature: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            { "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0 }
        ]
    })
}

fn signatures_response(entries: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": entries
    })
}

fn transaction_response(block_time: u64, memo: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "blockTime": block_time,
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "programId": MEMO_PROGRAM,
                            "parsed": memo
                        }
                    ]
                }
            }
        }
    })
}

#[test]
fn returns_ok_for_matching_recent_attestation() {
    let http = MapHttp::default()
        .with_response(
            signatures_body(25),
            signatures_response(json!([
                {"signature": "sig-new", "blockTime": 1_720_000_000, "err": null}
            ])),
        )
        .with_response(
            transaction_body("sig-new"),
            transaction_response(
                1_720_000_000,
                "ZCDEPIN|device-7|uptime|42|seconds|5733333|abc123def456",
            ),
        );

    let output = execute(
        r#"{"device_id":"device-7","max_age_secs":120}"#,
        &config(),
        &http,
        1_720_000_060,
    )
    .expect("watch execute");

    assert_eq!(output.verdict, Verdict::Ok);
    assert_eq!(output.age_secs, Some(60));
    assert!(output.summary.contains("Uptime OK"));
    assert!(output.summary.contains("device-7"));
    assert!(output.summary.contains("🟢"));
}

#[test]
fn returns_stale_for_matching_old_attestation() {
    let http = MapHttp::default()
        .with_response(
            signatures_body(25),
            signatures_response(json!([
                {"signature": "sig-old", "blockTime": 1_720_000_000, "err": null}
            ])),
        )
        .with_response(
            transaction_body("sig-old"),
            transaction_response(
                1_720_000_000,
                "ZCDEPIN|device-7|uptime|42|seconds|5733333|abc123def456",
            ),
        );

    let output = execute(
        r#"{"device_id":"device-7","max_age_secs":30}"#,
        &config(),
        &http,
        1_720_000_060,
    )
    .expect("watch execute");

    assert_eq!(output.verdict, Verdict::Stale);
    assert_eq!(output.age_secs, Some(60));
    assert!(output.summary.contains("Uptime STALE"));
}

#[test]
fn returns_missing_when_no_matching_memo_is_found() {
    let http = MapHttp::default()
        .with_response(
            signatures_body(25),
            signatures_response(json!([
                {"signature": "sig-failed", "blockTime": 1_720_000_010, "err": {"InstructionError": [0, "Custom"]}},
                {"signature": "sig-other", "blockTime": 1_720_000_000, "err": null}
            ])),
        )
        .with_response(
            transaction_body("sig-other"),
            transaction_response(
                1_720_000_000,
                "ZCDEPIN|device-8|uptime|42|seconds|5733333|abc123def456",
            ),
        );

    let output = execute(
        r#"{"device_id":"device-7"}"#,
        &config(),
        &http,
        1_720_000_060,
    )
    .expect("watch execute");

    assert_eq!(output.verdict, Verdict::Missing);
    assert_eq!(output.age_secs, None);
    assert!(output.summary.contains("Uptime MISSING"));
}

#[test]
fn prefers_newest_matching_attestation_by_block_time() {
    let http = MapHttp::default()
        .with_response(
            signatures_body(25),
            signatures_response(json!([
                {"signature": "sig-newer", "blockTime": 1_720_000_050, "err": null},
                {"signature": "sig-older", "blockTime": 1_720_000_000, "err": null}
            ])),
        )
        .with_response(
            transaction_body("sig-newer"),
            transaction_response(
                1_720_000_050,
                "ZCDEPIN|device-7|uptime|2|seconds|5733333|newnewnewnew",
            ),
        )
        .with_response(
            transaction_body("sig-older"),
            transaction_response(
                1_720_000_000,
                "ZCDEPIN|device-7|uptime|1|seconds|5733333|oldoldoldold",
            ),
        );

    let output = execute(
        r#"{"device_id":"device-7","max_age_secs":120}"#,
        &config(),
        &http,
        1_720_000_060,
    )
    .expect("watch execute");

    assert_eq!(output.verdict, Verdict::Ok);
    assert_eq!(output.age_secs, Some(10));
    assert!(output.summary.contains("sig-newer"));
}

#[test]
fn returns_missing_when_device_id_is_only_a_substring() {
    // Memo is for prod-greenhouse-7; a prompt-injected device_id of "7"
    // must not match via contains() and falsely report OK.
    let http = MapHttp::default()
        .with_response(
            signatures_body(25),
            signatures_response(json!([
                {"signature": "sig-other", "blockTime": 1_720_000_000, "err": null}
            ])),
        )
        .with_response(
            transaction_body("sig-other"),
            transaction_response(
                1_720_000_000,
                "ZCDEPIN|prod-greenhouse-7|temperature|21.4|celsius|5733333|abc123def456",
            ),
        );

    let output = execute(r#"{"device_id":"7"}"#, &config(), &http, 1_720_000_060).expect("watch");

    assert_eq!(output.verdict, Verdict::Missing);
    assert!(output.summary.contains("Uptime MISSING"));
}

#[test]
fn refuses_pipe_or_empty_device_id() {
    for args in [
        r#"{"device_id":""}"#,
        r#"{"device_id":"device|7"}"#,
        "{\"device_id\":\"device\\n7\"}",
    ] {
        let err = execute(args, &config(), &MapHttp::default(), 1).unwrap_err();
        assert!(
            err.contains("device_id"),
            "expected device_id refusal for {args}, got {err}"
        );
    }
}

#[test]
fn refuses_scan_limits_over_fifty() {
    let mut cfg = config();
    cfg.insert("scan_limit".to_string(), "51".to_string());

    let err = execute(r#"{"device_id":"device-7"}"#, &cfg, &MapHttp::default(), 1).unwrap_err();

    assert!(err.contains("scan_limit must be <= 50"));
}

#[test]
fn keeps_output_within_budget() {
    let long_device = "device-".to_string() + &"x".repeat(700);
    let args = serde_json::to_string(&json!({ "device_id": long_device })).unwrap();
    let memo = format!(
        "ZCDEPIN|{}|uptime|42|seconds|5733333|abc123def456",
        "device-".to_string() + &"x".repeat(700)
    );
    let http = MapHttp::default()
        .with_response(
            signatures_body(25),
            signatures_response(json!([
                {"signature": "sig-long", "blockTime": 1_720_000_000, "err": null}
            ])),
        )
        .with_response(
            transaction_body("sig-long"),
            transaction_response(1_720_000_000, &memo),
        );

    let output = execute(&args, &config(), &http, 1_720_000_060).expect("watch execute");

    assert!(output.summary.chars().count() <= 800);
}

#[test]
fn paginates_until_matching_memo_is_found() {
    let http = MapHttp::default()
        .with_response(
            signatures_body(2),
            signatures_response(json!([
                {"signature": "sig-a", "blockTime": 1_720_000_050, "err": null},
                {"signature": "sig-b", "blockTime": 1_720_000_040, "err": null}
            ])),
        )
        .with_response(
            transaction_body("sig-a"),
            transaction_response(
                1_720_000_050,
                "ZCDEPIN|other|uptime|1|seconds|5733333|aaaaaaaaaaaa",
            ),
        )
        .with_response(
            transaction_body("sig-b"),
            transaction_response(
                1_720_000_040,
                "ZCDEPIN|other|uptime|1|seconds|5733333|bbbbbbbbbbbb",
            ),
        )
        .with_response(
            signatures_body_before(2, Some("sig-b")),
            signatures_response(json!([
                {"signature": "sig-hit", "blockTime": 1_720_000_000, "err": null}
            ])),
        )
        .with_response(
            transaction_body("sig-hit"),
            transaction_response(
                1_720_000_000,
                "ZCDEPIN|device-7|uptime|42|seconds|5733333|abc123def456",
            ),
        );

    let mut cfg = config();
    cfg.insert("scan_limit".to_string(), "2".to_string());

    let output = execute(
        r#"{"device_id":"device-7","max_age_secs":3600}"#,
        &cfg,
        &http,
        1_720_000_060,
    )
    .expect("watch paginate");

    assert_eq!(output.verdict, Verdict::Ok);
    assert!(output.summary.contains("sig-hit"));
}

#[test]
fn reads_memo_from_inner_instructions() {
    let http = MapHttp::default()
        .with_response(
            signatures_body(25),
            signatures_response(json!([
                {"signature": "sig-cpi", "blockTime": 1_720_000_000, "err": null}
            ])),
        )
        .with_response(
            transaction_body("sig-cpi"),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "blockTime": 1_720_000_000,
                    "transaction": {
                        "message": {
                            "instructions": [
                                { "programId": "11111111111111111111111111111111" }
                            ]
                        }
                    },
                    "meta": {
                        "innerInstructions": [
                            {
                                "index": 0,
                                "instructions": [
                                    {
                                        "programId": MEMO_PROGRAM,
                                        "parsed": "ZCDEPIN|device-7|uptime|42|seconds|5733333|abc123def456"
                                    }
                                ]
                            }
                        ]
                    }
                }
            }),
        );

    let output = execute(
        r#"{"device_id":"device-7","max_age_secs":120}"#,
        &config(),
        &http,
        1_720_000_060,
    )
    .expect("inner memo");

    assert_eq!(output.verdict, Verdict::Ok);
    assert!(output.summary.contains("Uptime OK"));
}

#[test]
fn skips_failed_get_transaction_and_continues() {
    let http = MapHttp::default()
        .with_response(
            signatures_body(25),
            signatures_response(json!([
                {"signature": "sig-bad", "blockTime": 1_720_000_050, "err": null},
                {"signature": "sig-good", "blockTime": 1_720_000_000, "err": null}
            ])),
        )
        // no mock for sig-bad → transport error → skip
        .with_response(
            transaction_body("sig-good"),
            transaction_response(
                1_720_000_000,
                "ZCDEPIN|device-7|uptime|42|seconds|5733333|abc123def456",
            ),
        );

    let output = execute(
        r#"{"device_id":"device-7","max_age_secs":120}"#,
        &config(),
        &http,
        1_720_000_060,
    )
    .expect("skip bad tx");

    assert_eq!(output.verdict, Verdict::Ok);
    assert!(output.summary.contains("sig-good"));
}
