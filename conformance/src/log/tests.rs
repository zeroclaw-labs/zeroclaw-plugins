//! The chain arithmetic is tested in `safe_hands_core::log`. These cover the
//! layer around it: that a receipt is re-derived before it is chained, that a
//! hand-edited log stops verifying, and that anchors are read off a real RPC
//! response shape rather than an idealised one.

use super::*;
use safe_hands_core::rpc::MockTransport;

/// The real ALLOW receipt shipped for `--verify`.
const RECEIPT: &str = include_str!("../../receipts/live-allow.json");
const AUTHORITY: &str = "5Z6Ay5NEcbg3xhopc522sBCRXQujkTiuDRnHGfQdcnSf";

fn authority() -> Pubkey {
    parse_pubkey(AUTHORITY).expect("authority")
}

/// A fresh log path, cleaned up first so a failed run cannot poison the next.
fn scratch(name: &str) -> Args {
    let path = std::env::temp_dir().join(format!("safe-hands-log-test-{name}.jsonl"));
    let _ = fs::remove_file(&path);
    Args {
        log: path,
        authority: authority(),
        rpc: None,
        blockhash: None,
    }
}

fn receipt_file(name: &str, body: &str) -> String {
    let path = std::env::temp_dir().join(format!("safe-hands-receipt-{name}.json"));
    fs::write(&path, body).expect("write receipt");
    path.to_string_lossy().into_owned()
}

// ── append and verify ───────────────────────────────────────────────────────

#[test]
fn appending_builds_a_log_that_verifies() {
    let args = scratch("append");
    let receipt = receipt_file("append", RECEIPT);
    for _ in 0..3 {
        append(&args, &receipt).expect("append");
    }
    let records = read_records(&args.log).expect("read");
    assert_eq!(records.len(), 3);
    assert_eq!(
        records.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );

    let links = links_from(&records).expect("re-derive");
    let head = verify_chain(&args.authority, &links).expect("verifies");
    assert_eq!(head, records[2].head);

    // The same decision logged three times still produces three different
    // heads, because the sequence number is inside the hash.
    assert_ne!(records[0].head, records[1].head);
    assert_ne!(records[1].head, records[2].head);
}

/// The property that makes the log worth keeping: what gets chained is the
/// decision the engine produces, not the one the receipt claims.
#[test]
fn a_receipt_that_does_not_re_derive_is_refused() {
    let args = scratch("forged");
    let mut receipt: Value = serde_json::from_str(RECEIPT).expect("parse");
    receipt["decision"]["verdict"] = json!("ALLOW");
    receipt["intent"]["recipient"] = json!("AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9");
    let path = receipt_file("forged", &receipt.to_string());

    let error = append(&args, &path).expect_err("must refuse");
    assert!(
        error.contains("does not re-derive"),
        "unexpected error: {error}"
    );
    assert!(!args.log.exists(), "nothing may be written on refusal");
}

#[test]
fn editing_a_logged_verdict_breaks_verification() {
    let args = scratch("edited");
    let receipt = receipt_file("edited", RECEIPT);
    append(&args, &receipt).expect("append");

    let mut records = read_records(&args.log).expect("read");
    records[0].receipt["decision"]["verdict"] = json!("DENY");
    rewrite(&args.log, &records);

    let error = links_from(&read_records(&args.log).expect("read")).expect_err("must fail");
    assert!(
        error.contains("does not re-derive"),
        "unexpected error: {error}"
    );
}

/// Deleting a line is the whole point. It must be loud.
#[test]
fn deleting_an_entry_breaks_verification() {
    let args = scratch("deleted");
    let receipt = receipt_file("deleted", RECEIPT);
    for _ in 0..3 {
        append(&args, &receipt).expect("append");
    }
    let mut records = read_records(&args.log).expect("read");
    records.remove(1);
    rewrite(&args.log, &records);

    let links = links_from(&read_records(&args.log).expect("read")).expect("receipts still fine");
    assert!(
        verify_chain(&args.authority, &links).is_err(),
        "a removed entry went undetected"
    );
}

#[test]
fn appending_to_a_broken_log_is_refused() {
    let args = scratch("broken");
    let receipt = receipt_file("broken", RECEIPT);
    append(&args, &receipt).expect("append");

    let mut records = read_records(&args.log).expect("read");
    records[0].head = Head([0u8; 32]);
    rewrite(&args.log, &records);

    let error = append(&args, &receipt).expect_err("must refuse");
    assert!(
        error.contains("does not verify"),
        "unexpected error: {error}"
    );
    assert_eq!(
        read_records(&args.log).expect("read").len(),
        1,
        "a refused append must not extend the file"
    );
}

#[test]
fn an_absent_log_is_an_empty_log_not_an_error() {
    let args = scratch("absent");
    assert!(read_records(&args.log).expect("read").is_empty());
    assert_eq!(
        verify_chain(&args.authority, &[]).expect("verifies"),
        genesis_head(&args.authority)
    );
}

#[test]
fn a_corrupt_line_names_its_line_number() {
    let args = scratch("corrupt");
    let receipt = receipt_file("corrupt", RECEIPT);
    append(&args, &receipt).expect("append");
    let mut text = fs::read_to_string(&args.log).expect("read");
    text.push_str("{not json}\n");
    fs::write(&args.log, text).expect("write");

    let error = read_records(&args.log).expect_err("must fail");
    assert!(error.contains(":2"), "unexpected error: {error}");
}

fn rewrite(path: &Path, records: &[Record]) {
    let text = records
        .iter()
        .map(|r| serde_json::to_string(r).expect("encode"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, format!("{text}\n")).expect("write");
}

// ── anchoring ───────────────────────────────────────────────────────────────

#[test]
fn the_anchor_transaction_is_unsigned_and_carries_the_head() {
    let args = Args {
        blockhash: Some("11111111111111111111111111111111".into()),
        ..scratch("anchor")
    };
    let receipt = receipt_file("anchor", RECEIPT);
    append(&args, &receipt).expect("append");
    build_anchor(&args).expect("anchor builds");

    // Rebuild the same message here so the assertion is on content, not on
    // stdout: one memo, the authority signing, the log's real head inside.
    let records = read_records(&args.log).expect("read");
    let links = links_from(&records).expect("re-derive");
    let head = verify_chain(&args.authority, &links).expect("verifies");
    let message = anchor_message(
        &args.authority,
        &Hash::from_str("11111111111111111111111111111111").expect("hash"),
        &Anchor { count: 1, head },
    )
    .expect("message");
    let memo = String::from_utf8(message.instructions[0].data.clone()).expect("utf-8");
    assert_eq!(memo, format!("sh1 n=1 head={head}"));

    let serialized = bincode::serialize(&message).expect("serialize");
    let wire =
        unsigned_transaction_bytes(&serialized, message.header.num_required_signatures.into())
            .expect("wire");
    assert_eq!(wire[0], 1, "one signature slot");
    assert!(wire[1..65].iter().all(|b| *b == 0), "the slot is empty");
}

#[test]
fn anchoring_a_broken_log_is_refused() {
    let args = Args {
        blockhash: Some("11111111111111111111111111111111".into()),
        ..scratch("anchor-broken")
    };
    let receipt = receipt_file("anchor-broken", RECEIPT);
    append(&args, &receipt).expect("append");
    let mut records = read_records(&args.log).expect("read");
    records[0].head = Head([9u8; 32]);
    rewrite(&args.log, &records);

    let error = build_anchor(&args).expect_err("must refuse");
    assert!(error.contains("does not verify"), "unexpected: {error}");
}

// ── reading the chain ───────────────────────────────────────────────────────

/// The RPC prefixes inline memos with a byte count. Anchors written by other
/// programs, and transactions that failed, must not be mistaken for ours.
#[test]
fn anchors_are_read_out_of_a_real_signature_page() {
    let head = Head([0x3c; 32]);
    let transport = MockTransport::new().with(
        "getSignaturesForAddress",
        json!({"result": [
            {"signature": "sigA", "slot": 100, "err": null, "blockTime": 1,
             "memo": format!("[41] sh1 n=2 head={head}")},
            {"signature": "sigB", "slot": 101, "err": null, "blockTime": 2,
             "memo": "[11] hello there"},
            {"signature": "sigC", "slot": 102, "err": null, "blockTime": 3, "memo": null},
            {"signature": "sigD", "slot": 103, "err": {"InstructionError": []}, "blockTime": 4,
             "memo": format!("[41] sh1 n=9 head={head}")},
            {"signature": "sigE", "slot": 104, "err": null, "blockTime": 5,
             "memo": format!("sh1 n=5 head={head}")}
        ]}),
    );

    let anchors = fetch_anchors(&transport, &authority()).expect("fetch");
    assert_eq!(
        anchors
            .iter()
            .map(|a| (a.signature.as_str(), a.anchor.count, a.slot))
            .collect::<Vec<_>>(),
        vec![("sigA", 2, 100), ("sigE", 5, 104)],
        "only successful transactions carrying our memo count"
    );
    assert_eq!(anchors[0].block_time, Some(1));
    assert!(anchors.iter().all(|a| a.anchor.head == head));
}

#[test]
fn memo_length_prefixes_are_stripped_only_when_they_are_prefixes() {
    assert_eq!(strip_memo_prefix("[12] sh1 n=1"), "sh1 n=1");
    assert_eq!(strip_memo_prefix("  [12]   sh1"), "sh1");
    assert_eq!(strip_memo_prefix("sh1 n=1"), "sh1 n=1");
    assert_eq!(strip_memo_prefix("[abc] sh1"), "[abc] sh1");
    assert_eq!(strip_memo_prefix("[] sh1"), "[] sh1");
    assert_eq!(strip_memo_prefix("[12 sh1"), "[12 sh1");
}

#[test]
fn an_empty_signature_page_yields_no_anchors() {
    let transport = MockTransport::new().with("getSignaturesForAddress", json!({"result": []}));
    assert!(fetch_anchors(&transport, &authority())
        .expect("fetch")
        .is_empty());
}

#[test]
fn a_malformed_signature_page_is_an_error_not_an_empty_result() {
    let transport = MockTransport::new().with("getSignaturesForAddress", json!({"result": "no"}));
    assert!(fetch_anchors(&transport, &authority()).is_err());
}

#[test]
fn the_blockhash_is_read_from_the_finalized_value() {
    let transport = MockTransport::new().with(
        "getLatestBlockhash",
        json!({"result": {"value": {"blockhash": "11111111111111111111111111111111"}}}),
    );
    assert_eq!(
        latest_blockhash(&transport).expect("blockhash"),
        Hash::from_str("11111111111111111111111111111111").expect("hash")
    );

    let missing = MockTransport::new().with("getLatestBlockhash", json!({"result": {}}));
    assert!(latest_blockhash(&missing).is_err());
}

// ── argument handling ───────────────────────────────────────────────────────

#[test]
fn the_authority_is_required_and_must_be_a_real_key() {
    let none: Vec<String> = vec![];
    // The env var is a legitimate source, so only assert on the parse failure
    // that cannot depend on the environment.
    assert!(Args::parse(&["--authority".into(), "not-a-key".into()]).is_err());
    if std::env::var("SAFE_HANDS_LOG_AUTHORITY").is_err() {
        assert!(Args::parse(&none).is_err());
    }
}

#[test]
fn arguments_are_read_in_full() {
    let args = Args::parse(&[
        "--authority".into(),
        AUTHORITY.into(),
        "--log".into(),
        "a/b.jsonl".into(),
        "--rpc".into(),
        "https://example.invalid".into(),
        "--blockhash".into(),
        "11111111111111111111111111111111".into(),
    ])
    .expect("parses");
    assert_eq!(args.log, PathBuf::from("a/b.jsonl"));
    assert_eq!(args.authority, authority());
    assert_eq!(args.rpc.as_deref(), Some("https://example.invalid"));
    assert_eq!(
        args.blockhash.as_deref(),
        Some("11111111111111111111111111111111")
    );
}

// ── timestamps ──────────────────────────────────────────────────────────────

/// The timestamp is decoration, but a wrong one in an audit log is worse than
/// none, so the civil-date arithmetic gets checked against known instants —
/// including the leap day that catches naive implementations.
#[test]
fn the_recorded_timestamp_is_a_real_rfc_3339_instant() {
    for (unix, expected) in [
        (0, "1970-01-01T00:00:00Z"),
        (1, "1970-01-01T00:00:01Z"),
        (951_782_400, "2000-02-29T00:00:00Z"),
        (1_709_164_800, "2024-02-29T00:00:00Z"),
        (1_735_689_599, "2024-12-31T23:59:59Z"),
        (1_753_401_600, "2025-07-25T00:00:00Z"),
        (4_102_444_800, "2100-01-01T00:00:00Z"),
    ] {
        assert_eq!(rfc3339_from_unix(unix), expected, "unix {unix}");
    }

    let stamp = now_rfc3339();
    assert_eq!(stamp.len(), 20, "{stamp}");
    assert!(stamp.ends_with('Z'), "{stamp}");
}
