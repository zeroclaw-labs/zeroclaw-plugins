//! Adversarial input: a payment verdict is money advice, and every byte it
//! rests on arrives from an RPC endpoint nobody in this process controls.
//!
//! `tests/watcher.rs` covers the shapes a healthy endpoint returns. This file
//! covers the rest: signature strings that are not base58, token balances that
//! are not numbers, two token accounts for one owner and mint, mints claiming
//! more decimals than a u64 can scale by, expectations supplied one at a time,
//! and balance arithmetic at the edges of u64. A wrapped subtraction that reads
//! as a completed payment is a correctness bug with money attached, so the
//! assertions are on the refusal, never on the wrapped value.
//!
//! The generative sweeps run off fixed seeds, so a failure reproduces exactly.

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use payment_watch::watcher::{run, Lookups, WatchError};
use solana_core_wasi::amount::{from_base_units, to_base_units};
use solana_core_wasi::rpc::{parse_lamport_delta, parse_token_deltas, RpcError};

const REFERENCE: &str = "SysvarC1ock11111111111111111111111111111111";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const OTHER_MINT: &str = "So11111111111111111111111111111111111111112";
const RECIP: &str = "mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN";
const OTHER_WALLET: &str = "9B5XszUGdMaxCZ7uSQhPzdks5ZQSmWxrmzCSvtJ6Ns6g";

/// Replays captured response shapes by matching on the request body, the same
/// mock shape `tests/watcher.rs` uses.
struct MockRpc {
    responses: Vec<(&'static str, String)>,
    calls: Vec<String>,
}

impl MockRpc {
    fn new(responses: Vec<(&'static str, String)>) -> Self {
        Self {
            responses,
            calls: Vec::new(),
        }
    }
}

impl Lookups for MockRpc {
    fn rpc(&mut self, body: &str) -> Result<String, String> {
        self.calls.push(body.to_string());
        for (pat, resp) in &self.responses {
            if body.contains(pat) {
                return Ok(resp.clone());
            }
        }
        Err(format!("mock has no response for: {body}"))
    }
}

/// xorshift64* from a fixed seed: reproducible generative cases with no new
/// dependency and without reading the operating system's entropy.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}
/// Runs `f` and turns a panic into a failure that names the input. A component
/// that panics denies service to the whole agent, so the case has to be
/// identifiable from the failure alone.
fn no_panic<T>(case: &str, f: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_) => panic!("panicked on {case}: malformed input must be refused, not fatal"),
    }
}

fn args(extra: &[(&str, &str)]) -> String {
    let mut v = serde_json::json!({
        "reference": REFERENCE,
        "__config": { "rpc_url": "https://api.devnet.solana.com" },
    });
    for (k, val) in extra {
        v[*k] = serde_json::json!(val);
    }
    v.to_string()
}

/// A getSignaturesForAddress response listing successful signatures.
fn sigs_resp(sigs: &[&str]) -> String {
    let list: Vec<String> = sigs
        .iter()
        .map(|s| {
            let escaped = serde_json::Value::from(*s).to_string();
            format!(
                r#"{{"signature":{escaped},"slot":100,"err":null,"memo":null,"blockTime":1700000000,"confirmationStatus":"finalized"}}"#
            )
        })
        .collect();
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":[{}]}}"#,
        list.join(",")
    )
}

/// One token balance entry, exactly the shape getTransaction(jsonParsed) sends.
/// `amount` and `decimals` go in verbatim so a test can put anything there.
fn bal(index: u64, owner: &str, mint: &str, amount: &str, decimals: &str) -> String {
    format!(
        r#"{{"accountIndex":{index},"mint":"{mint}","owner":"{owner}","uiTokenAmount":{{"amount":"{amount}","decimals":{decimals},"uiAmountString":"x"}}}}"#
    )
}

fn tx_resp(pre: &[String], post: &[String]) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"meta":{{"err":null,"preTokenBalances":[{}],"postTokenBalances":[{}]}}}}}}"#,
        pre.join(","),
        post.join(",")
    )
}

/// The verdict JSON the tool hands back, parsed.
fn verdict(out: &str) -> serde_json::Value {
    serde_json::from_str(out).expect("the tool always emits JSON")
}
/// Every Rust file this package compiles: its own sources plus the vendored
/// core's, which is the whole surface a decision could hide in.
fn compiled_sources() -> Vec<(PathBuf, String)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    for dir in [root.join("src"), root.join("solana-core").join("src")] {
        for entry in fs::read_dir(&dir).expect("source directory") {
            let path = entry.expect("directory entry").path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                sources.push((
                    path.clone(),
                    fs::read_to_string(&path).expect("source file"),
                ));
            }
        }
    }
    assert!(
        sources.len() > 5,
        "expected the plugin sources and the vendored core, found {}",
        sources.len()
    );
    sources
}

/// Crate names in the resolved graph, read from the lockfile CI builds with.
fn locked_crate_names() -> Vec<String> {
    let lock = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    fs::read_to_string(lock)
        .expect("Cargo.lock")
        .lines()
        .filter_map(|line| line.strip_prefix("name = "))
        .map(|name| name.trim().trim_matches('"').to_string())
        .collect()
}

/// A two-call transcript: the signature list, then one transaction body.
fn transcript(sig: &str, tx: String) -> MockRpc {
    MockRpc::new(vec![
        ("getSignaturesForAddress", sigs_resp(&[sig])),
        ("getTransaction", tx),
    ])
}
#[test]
fn a_signature_with_a_multibyte_character_does_not_panic() {
    // The signature string is whatever the endpoint sent, not necessarily
    // base58. The summary trims it to a 12-byte prefix, which split a
    // multi-byte character and panicked: one hostile response took the whole
    // component down.
    for sig in [
        "aaaaaaaaaa\u{20ac}xx",
        "aaaaaaaaaaa\u{10348}",
        "\u{20ac}\u{20ac}\u{20ac}\u{20ac}\u{20ac}",
        "\u{10348}\u{10348}\u{10348}\u{10348}",
        "sig\u{0}with\u{0}nuls\u{0}inside",
    ] {
        let mut rpc = transcript(
            sig,
            tx_resp(
                &[bal(1, RECIP, USDC, "0", "6")],
                &[bal(1, RECIP, USDC, "25000000", "6")],
            ),
        );
        let out = no_panic(&format!("signature {sig:?}"), || run(&args(&[]), &mut rpc))
            .expect("an odd signature string is still a verdict");
        let v = verdict(&out);
        assert_eq!(v["paid"], true, "signature {sig:?}: {out}");
        assert_eq!(
            v["signature"], sig,
            "the verdict must carry the signature verbatim"
        );
    }
}

#[test]
fn token_balance_amounts_that_are_not_base_units_fail_closed() {
    // A pre-balance the decoder cannot read used to count as zero, which turns
    // a wallet that already held the tokens into a fresh full payment. The
    // amount field is a decimal string of base units or it is nothing.
    for amount in [
        "1e9",
        "",
        "-1",
        " 25",
        "25 ",
        "0x19",
        "25.0",
        "18446744073709551616",
        "null",
        "\u{ff12}\u{ff15}",
    ] {
        let raw = tx_resp(
            &[bal(1, RECIP, USDC, amount, "6")],
            &[bal(1, RECIP, USDC, "25000000", "6")],
        );
        let deltas = no_panic(&format!("pre amount {amount:?}"), || {
            parse_token_deltas(&raw)
        });
        assert!(
            matches!(deltas, Err(RpcError::BadData(_))),
            "pre amount {amount:?} was accepted: {deltas:?}"
        );
        let mut rpc = transcript("sigA", raw);
        let out = run(&args(&[]), &mut rpc).expect("a bad balance is a verdict, not a crash");
        assert_eq!(
            verdict(&out)["paid"],
            false,
            "unreadable pre balance {amount:?} reported PAID"
        );
    }
    for amount in ["1e9", "-1", "18446744073709551616", "not-a-number"] {
        let raw = tx_resp(&[], &[bal(1, RECIP, USDC, amount, "6")]);
        let deltas = no_panic(&format!("post amount {amount:?}"), || {
            parse_token_deltas(&raw)
        });
        assert!(
            matches!(deltas, Err(RpcError::BadData(_))),
            "post amount {amount:?} was accepted: {deltas:?}"
        );
    }

    // Rust's u64 parse accepts a leading plus. No node sends one, and it reads
    // unambiguously as the same number, so it is tolerated on purpose rather
    // than by accident.
    let raw = tx_resp(
        &[bal(1, RECIP, USDC, "+25", "6")],
        &[bal(1, RECIP, USDC, "125", "6")],
    );
    let deltas = parse_token_deltas(&raw).expect("a leading plus reads as the number");
    assert_eq!(deltas[0].received_base_units, 100);
}
#[test]
fn a_second_token_account_for_the_same_owner_and_mint_cannot_inflate_the_delta() {
    // Pre and post balances are per token account, not per (owner, mint), and a
    // wallet can hold more than one account for a mint. Pairing post entries
    // with the first pre entry of the same owner and mint made an account that
    // received nothing report the other account's entire balance.
    let pre = [
        bal(1, RECIP, USDC, "0", "6"),
        bal(2, RECIP, USDC, "25000000", "6"),
    ];
    let unchanged = [
        bal(1, RECIP, USDC, "0", "6"),
        bal(2, RECIP, USDC, "25000000", "6"),
    ];
    let deltas = parse_token_deltas(&tx_resp(&pre, &unchanged)).expect("well-formed balances");
    assert!(
        deltas.is_empty(),
        "nothing moved, yet the decode reported {deltas:?}"
    );
    let mut rpc = transcript("sigA", tx_resp(&pre, &unchanged));
    let out = run(
        &args(&[("expected_amount", "25"), ("mint", USDC)]),
        &mut rpc,
    )
    .expect("verdict");
    assert_eq!(verdict(&out)["paid"], false, "{out}");

    // The real payment into the second account is still seen, exactly once.
    let paid = [
        bal(1, RECIP, USDC, "0", "6"),
        bal(2, RECIP, USDC, "50000000", "6"),
    ];
    let deltas = parse_token_deltas(&tx_resp(&pre, &paid)).expect("well-formed balances");
    assert_eq!(deltas.len(), 1, "{deltas:?}");
    assert_eq!(deltas[0].received_base_units, 25_000_000);

    // An index that reports a different mint between pre and post is a lying
    // endpoint, not a transfer.
    let swapped = [bal(1, RECIP, OTHER_MINT, "5", "6")];
    let before = [bal(1, RECIP, USDC, "0", "6")];
    assert!(
        matches!(
            parse_token_deltas(&tx_resp(&before, &swapped)),
            Err(RpcError::BadData(_))
        ),
        "an account index that changed mint was accepted"
    );
}
#[test]
fn a_mint_claiming_more_decimals_than_u64_can_scale_by_is_still_exact() {
    // decimals is one byte off the wire. Rendering an amount at twenty or more
    // decimals computed 10^decimals in a u64: a panic in debug, and in release
    // a wrapped divisor and an amount that is simply wrong.
    for decimals in ["19", "20", "38", "255"] {
        let raw = tx_resp(&[], &[bal(1, RECIP, USDC, "5", decimals)]);
        let deltas = parse_token_deltas(&raw).expect("decimals is a u8, so the shape is valid");
        let d = &deltas[0];
        let rendered = no_panic(&format!("rendering at {decimals} decimals"), || {
            from_base_units(d.received_base_units, d.decimals)
        });
        assert_eq!(
            to_base_units(&rendered, d.decimals),
            Ok(5),
            "rendering at {decimals} decimals is not reversible: {rendered}"
        );
        let mut rpc = transcript("sigA", raw);
        let out = no_panic(&format!("watch at {decimals} decimals"), || {
            run(&args(&[]), &mut rpc)
        })
        .expect("verdict");
        assert!(
            verdict(&out)["summary"]
                .as_str()
                .expect("summary")
                .contains(&rendered),
            "the verdict must carry the exact amount: {out}"
        );
    }

    // An expected amount cannot be expressed at those decimals at all, so the
    // comparison refuses rather than guessing.
    let raw = tx_resp(&[], &[bal(1, RECIP, USDC, "5", "200")]);
    let mut rpc = transcript("sigA", raw);
    let err = run(
        &args(&[("expected_amount", "25"), ("mint", USDC)]),
        &mut rpc,
    )
    .expect_err("an unrepresentable expectation must be refused");
    assert!(matches!(err, WatchError::BadArgs(_)), "{err}");

    // Not a u8 at all: the decode refuses instead of clamping.
    for decimals in ["256", "-1", "6.5", "null", "1e3"] {
        let raw = tx_resp(&[], &[bal(1, RECIP, USDC, "5", decimals)]);
        assert!(
            matches!(parse_token_deltas(&raw), Err(RpcError::BadJson(_))),
            "decimals {decimals} was accepted"
        );
    }
}
#[test]
fn an_expected_mint_is_enforced_on_its_own() {
    // The reference key travels in a public payment request, so anyone can tag
    // a transfer with it. A caller that names the mint but no amount used to
    // get no mint check at all, so one unit of a worthless token read as PAID.
    let mut rpc = transcript(
        "sigA",
        tx_resp(
            &[bal(1, RECIP, OTHER_MINT, "0", "0")],
            &[bal(1, RECIP, OTHER_MINT, "1", "0")],
        ),
    );
    let out = run(&args(&[("mint", USDC)]), &mut rpc).expect("verdict");
    let v = verdict(&out);
    assert_eq!(
        v["paid"], false,
        "a transfer in another mint satisfied an expected mint: {out}"
    );
    assert!(
        v["summary"].as_str().expect("summary").contains("expected"),
        "the reason must name the expectation that failed: {out}"
    );
}

#[test]
fn every_combination_of_expectations_is_enforced() {
    // Expectations are independent filters: each one alone and all of them
    // together, have to hold before a payment counts.
    let rows = [
        (
            None::<&str>,
            None::<&str>,
            None::<&str>,
            RECIP,
            USDC,
            "25000000",
            true,
        ),
        (
            Some("25"),
            Some(USDC),
            Some(RECIP),
            RECIP,
            USDC,
            "25000000",
            true,
        ),
        (
            Some("25"),
            Some(USDC),
            Some(RECIP),
            RECIP,
            USDC,
            "24999999",
            false,
        ),
        (
            Some("25"),
            Some(USDC),
            None,
            RECIP,
            OTHER_MINT,
            "25000000",
            false,
        ),
        (None, Some(USDC), None, RECIP, OTHER_MINT, "1", false),
        (None, Some(USDC), None, RECIP, USDC, "1", true),
        (
            None,
            None,
            Some(RECIP),
            OTHER_WALLET,
            USDC,
            "25000000",
            false,
        ),
        (None, None, Some(RECIP), RECIP, USDC, "25000000", true),
        (
            Some("25"),
            Some(USDC),
            Some(OTHER_WALLET),
            RECIP,
            USDC,
            "25000000",
            false,
        ),
        (
            None,
            Some(OTHER_MINT),
            Some(RECIP),
            RECIP,
            USDC,
            "25000000",
            false,
        ),
        (Some("0.000001"), Some(USDC), None, RECIP, USDC, "1", true),
        (Some("25"), Some(USDC), None, RECIP, USDC, "25000001", true),
    ];
    for (i, (amount, mint, recipient, owner, got_mint, got_amount, paid)) in
        rows.into_iter().enumerate()
    {
        let mut extra: Vec<(&str, &str)> = Vec::new();
        if let Some(a) = amount {
            extra.push(("expected_amount", a));
        }
        if let Some(m) = mint {
            extra.push(("mint", m));
        }
        if let Some(r) = recipient {
            extra.push(("recipient", r));
        }
        let mut rpc = transcript(
            "sigA",
            tx_resp(
                &[bal(1, owner, got_mint, "0", "6")],
                &[bal(1, owner, got_mint, got_amount, "6")],
            ),
        );
        let out = no_panic(&format!("combination #{i}"), || {
            run(&args(&extra), &mut rpc)
        })
        .expect("verdict");
        assert_eq!(verdict(&out)["paid"], paid, "combination #{i}: {out}");
    }
}
/// Assert one signature-list body fails closed: paid is false or the call is
/// a typed RPC refusal.
fn sig_refusal(case: &str, body: String) {
    let mut rpc = MockRpc::new(vec![("getSignaturesForAddress", body)]);
    match no_panic(case, || run(&args(&[]), &mut rpc)) {
        Ok(out) => assert_eq!(verdict(&out)["paid"], false, "{case}: {out}"),
        Err(e) => assert!(matches!(e, WatchError::Rpc(_)), "{case}: {e}"),
    }
}

/// Assert one transaction body fails closed against a live expectation.
fn tx_refusal(case: &str, body: String) {
    let mut rpc = transcript("sigA", body);
    let expectations = [("expected_amount", "25"), ("mint", USDC)];
    match no_panic(case, || run(&args(&expectations), &mut rpc)) {
        Ok(out) => assert_eq!(verdict(&out)["paid"], false, "{case}: {out}"),
        Err(e) => assert!(
            matches!(e, WatchError::Rpc(_) | WatchError::BadArgs(_)),
            "{case}: {e}"
        ),
    }
}

#[test]
fn garbage_signature_lists_never_reach_a_paid_verdict() {
    // Models a hostile or broken endpoint answering the discovery call.
    let cases = [
        ("empty body", String::new()),
        ("json null", "null".into()),
        ("empty object", "{}".into()),
        ("result is an object", r#"{"result":{}}"#.into()),
        ("result is a string", r#"{"result":"sigA"}"#.into()),
        ("entry is empty", r#"{"result":[{}]}"#.into()),
        (
            "signature is a number",
            r#"{"result":[{"signature":5,"slot":1}]}"#.into(),
        ),
        (
            "slot is negative",
            r#"{"result":[{"signature":"s","slot":-1}]}"#.into(),
        ),
        (
            "slot is fractional",
            r#"{"result":[{"signature":"s","slot":1.5}]}"#.into(),
        ),
        (
            "slot overflows u64",
            r#"{"result":[{"signature":"s","slot":18446744073709551616}]}"#.into(),
        ),
        (
            "slot is missing",
            r#"{"result":[{"signature":"s"}]}"#.into(),
        ),
        (
            "confirmation status is a number",
            r#"{"result":[{"signature":"s","slot":1,"err":null,"confirmationStatus":7}]}"#.into(),
        ),
        (
            "rpc error object",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"behind"}}"#.into(),
        ),
        ("html error page", "<html>504</html>".into()),
        ("truncated", r#"{"result":[{"signature":"s","#.into()),
        (
            "deeply nested",
            format!(r#"{{"result":{}{}}}"#, "[".repeat(400), "]".repeat(400)),
        ),
        (
            "duplicate result members",
            r#"{"result":[{"signature":"s","slot":1,"err":null}],"result":[]}"#.into(),
        ),
    ];
    for (case, body) in cases {
        sig_refusal(case, body);
    }
}
#[test]
fn garbage_transaction_bodies_never_reach_a_paid_verdict() {
    // Models a hostile or broken endpoint answering the confirmation call: the
    // body that decides whether money arrived.
    let cases = [
        ("empty body", String::new()),
        ("json null", "null".into()),
        ("result null", r#"{"result":null}"#.into()),
        ("meta missing", r#"{"result":{}}"#.into()),
        ("meta null", r#"{"result":{"meta":null}}"#.into()),
        (
            "transaction failed",
            r#"{"result":{"meta":{"err":{"InstructionError":[0,"Custom"]}}}}"#.into(),
        ),
        (
            "err member missing",
            r#"{"result":{"meta":{"preTokenBalances":[],"postTokenBalances":[]}}}"#.into(),
        ),
        (
            "balances are objects",
            r#"{"result":{"meta":{"err":null,"preTokenBalances":{},"postTokenBalances":{}}}}"#
                .into(),
        ),
        (
            "entry missing mint",
            r#"{"result":{"meta":{"err":null,"postTokenBalances":[{"accountIndex":1,"owner":"x","uiTokenAmount":{"amount":"1","decimals":6}}]}}}"#.into(),
        ),
        (
            "entry missing amount",
            r#"{"result":{"meta":{"err":null,"postTokenBalances":[{"accountIndex":1,"mint":"m","owner":"x","uiTokenAmount":{"decimals":6}}]}}}"#.into(),
        ),
        (
            "amount is a number",
            r#"{"result":{"meta":{"err":null,"postTokenBalances":[{"accountIndex":1,"mint":"m","owner":"x","uiTokenAmount":{"amount":1,"decimals":6}}]}}}"#.into(),
        ),
        (
            "ui amount is null",
            r#"{"result":{"meta":{"err":null,"postTokenBalances":[{"accountIndex":1,"mint":"m","owner":"x","uiTokenAmount":null}]}}}"#.into(),
        ),
        (
            "account index missing",
            r#"{"result":{"meta":{"err":null,"postTokenBalances":[{"mint":"m","owner":"x","uiTokenAmount":{"amount":"1","decimals":6}}]}}}"#.into(),
        ),
        (
            "account index negative",
            r#"{"result":{"meta":{"err":null,"postTokenBalances":[{"accountIndex":-1,"mint":"m","owner":"x","uiTokenAmount":{"amount":"1","decimals":6}}]}}}"#.into(),
        ),
        ("html error page", "<html>504</html>".into()),
        ("truncated", r#"{"result":{"meta":{"err":null,"postToken"#.into()),
        (
            "deeply nested",
            format!(r#"{{"result":{}{}}}"#, "[".repeat(400), "]".repeat(400)),
        ),
        (
            "megabyte of padding",
            format!(r#"{{"result":{{"meta":{{"err":null,"memo":"{}"}}}}}}"#, "a".repeat(1_000_000)),
        ),
    ];
    for (case, body) in cases {
        tx_refusal(case, body);
    }
}
#[test]
fn a_transaction_that_moves_nothing_or_moves_backwards_is_never_paid() {
    // The delta is post minus pre. In release mode an unguarded subtraction
    // wraps, and a wrapped delta reads as an enormous payment, so the decode
    // has to drop non-positive deltas instead of computing them.
    for (case, pre, post) in [
        ("nothing moved", "25000000", "25000000"),
        ("balance fell", "25000000", "1"),
        ("emptied", "18446744073709551615", "0"),
        ("both zero", "0", "0"),
    ] {
        let raw = tx_resp(
            &[bal(1, RECIP, USDC, pre, "6")],
            &[bal(1, RECIP, USDC, post, "6")],
        );
        let deltas = parse_token_deltas(&raw).expect("well-formed balances");
        assert!(deltas.is_empty(), "{case}: reported {deltas:?}");
        let mut rpc = transcript("sigA", raw);
        let out = run(&args(&[]), &mut rpc).expect("verdict");
        assert_eq!(verdict(&out)["paid"], false, "{case}: {out}");
    }

    // The full u64 range in the other direction is reported exactly.
    let raw = tx_resp(
        &[bal(1, RECIP, USDC, "0", "0")],
        &[bal(1, RECIP, USDC, "18446744073709551615", "0")],
    );
    let deltas = parse_token_deltas(&raw).expect("well-formed balances");
    assert_eq!(deltas[0].received_base_units, u64::MAX);
}

#[test]
fn lamport_deltas_never_wrap_and_out_of_range_indexes_refuse() {
    // Native balances are the one place the subtraction legitimately goes
    // negative. It has to come back signed and exact, never wrapped into a
    // credit that reads as a payment.
    let body = |pre: &str, post: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"meta":{{"preBalances":[{pre}],"postBalances":[{post}]}}}}}}"#
        )
    };
    let max = "18446744073709551615";
    assert_eq!(
        parse_lamport_delta(&body(max, "0"), 0),
        Ok(-(u64::MAX as i128))
    );
    assert_eq!(
        parse_lamport_delta(&body("0", max), 0),
        Ok(u64::MAX as i128)
    );
    assert_eq!(parse_lamport_delta(&body("5", "5"), 0), Ok(0));
    assert!(matches!(
        parse_lamport_delta(&body("1", "2"), 7),
        Err(RpcError::MissingField(_))
    ));
    for bad in ["-1", "1.5", "18446744073709551616", "null", "\"5\"", "true"] {
        let raw = body(bad, "5");
        let got = no_panic(&format!("pre balance {bad}"), || {
            parse_lamport_delta(&raw, 0)
        });
        assert!(
            matches!(got, Err(RpcError::MissingField(_))),
            "pre balance {bad} was accepted as {got:?}"
        );
    }
}
#[test]
fn a_slot_at_u64_max_is_reported_verbatim() {
    // The slot is only ever reported, never used in arithmetic. An absurd one
    // has to print exactly rather than wrap into a plausible height.
    for slot in ["0", "18446744073709551615"] {
        let sigs = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":[{{"signature":"sigA","slot":{slot},"err":null,"blockTime":null,"confirmationStatus":null}}]}}"#
        );
        let mut rpc = MockRpc::new(vec![
            ("getSignaturesForAddress", sigs),
            (
                "getTransaction",
                tx_resp(&[], &[bal(1, RECIP, USDC, "25000000", "6")]),
            ),
        ]);
        let out = run(&args(&[]), &mut rpc).expect("verdict");
        let v = verdict(&out);
        assert_eq!(v["paid"], true, "{out}");
        assert!(
            v["summary"]
                .as_str()
                .expect("summary")
                .contains(&format!("slot {slot}")),
            "slot {slot} was not reported verbatim: {out}"
        );
    }
}

#[test]
fn reference_arguments_of_any_shape_refuse_before_the_network() {
    // Models a prompt-injected reference. Every one is refused as a bad
    // argument, and none of them costs an RPC call.
    let long = "z".repeat(50_000);
    let over_long = format!("{REFERENCE}1");
    let cases = [
        "",
        " ",
        "1",
        "abc",
        "0OIl",
        "\u{65e5}\u{672c}\u{8a9e}",
        over_long.as_str(),
        long.as_str(),
    ];
    for (i, case) in cases.iter().enumerate() {
        let mut v: serde_json::Value = serde_json::from_str(&args(&[])).expect("args");
        v["reference"] = serde_json::json!(case);
        let mut rpc = MockRpc::new(vec![]);
        let err = no_panic(&format!("reference #{i}"), || run(&v.to_string(), &mut rpc))
            .expect_err("a malformed reference must be refused");
        assert!(
            matches!(err, WatchError::BadArgs(_)),
            "reference #{i}: {err}"
        );
        assert!(rpc.calls.is_empty(), "reference #{i} reached the network");
    }

    // The 50,000-character case is refused by length: base58 decoding is
    // quadratic, and 50,000 characters took 5.1 seconds on the development box
    // inside a component that is meant to answer a chat message.
    let mut v: serde_json::Value = serde_json::from_str(&args(&[])).expect("args");
    v["reference"] = serde_json::json!(long);
    let mut rpc = MockRpc::new(vec![]);
    let err = run(&v.to_string(), &mut rpc).expect_err("an over-long reference must be refused");
    assert!(
        err.to_string().contains("too long"),
        "not refused by length: {err}"
    );
}
#[test]
fn the_same_transcript_twice_produces_byte_identical_output() {
    // Idempotency: the verdict is what a human acts on, and it must not depend
    // on iteration order, a clock or a random seed. The requests issued have
    // to match too, so a retry costs the same two calls.
    let transcripts = [
        (
            sigs_resp(&["sigA"]),
            tx_resp(
                &[bal(1, RECIP, USDC, "0", "6")],
                &[bal(1, RECIP, USDC, "25000000", "6")],
            ),
        ),
        (
            sigs_resp(&["sigA", "sigB"]),
            tx_resp(&[], &[bal(1, RECIP, USDC, "1", "0")]),
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"result":[]}"#.to_string(),
            String::new(),
        ),
    ];
    for (i, (sigs, tx)) in transcripts.iter().enumerate() {
        let pair = || {
            MockRpc::new(vec![
                ("getSignaturesForAddress", sigs.clone()),
                ("getTransaction", tx.clone()),
            ])
        };
        let mut a = pair();
        let mut b = pair();
        let first = format!("{:?}", run(&args(&[]), &mut a));
        let second = format!("{:?}", run(&args(&[]), &mut b));
        assert_eq!(first, second, "transcript #{i} disagreed with itself");
        assert_eq!(
            a.calls, b.calls,
            "transcript #{i} issued different requests"
        );
    }
}

#[test]
fn nothing_in_the_decision_path_reads_a_clock_or_random_bytes() {
    // A verdict that depends on when it ran cannot be reproduced, and a
    // payment claim nobody can reproduce is not evidence of anything.
    const FORBIDDEN: &[&str] = &[
        "SystemTime",
        "UNIX_EPOCH",
        "Instant",
        "now()",
        "elapsed()",
        "getrandom",
        "thread_rng",
        "OsRng",
        "random",
    ];
    for (path, text) in compiled_sources() {
        for spelling in FORBIDDEN {
            assert!(
                !text.contains(spelling),
                "{} names {spelling}: a decision must not depend on a clock or on entropy",
                path.display()
            );
        }
    }
    for name in locked_crate_names() {
        let lowered = name.to_lowercase();
        for fragment in ["rand", "chrono", "getrandom"] {
            assert!(
                !lowered.contains(fragment),
                "crate {name} can supply entropy: this package must stay deterministic"
            );
        }
        assert!(
            !["time", "instant", "quanta"].contains(&lowered.as_str()),
            "crate {name} can supply a clock: this package must stay deterministic"
        );
    }
}

#[test]
fn a_seeded_sweep_of_random_rpc_bodies_never_panics() {
    // Either call can answer with anything at all. Nothing it answers with may
    // be fatal, and none of it may read as a completed payment.
    let alphabet: &[u8] = b"{}[]\":,0123456789abcdefnulltrue-+.eE\\/ \n\t=z\0";
    let mut rng = Rng(0x7761_7463_6832_3536);
    let good_tx = tx_resp(&[], &[bal(1, RECIP, USDC, "25000000", "6")]);
    for i in 0..384 {
        let len = rng.below(96);
        let body: String = (0..len)
            .map(|_| alphabet[rng.below(alphabet.len())] as char)
            .collect();
        let mut first = MockRpc::new(vec![
            ("getSignaturesForAddress", body.clone()),
            ("getTransaction", good_tx.clone()),
        ]);
        let mut second = MockRpc::new(vec![
            ("getSignaturesForAddress", sigs_resp(&["sigA"])),
            ("getTransaction", body.clone()),
        ]);
        let expectations = [("expected_amount", "25"), ("mint", USDC)];
        for (position, rpc) in [("signature list", &mut first), ("transaction", &mut second)] {
            let case = format!("random {position} body #{i}: {body:?}");
            if let Ok(out) = no_panic(&case, || run(&args(&expectations), rpc)) {
                assert_eq!(verdict(&out)["paid"], false, "{case}: {out}");
            }
        }
    }
}
