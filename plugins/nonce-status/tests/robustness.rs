//! Adversarial input: the RPC endpoint and the tool arguments are both
//! untrusted, and a panic inside a WIT component takes the agent down instead
//! of printing a stack trace someone reads later.
//!
//! `tests/core.rs` covers the shapes a healthy endpoint returns. This file
//! covers what a hostile, broken or man-in-the-middled one returns: truncated
//! bodies, wrong types, absurd numbers, payloads that are not base64, accounts
//! owned by the wrong program and account data of every length from zero to
//! two hundred bytes. Every case has to end in a typed refusal or a fail-closed
//! summary. Never a panic, and never READY unless the account really is an
//! initialized 80-byte nonce owned by the system program.
//!
//! The generative sweeps run off fixed seeds, so a failure reproduces exactly.

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use nonce_status::core::{run, Lookups, StatusError};
use solana_core_wasi::encoding::base64_encode;
use solana_core_wasi::pubkey::Pubkey;

const NONCE_ACCT: &str = "8XkoSVfNbLKKzcpsTCyzysXbygqrGrbW8t5RS6Wxsdb1";
const AUTHORITY: &str = "9B5XszUGdMaxCZ7uSQhPzdks5ZQSmWxrmzCSvtJ6Ns6g";
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// Answers every request with the same body. The endpoint is untrusted, so
/// each decoder in the path has to survive it on its own.
struct Always {
    body: String,
    calls: usize,
}

impl Always {
    fn new(body: impl Into<String>) -> Self {
        Self {
            body: body.into(),
            calls: 0,
        }
    }
}

impl Lookups for Always {
    fn rpc(&mut self, _body: &str) -> Result<String, String> {
        self.calls += 1;
        Ok(self.body.clone())
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

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
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

fn args(account: Option<&str>) -> String {
    let mut v = serde_json::json!({
        "__config": {
            "rpc_url": "https://api.devnet.solana.com",
            "nonce_account": NONCE_ACCT,
        },
    });
    if let Some(a) = account {
        v["account"] = serde_json::json!(a);
    }
    v.to_string()
}

/// A getAccountInfo response carrying `data` and `owner` verbatim. The core's
/// own encoder builds the payload; its round-trip is pinned in encoding.rs.
fn account_resp(data: &[u8], owner: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{"data":["{}","base64"],"owner":"{owner}","lamports":1447680,"executable":false,"rentEpoch":0,"space":{}}}}}}}"#,
        base64_encode(data),
        data.len()
    )
}

/// The 80-byte layout: versions tag, state tag, authority, durable nonce, fee.
fn nonce_bytes(version: u32, state: u32, fee: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(80);
    d.extend_from_slice(&version.to_le_bytes());
    d.extend_from_slice(&state.to_le_bytes());
    d.extend_from_slice(&Pubkey::parse(AUTHORITY).expect("fixture authority").0);
    d.extend_from_slice(&[0xCD; 32]);
    d.extend_from_slice(&fee.to_le_bytes());
    d
}
/// Feed one body through the tool and assert it fails closed: a typed RPC
/// error or a summary that is not READY. Returns the summary when there was
/// one, so a caller can assert on the wording.
fn refuses(case: &str, body: &str) -> Option<String> {
    let mut rpc = Always::new(body);
    match no_panic(case, || run(&args(None), &mut rpc)) {
        Ok(json) => {
            let v: serde_json::Value = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("{case}: tool output is not JSON: {e}"));
            assert_eq!(v["ready"], false, "{case}: reported READY");
            Some(v["summary"].as_str().unwrap_or_default().to_string())
        }
        Err(e) => {
            assert!(
                matches!(e, StatusError::Rpc(_)),
                "{case}: expected a typed RPC refusal, got {e}"
            );
            None
        }
    }
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
#[test]
fn garbage_rpc_bodies_are_always_a_typed_refusal() {
    // Models an endpoint that is hostile, broken or a proxy in between: none
    // of this may become READY and none of it may be fatal.
    let good = base64_encode(&nonce_bytes(1, 1, 5000));
    let cases = [
        ("empty body", String::new()),
        ("one byte", "n".into()),
        ("json null", "null".into()),
        ("json array", "[]".into()),
        ("json number", "7".into()),
        ("empty object", "{}".into()),
        ("no result member", r#"{"jsonrpc":"2.0","id":1}"#.into()),
        (
            "result null",
            r#"{"jsonrpc":"2.0","id":1,"result":null}"#.into(),
        ),
        (
            "result is a string",
            r#"{"jsonrpc":"2.0","id":1,"result":"ok"}"#.into(),
        ),
        (
            "truncated mid-object",
            r#"{"jsonrpc":"2.0","id":1,"result":{"value":"#.into(),
        ),
        (
            "html error page",
            "<html><body>502 Bad Gateway</body></html>".into(),
        ),
        (
            "byte order mark",
            "\u{feff}{\"result\":{\"value\":null}}".to_string(),
        ),
        (
            "trailing nul byte",
            "{\"result\":{\"value\":null}}\0".to_string(),
        ),
        (
            "value member missing",
            r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1}}}"#.into(),
        ),
        (
            "account missing",
            r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":null}}"#.into(),
        ),
        ("value is a number", r#"{"result":{"value":7}}"#.into()),
        ("value is an array", r#"{"result":{"value":[]}}"#.into()),
        (
            "data is a string",
            format!(r#"{{"result":{{"value":{{"data":"{good}","owner":"{SYSTEM_PROGRAM}"}}}}}}"#),
        ),
        (
            "data is empty",
            format!(r#"{{"result":{{"value":{{"data":[],"owner":"{SYSTEM_PROGRAM}"}}}}}}"#),
        ),
        (
            "data[0] is null",
            format!(
                r#"{{"result":{{"value":{{"data":[null,"base64"],"owner":"{SYSTEM_PROGRAM}"}}}}}}"#
            ),
        ),
        (
            "data[0] is a number",
            format!(
                r#"{{"result":{{"value":{{"data":[7,"base64"],"owner":"{SYSTEM_PROGRAM}"}}}}}}"#
            ),
        ),
        (
            "data is not base64",
            format!(
                r#"{{"result":{{"value":{{"data":["!!!!","base64"],"owner":"{SYSTEM_PROGRAM}"}}}}}}"#
            ),
        ),
        (
            "base64 padding in the middle",
            format!(
                r#"{{"result":{{"value":{{"data":["a=bc","base64"],"owner":"{SYSTEM_PROGRAM}"}}}}}}"#
            ),
        ),
        (
            "base64 length not a multiple of four",
            format!(
                r#"{{"result":{{"value":{{"data":["abc","base64"],"owner":"{SYSTEM_PROGRAM}"}}}}}}"#
            ),
        ),
        (
            "data decodes to one byte",
            format!(
                r#"{{"result":{{"value":{{"data":["QQ==","base64"],"owner":"{SYSTEM_PROGRAM}"}}}}}}"#
            ),
        ),
        (
            "megabyte of base64 data",
            format!(
                r#"{{"result":{{"value":{{"data":["{}","base64"],"owner":"{SYSTEM_PROGRAM}"}}}}}}"#,
                "A".repeat(1_000_000)
            ),
        ),
        (
            "owner missing",
            format!(r#"{{"result":{{"value":{{"data":["{good}","base64"]}}}}}}"#),
        ),
        (
            "owner is null",
            format!(r#"{{"result":{{"value":{{"data":["{good}","base64"],"owner":null}}}}}}"#),
        ),
        (
            "owner is not base58",
            format!(r#"{{"result":{{"value":{{"data":["{good}","base64"],"owner":"0OIl"}}}}}}"#),
        ),
        (
            "owner is too short",
            format!(r#"{{"result":{{"value":{{"data":["{good}","base64"],"owner":"abc"}}}}}}"#),
        ),
        (
            "owner is far too long",
            format!(
                r#"{{"result":{{"value":{{"data":["{good}","base64"],"owner":"{}"}}}}}}"#,
                "z".repeat(4096)
            ),
        ),
        (
            "rpc error object",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"node is behind"}}"#.into(),
        ),
        (
            "error and result together",
            format!(
                r#"{{"error":{{"code":-1,"message":"x"}},"result":{{"value":{{"data":["{good}","base64"],"owner":"{SYSTEM_PROGRAM}"}}}}}}"#
            ),
        ),
        (
            "deeply nested result",
            format!(r#"{{"result":{}{}}}"#, "[".repeat(400), "]".repeat(400)),
        ),
    ];
    for (case, body) in cases {
        refuses(case, &body);
    }
}
#[test]
fn account_data_of_every_length_is_classified() {
    // Models a truncated or padded account. The runtime's nonce state is
    // exactly 80 bytes, so every other length has to refuse rather than read
    // short and report a nonce that is not there.
    let valid = nonce_bytes(1, 1, 5000);
    for len in 0usize..=200 {
        let mut data = valid.clone();
        data.resize(len, 0xEE);
        let mut rpc = Always::new(account_resp(&data, SYSTEM_PROGRAM));
        let json = no_panic(&format!("{len}-byte account"), || {
            run(&args(None), &mut rpc)
        })
        .unwrap_or_else(|e| panic!("{len}-byte account failed instead of refusing: {e}"));
        let v: serde_json::Value = serde_json::from_str(&json).expect("tool output is JSON");
        assert_eq!(v["ready"], len == 80, "{len}-byte account: {json}");
    }
}

#[test]
fn version_and_state_tags_outside_the_current_pair_are_refused() {
    // Models tampered leading tags or an account written by a future runtime.
    // Only versions 1 with state 1 is a nonce this runtime accepts.
    let mut rng = Rng(0x6e6f_6e63_655f_7461);
    let mut pairs = vec![
        (0u32, 1u32),
        (1, 0),
        (0, 0),
        (2, 1),
        (1, 2),
        (u32::MAX, 1),
        (1, u32::MAX),
        (1, 1),
    ];
    for _ in 0..64 {
        pairs.push(((rng.next_u64() >> 32) as u32, (rng.next_u64() >> 32) as u32));
    }
    for (version, state) in pairs {
        let mut rpc = Always::new(account_resp(
            &nonce_bytes(version, state, 5000),
            SYSTEM_PROGRAM,
        ));
        let json = no_panic(&format!("tags {version}/{state}"), || {
            run(&args(None), &mut rpc)
        })
        .expect("a well-formed envelope is a verdict, not an error");
        let v: serde_json::Value = serde_json::from_str(&json).expect("tool output is JSON");
        assert_eq!(
            v["ready"],
            version == 1 && state == 1,
            "tags {version}/{state}: {json}"
        );
    }
}
#[test]
fn an_account_owned_by_another_program_is_never_read_as_a_nonce() {
    // Models an endpoint pointing the tool at a token account, an ATA or an
    // attacker's own program account. The body must not be read at all: an
    // authority parsed out of an untrusted account is worse than no answer.
    let mut rng = Rng(0x6f77_6e65_725f_7377);
    let mut owners = vec![
        TOKEN_PROGRAM.to_string(),
        ATA_PROGRAM.to_string(),
        NONCE_ACCT.to_string(),
    ];
    for _ in 0..16 {
        let mut key = [0u8; 32];
        for b in key.iter_mut() {
            *b = rng.byte();
        }
        owners.push(Pubkey(key).to_base58());
    }
    for owner in owners {
        let mut rpc = Always::new(account_resp(&nonce_bytes(1, 1, 5000), &owner));
        let json = no_panic(&format!("owner {owner}"), || run(&args(None), &mut rpc))
            .expect("a well-formed envelope is a verdict");
        let v: serde_json::Value = serde_json::from_str(&json).expect("tool output is JSON");
        assert_eq!(v["ready"], false, "owner {owner} reported READY");
        let summary = v["summary"].as_str().expect("summary");
        assert!(
            summary.contains("NOT A NONCE ACCOUNT"),
            "owner {owner}: {summary}"
        );
        assert!(
            !summary.contains(AUTHORITY),
            "owner {owner}: read the body of an account it does not trust"
        );
    }
}

#[test]
fn a_fee_of_u64_max_is_reported_without_wrapping() {
    // lamports_per_signature is eight bytes off the wire and reaches the
    // operator through a format string. An absurd value must print exactly
    // rather than wrap into something plausible.
    for fee in [0u64, 1, 5000, u64::MAX - 1, u64::MAX] {
        let mut rpc = Always::new(account_resp(&nonce_bytes(1, 1, fee), SYSTEM_PROGRAM));
        let json = run(&args(None), &mut rpc).expect("verdict");
        let v: serde_json::Value = serde_json::from_str(&json).expect("tool output is JSON");
        assert_eq!(v["ready"], true, "fee {fee}");
        let summary = v["summary"].as_str().expect("summary");
        assert!(
            summary.contains(&format!("fee {fee} lamports")),
            "fee {fee} was not reported verbatim: {summary}"
        );
    }
}
#[test]
fn absurd_numeric_fields_do_not_change_the_verdict() {
    // Valid JSON, impossible numbers: a negative slot and lamports, a rent
    // epoch beyond any real one, a space field that disagrees with the data.
    // None of them feed the decision, so none of them may move it.
    let data = base64_encode(&nonce_bytes(1, 1, 5000));
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":-1}},"value":{{"data":["{data}","base64"],"owner":"{SYSTEM_PROGRAM}","lamports":-5,"executable":true,"rentEpoch":1e308,"space":99999}}}}}}"#
    );
    let mut rpc = Always::new(body);
    let json = run(&args(None), &mut rpc).expect("verdict");
    let v: serde_json::Value = serde_json::from_str(&json).expect("tool output is JSON");
    assert_eq!(
        v["ready"], true,
        "an unread number changed the verdict: {json}"
    );
    assert!(v["summary"].as_str().expect("summary").contains(AUTHORITY));
}

#[test]
fn account_arguments_of_any_shape_refuse_before_the_network() {
    // Models a prompt-injected `account` argument. Every one of these is
    // refused as a bad argument, and none of them costs an RPC call.
    let long = "z".repeat(50_000);
    let cases = [
        "",
        " ",
        "\t",
        "1",
        "abc",
        "0OIl",
        "l1I0O",
        "8XkoSVfNbLKKzcpsTCyzysXbyg",
        "8XkoSVfNbLKKzcpsTCyzysXbygqrGrbW8t5RS6Wxsdb11",
        "\u{65e5}\u{672c}\u{8a9e}",
        "\u{feff}8XkoSVfNbLKKzcpsTCyzysXbygqrGrbW8t5RS6Wxsdb1",
        "8XkoSVfNbLKKzcpsTCyzysXbygqrGrbW8t5RS6Wxsdb1\0",
        long.as_str(),
    ];
    for (i, case) in cases.iter().enumerate() {
        let mut rpc = Always::new("{}");
        let err = no_panic(&format!("account argument #{i}"), || {
            run(&args(Some(case)), &mut rpc)
        })
        .expect_err("a malformed account argument must be refused");
        assert!(
            matches!(err, StatusError::BadArgs(_)),
            "account argument #{i} ({} bytes): {err}",
            case.len()
        );
        assert_eq!(rpc.calls, 0, "account argument #{i} reached the network");
    }
}
#[test]
fn an_over_long_account_argument_is_refused_before_the_decoder_runs() {
    // base58 decoding is quadratic in the input length: 50,000 characters took
    // 5.1 seconds on the development box and a megabyte would take hours, all
    // inside a component that is meant to answer a chat message. A 32-byte key
    // is at most 44 characters, so anything longer is refused by length.
    for len in [45usize, 1_000, 50_000] {
        let arg = "z".repeat(len);
        let mut rpc = Always::new("{}");
        let err = run(&args(Some(&arg)), &mut rpc)
            .expect_err("an over-long account argument must be refused");
        assert!(
            err.to_string().contains("too long"),
            "{len} characters was not refused by length: {err}"
        );
        assert_eq!(rpc.calls, 0, "{len} characters reached the network");
    }
}

#[test]
fn duplicate_result_keys_resolve_last_wins_and_never_blend() {
    // Models a proxy appending a second `result` member. serde_json keeps the
    // last one, so the verdict follows exactly one member instead of mixing
    // two, and a valid member appended after a null does not sneak past a
    // refusal that already happened.
    let good = format!(
        r#""result":{{"context":{{"slot":1}},"value":{{"data":["{}","base64"],"owner":"{SYSTEM_PROGRAM}"}}}}"#,
        base64_encode(&nonce_bytes(1, 1, 5000))
    );
    let null = r#""result":{"value":null}"#;
    for (case, body, ready) in [
        ("valid then null", format!("{{{good},{null}}}"), false),
        ("null then valid", format!("{{{null},{good}}}"), true),
    ] {
        let mut rpc = Always::new(body);
        let json = no_panic(case, || run(&args(None), &mut rpc)).expect("verdict");
        let v: serde_json::Value = serde_json::from_str(&json).expect("tool output is JSON");
        assert_eq!(v["ready"], ready, "{case}: {json}");
    }
}

#[test]
fn the_same_response_twice_produces_byte_identical_output() {
    // Idempotency: the summary is what the operator acts on. Nothing in the
    // path may depend on iteration order, a clock or a random seed, so two
    // identical calls have to produce identical bytes.
    let bodies = [
        account_resp(&nonce_bytes(1, 1, 5000), SYSTEM_PROGRAM),
        account_resp(&nonce_bytes(1, 0, 5000), SYSTEM_PROGRAM),
        account_resp(&nonce_bytes(1, 1, u64::MAX), TOKEN_PROGRAM),
        r#"{"jsonrpc":"2.0","id":1,"result":{"value":null}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}"#.to_string(),
    ];
    for body in bodies {
        let mut first = Always::new(body.clone());
        let mut second = Always::new(body.clone());
        let a = format!("{:?}", run(&args(None), &mut first));
        let b = format!("{:?}", run(&args(None), &mut second));
        assert_eq!(a, b, "two identical calls disagreed");
    }
}
#[test]
fn nothing_in_the_decision_path_reads_a_clock_or_random_bytes() {
    // A verdict that depends on when it ran cannot be reproduced, and a tool
    // an operator cannot reproduce is not evidence of anything. The one map in
    // the path orders its keys explicitly; the byte-identical test above is
    // what proves that ordering holds.
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
fn base58_bounds_are_what_the_length_guard_assumes() {
    // The length guard rests on 44 being the longest base58 encoding of 32
    // bytes. If that ever moved, the guard would start refusing real keys.
    assert_eq!(Pubkey([0xFF; 32]).to_base58().len(), 44);
    assert_eq!(Pubkey([0u8; 32]).to_base58().len(), 32);
    let mut rng = Rng(0x6238_3558_5f6c_656e);
    let mut longest = 0;
    for _ in 0..512 {
        let mut key = [0u8; 32];
        for b in key.iter_mut() {
            *b = rng.byte();
        }
        let encoded = Pubkey(key).to_base58();
        assert_eq!(
            Pubkey::parse(&encoded),
            Ok(Pubkey(key)),
            "a real key must parse"
        );
        longest = longest.max(encoded.len());
    }
    assert_eq!(
        longest, 44,
        "the guard's 44-character bound no longer matches the encoder"
    );
}
#[test]
fn a_seeded_sweep_of_random_bodies_never_panics() {
    // An endpoint can send anything at all. Nothing it sends may be fatal, and
    // none of it may read as a healthy nonce account.
    let alphabet: &[u8] = b"{}[]\":,0123456789abcdefnulltrue-+.eE\\/ \n\t=z\0";
    let mut rng = Rng(0x6e6f_6e63_6535_3132);
    for i in 0..512 {
        let len = rng.below(96);
        let body: String = (0..len)
            .map(|_| alphabet[rng.below(alphabet.len())] as char)
            .collect();
        let mut rpc = Always::new(body.clone());
        let out = no_panic(&format!("random body #{i}: {body:?}"), || {
            run(&args(None), &mut rpc)
        });
        if let Ok(json) = out {
            let v: serde_json::Value = serde_json::from_str(&json).expect("tool output is JSON");
            assert_eq!(
                v["ready"], false,
                "random body #{i} reported READY: {body:?}"
            );
        }
    }
}

#[test]
fn a_seeded_sweep_of_random_account_data_never_panics() {
    // Account bytes are attacker-controlled in the worst case. READY is only
    // correct for exactly 80 bytes, tags 1 and 1, owned by the system program:
    // this asserts that oracle over random payloads rather than a class of
    // hand-picked ones.
    let owners = [SYSTEM_PROGRAM, TOKEN_PROGRAM, ATA_PROGRAM];
    let mut rng = Rng(0x6461_7461_5f73_7765);
    for i in 0..256 {
        let len = rng.below(121);
        let data: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let owner = owners[rng.below(owners.len())];
        let mut rpc = Always::new(account_resp(&data, owner));
        let case = format!("random data #{i}: {len} bytes owned by {owner}");
        let json = no_panic(&case, || run(&args(None), &mut rpc))
            .unwrap_or_else(|e| panic!("{case} failed instead of refusing: {e}"));
        let v: serde_json::Value = serde_json::from_str(&json).expect("tool output is JSON");
        let expected = len == 80
            && owner == SYSTEM_PROGRAM
            && u32::from_le_bytes(data[0..4].try_into().expect("four bytes")) == 1
            && u32::from_le_bytes(data[4..8].try_into().expect("four bytes")) == 1;
        assert_eq!(v["ready"], expected, "{case}: {json}");
    }
}
