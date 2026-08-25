//! Adversarial input: the arguments come from a model that can be talked into
//! anything, and the account bytes come from an endpoint nobody here controls.
//!
//! `tests/builder.rs` covers the happy paths and the policy refusals. This file
//! covers the encoder and the arithmetic: amount strings at the edges of u64,
//! mint accounts of every length including truncated Token-2022 extension data,
//! accounts owned by the wrong program, blockhashes that are not blockhashes,
//! and the compiled message decoded again to prove no instruction points past
//! the account list it ships with. Every refusal has to arrive without
//! transaction bytes, and nothing may panic: a panic in a component is a denial
//! of service for the whole agent.
//!
//! The generative sweeps run off fixed seeds, so a failure reproduces exactly.

use std::collections::BTreeMap;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use solana_core_wasi::amount::{from_base_units, to_base_units, AmountError};
use solana_core_wasi::encoding::{
    base64_decode, base64_encode, push_compact_u16, read_compact_u16,
};
use solana_core_wasi::pubkey::{derive_ata, token_2022_program, token_program, Pubkey};
use spl_transfer_build::builder::{run, BuildError, Lookups};

const SENDER: &str = "9B5XszUGdMaxCZ7uSQhPzdks5ZQSmWxrmzCSvtJ6Ns6g";
const RECIP: &str = "mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN";
const OTHER: &str = "SysvarC1ock11111111111111111111111111111111";
const USDC_DEV: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const NONCE_ACCT: &str = "8XkoSVfNbLKKzcpsTCyzysXbygqrGrbW8t5RS6Wxsdb1";
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// Solana's PACKET_DATA_SIZE: 1280-byte IPv6 MTU less the 40-byte header and
/// the 8-byte fragment header. A transaction over this cannot be sent.
const PACKET_DATA_SIZE: usize = 1232;

/// Replays captured response shapes by matching on the request body, the same
/// mock shape `tests/builder.rs` uses.
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

fn cfg(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn base_cfg() -> BTreeMap<String, String> {
    cfg(&[
        ("rpc_url", "https://api.devnet.solana.com"),
        ("allow_recipients", RECIP),
        ("caps", &format!("SOL:0.1:9,{USDC_DEV}:25:6")),
    ])
}

fn args(amount: &str, mint: Option<&str>, config: BTreeMap<String, String>) -> String {
    let mut v = serde_json::json!({
        "sender": SENDER,
        "recipient": RECIP,
        "amount": amount,
        "__config": config,
    });
    if let Some(m) = mint {
        v["mint"] = serde_json::json!(m);
    }
    v.to_string()
}

fn blockhash_resp() -> String {
    r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"blockhash":"J7rBdM6AecPDEZp8aPq5iPSNKVkU5Q76F3oAV4eW5wsW","lastValidBlockHeight":100}}}"#.to_string()
}

fn account_missing_resp() -> String {
    r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":null}}"#.to_string()
}

/// A getAccountInfo response carrying `data` and `owner` verbatim.
fn account_resp(data: &[u8], owner: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{"data":["{}","base64"],"owner":"{owner}","lamports":1461600,"executable":false,"rentEpoch":0,"space":{}}}}}}}"#,
        base64_encode(data),
        data.len()
    )
}
/// An SPL mint account body: decimals at offset 44, initialized flag at 45,
/// then whatever extension bytes the caller asked for.
fn mint_bytes(decimals: u8, initialized: u8, len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    if len > 45 {
        data[44] = decimals;
        data[45] = initialized;
    }
    data
}

fn mint_resp(decimals: u8) -> String {
    account_resp(&mint_bytes(decimals, 1, 82), TOKEN_PROGRAM)
}

/// The 80-byte nonce layout, owned by whichever program the caller names.
fn nonce_resp(authority: &str, owner: &str) -> String {
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&Pubkey::parse(authority).expect("fixture authority").0);
    data.extend_from_slice(&[0xCD; 32]);
    data.extend_from_slice(&5000u64.to_le_bytes());
    account_resp(&data, owner)
}

/// The three responses a full SPL build needs: blockhash, the mint and a
/// missing destination ATA. Order matters, the mint pattern is more specific.
fn spl_transcript(mint: String) -> MockRpc {
    MockRpc::new(vec![
        ("getLatestBlockhash", blockhash_resp()),
        (USDC_DEV, mint),
        ("getAccountInfo", account_missing_resp()),
    ])
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

/// What a validator reads back out of the compiled bytes. The builder writes
/// account indexes as single bytes, so the only way to prove it never points
/// past its own key list is to decode the message again.
struct Decoded {
    keys: usize,
    keys_b58: Vec<String>,
    signers: usize,
    readonly_signed: usize,
    readonly_unsigned: usize,
    instructions: Vec<(usize, Vec<usize>, usize)>,
    len: usize,
}

fn decode_unsigned_tx(case: &str, b64: &str) -> Decoded {
    let raw = base64_decode(b64).unwrap_or_else(|| panic!("{case}: not standard base64"));
    let (sig_count, prefix) =
        read_compact_u16(&raw).unwrap_or_else(|| panic!("{case}: no signature count"));
    let body_at = prefix + 64 * sig_count as usize;
    assert!(body_at + 3 <= raw.len(), "{case}: header past the end");
    let msg = &raw[body_at..];
    let signers = msg[0] as usize;
    assert_eq!(sig_count as usize, signers, "{case}: signature slots");
    let (key_count, key_prefix) =
        read_compact_u16(&msg[3..]).unwrap_or_else(|| panic!("{case}: no key count"));
    let keys = key_count as usize;
    let mut at = 3 + key_prefix + 32 * keys;
    assert!(
        at + 32 <= msg.len(),
        "{case}: keys or blockhash past the end"
    );
    at += 32;
    let (ix_count, used) =
        read_compact_u16(&msg[at..]).unwrap_or_else(|| panic!("{case}: no instruction count"));
    at += used;
    let mut instructions = Vec::new();
    for _ in 0..ix_count {
        assert!(at < msg.len(), "{case}: instruction past the end");
        let program = msg[at] as usize;
        at += 1;
        let (accounts, used) =
            read_compact_u16(&msg[at..]).unwrap_or_else(|| panic!("{case}: no account count"));
        at += used;
        let end = at + accounts as usize;
        assert!(end <= msg.len(), "{case}: account indexes past the end");
        let indexes = msg[at..end].iter().map(|&i| i as usize).collect();
        at = end;
        let (data_len, used) =
            read_compact_u16(&msg[at..]).unwrap_or_else(|| panic!("{case}: no data length"));
        at += used + data_len as usize;
        assert!(at <= msg.len(), "{case}: instruction data past the end");
        instructions.push((program, indexes, data_len as usize));
    }
    assert_eq!(
        at,
        msg.len(),
        "{case}: trailing bytes after the last instruction"
    );
    Decoded {
        keys,
        keys_b58: (0..keys)
            .map(|i| {
                let at = 3 + key_prefix + 32 * i;
                let mut key = [0u8; 32];
                key.copy_from_slice(&msg[at..at + 32]);
                Pubkey(key).to_base58()
            })
            .collect(),
        signers,
        readonly_signed: msg[1] as usize,
        readonly_unsigned: msg[2] as usize,
        instructions,
        len: raw.len(),
    }
}
#[test]
fn arguments_of_any_shape_never_panic_and_never_build() {
    // Models a prompt-injected or simply broken tool call. Every one of these
    // is refused before the network, and a refusal never carries bytes.
    let config = serde_json::to_value(base_cfg()).expect("config serializes");
    let base = serde_json::json!({
        "sender": SENDER,
        "recipient": RECIP,
        "amount": "0.01",
        "__config": config,
    });
    let with = |field: &str, value: serde_json::Value| {
        let mut v = base.clone();
        v[field] = value;
        v.to_string()
    };
    let without = |field: &str| {
        let mut v = base.clone();
        v.as_object_mut().expect("object").remove(field);
        v.to_string()
    };
    let long = "z".repeat(50_000);
    let nested = format!("{}{}", "[".repeat(100), "]".repeat(100));
    let cases = [
        ("json null", "null".to_string()),
        ("json array", "[]".to_string()),
        ("empty object", "{}".to_string()),
        ("not json at all", "sender=alice&amount=1".to_string()),
        ("truncated json", r#"{"sender":"#.to_string()),
        (
            "nesting past the parser's limit",
            format!(
                r#"{{"sender":{}{},"amount":"1"}}"#,
                "[".repeat(400),
                "]".repeat(400)
            ),
        ),
        (
            "duplicate sender member",
            format!(
                r#"{{"sender":"{SENDER}","sender":"{OTHER}","recipient":"{RECIP}","amount":"0.01","__config":{config}}}"#
            ),
        ),
        ("sender missing", without("sender")),
        ("recipient missing", without("recipient")),
        ("amount missing", without("amount")),
        ("config missing", without("__config")),
        ("amount is a number", with("amount", serde_json::json!(25))),
        ("amount is null", with("amount", serde_json::json!(null))),
        ("amount is an array", with("amount", serde_json::json!([1]))),
        ("amount is a bool", with("amount", serde_json::json!(true))),
        (
            "amount is deeply nested",
            with(
                "amount",
                serde_json::from_str(&nested).expect("nested array"),
            ),
        ),
        (
            "amount is ten thousand digits",
            with("amount", serde_json::json!("1".repeat(10_000))),
        ),
        ("sender is a number", with("sender", serde_json::json!(7))),
        (
            "sender is over-long",
            with("sender", serde_json::json!(long)),
        ),
        (
            "recipient is over-long",
            with("recipient", serde_json::json!(long)),
        ),
        (
            "config is a string",
            with("__config", serde_json::json!("rpc_url=x")),
        ),
        (
            "config is an array",
            with("__config", serde_json::json!([])),
        ),
        (
            "config value is a number",
            with("__config", serde_json::json!({"rpc_url": 7})),
        ),
        (
            "unknown argument",
            with("skip_checks", serde_json::json!(true)),
        ),
        ("mint is a number", with("mint", serde_json::json!(6))),
        ("mint is empty", with("mint", serde_json::json!(""))),
        ("memo is a number", with("memo", serde_json::json!(7))),
        (
            "memo is 257 bytes",
            with("memo", serde_json::json!("m".repeat(257))),
        ),
        (
            "memo is a megabyte",
            with("memo", serde_json::json!("m".repeat(1_000_000))),
        ),
        (
            "reference is empty",
            with("reference", serde_json::json!("")),
        ),
        (
            "reference is a number",
            with("reference", serde_json::json!(7)),
        ),
    ];
    for (case, raw) in cases {
        let mut rpc = spl_transcript(mint_resp(6));
        match no_panic(case, || run(&raw, &mut rpc)) {
            Ok(out) => panic!("{case}: built a transaction from bad arguments: {out}"),
            Err(e) => {
                assert!(
                    matches!(
                        e,
                        BuildError::BadArgs(_) | BuildError::Policy(_) | BuildError::Refused { .. }
                    ),
                    "{case}: expected an argument or policy refusal, got {e}"
                );
                assert!(
                    !e.to_string().contains("unsigned"),
                    "{case}: a refusal mentioned transaction bytes"
                );
            }
        }
        assert!(rpc.calls.is_empty(), "{case} reached the network");
    }
}
#[test]
fn amount_strings_are_exact_or_refused() {
    // The amount arrives as a string from the model. Anything that is not an
    // exact decimal in the mint's precision is refused rather than rounded:
    // rounding here is somebody's money.
    for (amount, decimals, expected) in [
        ("0.1", 9u8, Ok(100_000_000u64)),
        ("0.000000001", 9, Ok(1)),
        (".5", 9, Ok(500_000_000)),
        ("00000000000000000000000001", 9, Ok(1_000_000_000)),
        ("9007199.254740993", 9, Ok(9_007_199_254_740_993)),
        ("25", 6, Ok(25_000_000)),
        ("", 9, Err(AmountError::Empty)),
        (".", 9, Err(AmountError::Empty)),
        ("-1", 9, Err(AmountError::BadChar)),
        ("+1", 9, Err(AmountError::BadChar)),
        (" 1", 9, Err(AmountError::BadChar)),
        ("1 ", 9, Err(AmountError::BadChar)),
        ("1_000", 9, Err(AmountError::BadChar)),
        ("\u{661}\u{662}", 9, Err(AmountError::BadChar)),
        ("\u{ff11}", 9, Err(AmountError::BadChar)),
        ("1e6", 9, Err(AmountError::ScientificNotation)),
        ("1E6", 9, Err(AmountError::ScientificNotation)),
        ("1.2.3", 9, Err(AmountError::TooManyDots)),
        ("0", 9, Err(AmountError::Zero)),
        ("0.000000000", 9, Err(AmountError::Zero)),
        (
            "0.0000000001",
            9,
            Err(AmountError::TooManyDecimals {
                given: 10,
                allowed: 9,
            }),
        ),
        ("18446744073709551616", 0, Err(AmountError::Overflow)),
        ("18446744073709.551616", 6, Err(AmountError::Overflow)),
        ("184467440737095516150", 0, Err(AmountError::Overflow)),
    ] {
        assert_eq!(
            to_base_units(amount, decimals),
            expected,
            "amount {amount:?} at {decimals} decimals"
        );
    }

    // End to end: the cap itself builds, one base unit past it refuses.
    let mut rpc = MockRpc::new(vec![("getLatestBlockhash", blockhash_resp())]);
    run(&args("0.1", None, base_cfg()), &mut rpc).expect("the cap itself must build");
    let mut rpc = MockRpc::new(vec![("getLatestBlockhash", blockhash_resp())]);
    let err = run(&args("0.100000001", None, base_cfg()), &mut rpc)
        .expect_err("one lamport over the cap must refuse");
    assert!(
        err.to_string()
            .contains("exceeds the operator's per-transfer cap"),
        "{err}"
    );
    assert!(rpc.calls.is_empty(), "refused before the network");
}

#[test]
fn amount_arithmetic_never_wraps_in_either_direction() {
    // Release builds wrap instead of panicking, so both directions have to be
    // total: render any (u64, u8) pair exactly, and refuse anything that cannot
    // be held rather than computing with a wrapped divisor.
    let mut rng = Rng(0x616d_6f75_6e74_7331);
    let mut values = vec![
        0u64,
        1,
        2,
        9,
        10,
        99,
        100,
        1_000_000,
        10_000_000_000_000_000_000,
        u64::MAX - 1,
        u64::MAX,
    ];
    for _ in 0..48 {
        values.push(rng.next_u64());
    }
    for units in values {
        for decimals in 0u8..=255 {
            let rendered = no_panic(&format!("from_base_units({units}, {decimals})"), || {
                from_base_units(units, decimals)
            });
            let back = to_base_units(&rendered, decimals);
            if units == 0 {
                assert_eq!(
                    back,
                    Err(AmountError::Zero),
                    "zero at {decimals} decimals rendered {rendered}"
                );
            } else {
                assert_eq!(
                    back,
                    Ok(units),
                    "{units} at {decimals} decimals rendered {rendered}"
                );
            }
        }
    }
}
#[test]
fn the_compiled_message_never_references_an_account_it_does_not_carry() {
    // Account indexes are single bytes on the wire. An index past the end of
    // the message's own key list would still look well-formed and would name
    // the wrong account, so the emitted bytes get decoded again and checked.
    let mut nonce_cfg = base_cfg();
    nonce_cfg.insert("nonce_account".to_string(), NONCE_ACCT.to_string());
    let with = |amount: &str,
                mint: Option<&str>,
                extra: &[(&str, &str)],
                config: BTreeMap<String, String>| {
        let mut v: serde_json::Value =
            serde_json::from_str(&args(amount, mint, config)).expect("args are JSON");
        for (k, val) in extra {
            v[*k] = serde_json::json!(val);
        }
        v.to_string()
    };
    let memo_256 = "m".repeat(256);
    let existing_ata = account_resp(&mint_bytes(6, 1, 165), TOKEN_PROGRAM);
    let blockhash_only = || MockRpc::new(vec![("getLatestBlockhash", blockhash_resp())]);
    let cases = [
        (
            "sol",
            with("0.05", None, &[], base_cfg()),
            blockhash_only(),
            1,
        ),
        (
            "sol with a 256-byte memo",
            with("0.05", None, &[("memo", &memo_256)], base_cfg()),
            blockhash_only(),
            2,
        ),
        (
            "sol with a reference",
            with("0.05", None, &[("reference", OTHER)], base_cfg()),
            blockhash_only(),
            1,
        ),
        (
            "sol with memo and reference",
            with(
                "0.05",
                None,
                &[("memo", "invoice #412"), ("reference", OTHER)],
                base_cfg(),
            ),
            blockhash_only(),
            2,
        ),
        (
            "spl with the destination ata missing",
            with("25", Some(USDC_DEV), &[], base_cfg()),
            spl_transcript(mint_resp(6)),
            2,
        ),
        (
            "spl with memo and reference",
            with(
                "25",
                Some(USDC_DEV),
                &[("memo", "invoice #412"), ("reference", OTHER)],
                base_cfg(),
            ),
            spl_transcript(mint_resp(6)),
            3,
        ),
        (
            "spl with the destination ata present",
            with("25", Some(USDC_DEV), &[], base_cfg()),
            MockRpc::new(vec![
                ("getLatestBlockhash", blockhash_resp()),
                (USDC_DEV, mint_resp(6)),
                ("getAccountInfo", existing_ata),
            ]),
            1,
        ),
        (
            "durable nonce, sol",
            with("0.05", None, &[], nonce_cfg.clone()),
            MockRpc::new(vec![(NONCE_ACCT, nonce_resp(SENDER, SYSTEM_PROGRAM))]),
            2,
        ),
        (
            "durable nonce, spl",
            with("25", Some(USDC_DEV), &[], nonce_cfg.clone()),
            MockRpc::new(vec![
                (NONCE_ACCT, nonce_resp(SENDER, SYSTEM_PROGRAM)),
                (USDC_DEV, mint_resp(6)),
                ("getAccountInfo", account_missing_resp()),
            ]),
            3,
        ),
    ];
    for (case, raw, mut rpc, instructions) in cases {
        let out = no_panic(case, || run(&raw, &mut rpc))
            .unwrap_or_else(|e| panic!("{case} did not build: {e}"));
        let v: serde_json::Value = serde_json::from_str(&out).expect("tool output is JSON");
        let d = decode_unsigned_tx(
            case,
            v["unsigned_transaction_base64"]
                .as_str()
                .expect("transaction bytes"),
        );
        assert_eq!(
            d.instructions.len(),
            instructions,
            "{case}: instruction count"
        );
        assert_eq!(d.signers, 1, "{case}: only the sender signs");
        assert_eq!(
            d.readonly_signed, 0,
            "{case}: the sender signs and is writable"
        );
        assert!(d.keys >= 2, "{case}: only {} account keys", d.keys);
        assert!(
            d.readonly_unsigned < d.keys,
            "{case}: readonly count {} past {} keys",
            d.readonly_unsigned,
            d.keys
        );
        for (program, indexes, _) in &d.instructions {
            assert!(
                *program < d.keys,
                "{case}: program index {program} past {} keys",
                d.keys
            );
            for i in indexes {
                assert!(
                    *i < d.keys,
                    "{case}: account index {i} past {} keys",
                    d.keys
                );
            }
        }
        assert!(
            d.len <= PACKET_DATA_SIZE,
            "{case}: {} bytes is over the {PACKET_DATA_SIZE}-byte packet limit",
            d.len
        );
    }
}
#[test]
fn compact_u16_lengths_round_trip_and_refuse_overruns() {
    // The length prefix in front of every vector in a message. A decoder that
    // accepts a truncated or non-minimal prefix disagrees with the runtime
    // about where the next field starts.
    for n in [0u16, 1, 0x7f, 0x80, 0xff, 0x3fff, 0x4000, 0x7fff, 0xffff] {
        let mut out = Vec::new();
        push_compact_u16(n, &mut out);
        assert!(out.len() <= 3, "{n:#x} encoded to {} bytes", out.len());
        assert_eq!(read_compact_u16(&out), Some((n, out.len())), "{n:#x}");
    }
    // Truncated: a continuation bit with nothing behind it.
    assert_eq!(read_compact_u16(&[]), None);
    assert_eq!(read_compact_u16(&[0x80]), None);
    assert_eq!(read_compact_u16(&[0x80, 0x80]), None);
    // A third byte that still continues and a value past u16.
    assert_eq!(read_compact_u16(&[0x80, 0x80, 0x80]), None);
    assert_eq!(read_compact_u16(&[0xff, 0xff, 0x04]), None);
    assert_eq!(read_compact_u16(&[0xff, 0xff, 0xff]), None);
    // Aliased: a length written in more bytes than it needs. solana-sdk's
    // short-vec rejects this as VisitError::Alias, so two different byte
    // strings can never claim the same length.
    assert_eq!(read_compact_u16(&[0x80, 0x00]), None);
    assert_eq!(read_compact_u16(&[0xff, 0x00]), None);
    assert_eq!(read_compact_u16(&[0x80, 0x80, 0x00]), None);
    // Trailing bytes belong to the next field, not to this one.
    assert_eq!(read_compact_u16(&[0x00]), Some((0, 1)));
    assert_eq!(read_compact_u16(&[0x01, 0xff, 0xff]), Some((1, 1)));
    let mut rng = Rng(0x7368_6f72_7476_6563);
    for _ in 0..512 {
        let n = (rng.next_u64() >> 48) as u16;
        let mut out = Vec::new();
        push_compact_u16(n, &mut out);
        assert_eq!(read_compact_u16(&out), Some((n, out.len())), "{n:#x}");
    }
}

#[test]
fn mint_account_data_of_every_length_is_classified() {
    // Models a truncated mint and a Token-2022 mint whose extension bytes are
    // cut short. Decimals live at offset 44 of the 82-byte base layout, so
    // anything shorter refuses, and extension bytes past the base do not move
    // the decimals.
    for len in [0usize, 1, 44, 45, 46, 60, 81, 82, 83, 100, 165, 182, 400] {
        let mut rpc = spl_transcript(account_resp(&mint_bytes(6, 1, len), TOKEN_PROGRAM));
        let out = no_panic(&format!("{len}-byte mint"), || {
            run(&args("25", Some(USDC_DEV), base_cfg()), &mut rpc)
        });
        if len >= 82 {
            let json = out.unwrap_or_else(|e| panic!("{len}-byte mint refused a valid base: {e}"));
            let v: serde_json::Value = serde_json::from_str(&json).expect("tool output is JSON");
            let d = decode_unsigned_tx(
                &format!("{len}-byte mint"),
                v["unsigned_transaction_base64"]
                    .as_str()
                    .expect("transaction bytes"),
            );
            assert!(d.len <= PACKET_DATA_SIZE);
        } else {
            let err = out.expect_err("a mint shorter than the base layout must refuse");
            assert!(matches!(err, BuildError::Rpc(_)), "{len}-byte mint: {err}");
        }
    }
    // An uninitialized mint refuses at every length.
    for len in [82usize, 165, 400] {
        let mut rpc = spl_transcript(account_resp(&mint_bytes(6, 0, len), TOKEN_PROGRAM));
        let err = run(&args("25", Some(USDC_DEV), base_cfg()), &mut rpc)
            .expect_err("an uninitialized mint must refuse");
        assert!(
            err.to_string().contains("not initialized"),
            "{len}-byte uninitialized mint: {err}"
        );
    }
}
#[test]
fn a_mint_account_owned_by_another_program_is_refused() {
    // The mint's owner decides the ATA derivation and the program the transfer
    // is addressed to. An owner that is neither token program is refused by
    // name: guessing one would build a transaction that cannot execute while
    // the digest describes one that can.
    for owner in [SYSTEM_PROGRAM, RECIP, SENDER, ATA_PROGRAM] {
        let mut rpc = spl_transcript(account_resp(&mint_bytes(6, 1, 82), owner));
        let err = run(&args("25", Some(USDC_DEV), base_cfg()), &mut rpc)
            .expect_err("a mint owned by another program must refuse");
        assert!(
            matches!(err, BuildError::Refused { .. }),
            "owner {owner}: {err}"
        );
        let shown = err.to_string();
        assert!(
            shown.contains("owned by") && shown.contains(owner),
            "the refusal must name the owner it saw: {shown}"
        );
        assert!(
            shown.contains("Token-2022"),
            "the refusal must say which programs are accepted: {shown}"
        );
        assert!(
            !shown.contains("unsigned"),
            "owner {owner}: a refusal mentioned transaction bytes"
        );
    }
    for owner in [TOKEN_PROGRAM, TOKEN_2022] {
        let mut rpc = spl_transcript(account_resp(&mint_bytes(6, 1, 82), owner));
        run(&args("25", Some(USDC_DEV), base_cfg()), &mut rpc)
            .unwrap_or_else(|e| panic!("a mint owned by {owner} must build: {e}"));
    }
}

#[test]
fn a_token_2022_mint_never_derives_a_classic_ata() {
    // The defect this pins: the mint's owner was fetched and discarded, the ATA
    // was always derived under the classic program, and the transfer was always
    // addressed to it. A Token-2022 mint has the same 82-byte base layout, so
    // the decimals read correctly and the tool produced a transaction naming
    // accounts that program will never accept.
    let mint = Pubkey::parse(USDC_DEV).expect("mint");
    let sender = Pubkey::parse(SENDER).expect("sender");
    let recipient = Pubkey::parse(RECIP).expect("recipient");
    let classic = token_program();
    let t22 = token_2022_program();
    assert_eq!(t22.to_base58(), TOKEN_2022, "the fixture names Token-2022");

    let mut rpc = spl_transcript(account_resp(&mint_bytes(6, 1, 82), TOKEN_2022));
    let out = run(&args("25", Some(USDC_DEV), base_cfg()), &mut rpc)
        .expect("a Token-2022 mint is a supported transfer");
    let v: serde_json::Value = serde_json::from_str(&out).expect("tool output is JSON");
    let d = decode_unsigned_tx(
        "token-2022 transfer",
        v["unsigned_transaction_base64"]
            .as_str()
            .expect("transaction bytes"),
    );

    for wallet in [sender, recipient] {
        let wrong = derive_ata(&wallet, &mint, &classic).to_base58();
        let right = derive_ata(&wallet, &mint, &t22).to_base58();
        assert_ne!(wrong, right, "the two derivations must differ");
        assert!(
            d.keys_b58.contains(&right),
            "the Token-2022 ATA {right} is not in the account list {:?}",
            d.keys_b58
        );
        assert!(
            !d.keys_b58.contains(&wrong),
            "the classic ATA {wrong} is in the account list for a Token-2022 mint"
        );
    }
    assert!(
        d.keys_b58.contains(&TOKEN_2022.to_string()),
        "the transaction must carry the Token-2022 program id: {:?}",
        d.keys_b58
    );
    assert!(
        !d.keys_b58.contains(&TOKEN_PROGRAM.to_string()),
        "the classic token program is not part of a Token-2022 transfer"
    );
    // The transfer is the last instruction, and it must be addressed to the
    // program that owns the mint.
    let (program, _, _) = d.instructions.last().expect("at least one instruction");
    assert_eq!(
        d.keys_b58[*program], TOKEN_2022,
        "the transfer instruction went to the wrong program"
    );
    assert!(
        v["summary"]
            .as_str()
            .expect("summary")
            .contains("Token-2022"),
        "the digest the human signs off on must say which program: {out}"
    );
}

#[test]
fn a_nonce_account_owned_by_another_program_is_refused() {
    // A durable-nonce transaction carries the account's stored hash as its
    // blockhash, so whoever owns those 80 bytes chooses it. nonce-status
    // already refuses an account the system program does not own, and the
    // builder has to agree or the two tools describe the same account
    // differently.
    let mut nonce_cfg = base_cfg();
    nonce_cfg.insert("nonce_account".to_string(), NONCE_ACCT.to_string());
    for owner in [TOKEN_PROGRAM, TOKEN_2022, RECIP] {
        let mut rpc = MockRpc::new(vec![(NONCE_ACCT, nonce_resp(SENDER, owner))]);
        let err = run(&args("0.05", None, nonce_cfg.clone()), &mut rpc)
            .expect_err("a nonce account owned by another program must refuse");
        assert!(
            matches!(err, BuildError::Refused { .. }),
            "owner {owner}: {err}"
        );
        assert!(
            err.to_string().contains("system program"),
            "owner {owner}: {err}"
        );
    }
    let mut rpc = MockRpc::new(vec![(NONCE_ACCT, nonce_resp(SENDER, SYSTEM_PROGRAM))]);
    run(&args("0.05", None, nonce_cfg), &mut rpc).expect("a real nonce account must build");
}

#[test]
fn cap_decimals_that_disagree_with_the_chain_refuse_in_both_directions() {
    // The operator's cap is written at some precision and the mint's lives on
    // chain. If they disagree the amount would be scaled by the wrong power of
    // ten, which is how 25 USDC becomes 25,000.
    for chain in [0u8, 1, 3, 5, 7, 9, 18, 255] {
        let mut rpc = spl_transcript(mint_resp(chain));
        let err = run(&args("25", Some(USDC_DEV), base_cfg()), &mut rpc)
            .expect_err("a decimals mismatch must refuse");
        assert!(
            matches!(err, BuildError::Refused { .. }),
            "chain decimals {chain}: {err}"
        );
        assert!(
            err.to_string().contains("decimals"),
            "chain decimals {chain}: {err}"
        );
    }
    let mut rpc = spl_transcript(mint_resp(6));
    run(&args("25", Some(USDC_DEV), base_cfg()), &mut rpc).expect("matching decimals must build");
}
#[test]
fn blockhash_responses_of_any_shape_refuse() {
    // The blockhash is the 32 bytes the transaction is built around. A missing
    // or malformed one must not produce a transaction at all.
    let cases = [
        ("empty body", String::new()),
        ("json null", "null".to_string()),
        ("result null", r#"{"result":null}"#.to_string()),
        (
            "value missing",
            r#"{"result":{"context":{"slot":1}}}"#.to_string(),
        ),
        (
            "blockhash missing",
            r#"{"result":{"value":{"lastValidBlockHeight":1}}}"#.to_string(),
        ),
        (
            "blockhash is null",
            r#"{"result":{"value":{"blockhash":null}}}"#.to_string(),
        ),
        (
            "blockhash is a number",
            r#"{"result":{"value":{"blockhash":7}}}"#.to_string(),
        ),
        (
            "blockhash is empty",
            r#"{"result":{"value":{"blockhash":""}}}"#.to_string(),
        ),
        (
            "blockhash is not base58",
            r#"{"result":{"value":{"blockhash":"0OIl"}}}"#.to_string(),
        ),
        (
            "blockhash is 31 bytes",
            format!(
                r#"{{"result":{{"value":{{"blockhash":"{}"}}}}}}"#,
                "1".repeat(31)
            ),
        ),
        (
            "blockhash is far too long",
            format!(
                r#"{{"result":{{"value":{{"blockhash":"{}"}}}}}}"#,
                "z".repeat(4096)
            ),
        ),
        (
            "rpc error",
            r#"{"error":{"code":-32005,"message":"behind"}}"#.to_string(),
        ),
        ("html error page", "<html>504</html>".to_string()),
        (
            "deeply nested",
            format!(r#"{{"result":{}{}}}"#, "[".repeat(400), "]".repeat(400)),
        ),
    ];
    for (case, body) in cases {
        let mut rpc = MockRpc::new(vec![("getLatestBlockhash", body)]);
        let err = no_panic(case, || run(&args("0.05", None, base_cfg()), &mut rpc))
            .err()
            .unwrap_or_else(|| panic!("{case}: built a transaction without a blockhash"));
        assert!(matches!(err, BuildError::Rpc(_)), "{case}: {err}");
    }
}
#[test]
fn operator_config_soup_fails_closed() {
    // Config is operator-controlled, but a typo in it is exactly how a cap
    // silently stops existing. Every one of these denies rather than guesses,
    // and none of them costs an RPC call.
    let good = [
        ("rpc_url", "https://api.devnet.solana.com"),
        ("allow_recipients", RECIP),
        ("caps", "SOL:0.1:9"),
    ];
    let long = "z".repeat(4096);
    let overrides = [
        ("plain http", "rpc_url", "http://x.example"),
        ("no scheme", "rpc_url", "api.devnet.solana.com"),
        ("empty rpc url", "rpc_url", ""),
        ("empty allowlist", "allow_recipients", ""),
        ("allowlist of commas", "allow_recipients", ",,,"),
        ("bad allowlist entry", "allow_recipients", "not-a-key"),
        (
            "allowlist entry far too long",
            "allow_recipients",
            long.as_str(),
        ),
        ("cap with two fields", "caps", "SOL:0.1"),
        ("cap with four fields", "caps", "SOL:0.1:9:extra"),
        ("cap with no amount", "caps", "SOL::9"),
        ("cap with a negative amount", "caps", "SOL:-1:9"),
        ("cap at zero", "caps", "SOL:0:9"),
        ("cap with bad decimals", "caps", "SOL:0.1:x"),
        ("cap with 256 decimals", "caps", "SOL:0.1:256"),
        ("sol at the wrong decimals", "caps", "SOL:0.1:6"),
        ("cap in scientific notation", "caps", "SOL:1e2:9"),
        ("cap for a bad mint", "caps", "badmint:1:6"),
        ("empty caps", "caps", ""),
        ("unknown key", "max_amout", "999"),
        ("misspelled rpc url key", "rcp_url", "https://x.example"),
        ("nonce account is not a key", "nonce_account", "nope"),
        ("nonce account far too long", "nonce_account", long.as_str()),
    ];
    for (case, key, value) in overrides {
        let mut c = cfg(&good);
        c.insert(key.to_string(), value.to_string());
        let mut rpc = MockRpc::new(vec![]);
        let err = no_panic(case, || run(&args("0.05", None, c), &mut rpc))
            .err()
            .unwrap_or_else(|| panic!("{case}: built a transaction under a broken policy"));
        assert!(
            matches!(
                err,
                BuildError::Policy(_) | BuildError::BadArgs(_) | BuildError::Refused { .. }
            ),
            "{case}: {err}"
        );
        assert!(rpc.calls.is_empty(), "{case} reached the network");
    }
    for missing in ["rpc_url", "allow_recipients", "caps"] {
        let mut c = cfg(&good);
        c.remove(missing);
        let mut rpc = MockRpc::new(vec![]);
        let err = run(&args("0.05", None, c), &mut rpc)
            .expect_err("a missing policy member must deny everything");
        assert!(
            matches!(err, BuildError::Policy(_)),
            "{missing} missing: {err}"
        );
        assert!(rpc.calls.is_empty());
    }
}
#[test]
fn the_same_arguments_twice_build_byte_identical_transactions() {
    // Key ordering runs through a HashMap, which std seeds randomly per
    // process. The order is meant to come from first-seen position and a stable
    // sort, so two identical calls must produce identical bytes, and the same
    // must hold for a refusal.
    let mut nonce_cfg = base_cfg();
    nonce_cfg.insert("nonce_account".to_string(), NONCE_ACCT.to_string());
    let cases = [
        ("sol", args("0.05", None, base_cfg()), 0),
        ("spl", args("25", Some(USDC_DEV), base_cfg()), 1),
        ("durable nonce", args("0.05", None, nonce_cfg), 2),
        ("refusal", args("99", None, base_cfg()), 0),
    ];
    for (case, raw, kind) in cases {
        let transport = || match kind {
            1 => spl_transcript(mint_resp(6)),
            2 => MockRpc::new(vec![(NONCE_ACCT, nonce_resp(SENDER, SYSTEM_PROGRAM))]),
            _ => MockRpc::new(vec![("getLatestBlockhash", blockhash_resp())]),
        };
        let mut a = transport();
        let mut b = transport();
        let first = format!("{:?}", run(&raw, &mut a));
        let second = format!("{:?}", run(&raw, &mut b));
        assert_eq!(first, second, "{case} disagreed with itself");
        assert_eq!(a.calls, b.calls, "{case} issued different requests");
    }
}

#[test]
fn nothing_in_the_decision_path_reads_a_clock_or_random_bytes() {
    // A transaction that depends on when it was built cannot be reviewed twice
    // and cannot be reproduced by the human who has to sign it.
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
fn a_seeded_sweep_of_random_arguments_never_panics() {
    // Field by field, whatever a talked-into model might send. Nothing may be
    // fatal, and anything that does build still has to satisfy the encoder's
    // own invariants.
    let pool = [
        "",
        " ",
        "0",
        "-1",
        "1e9",
        ".",
        "..",
        "0.0",
        "0.05",
        "25",
        "SOL",
        "sol",
        RECIP,
        SENDER,
        OTHER,
        USDC_DEV,
        "0OIl",
        "1111111111111111111111111111111111111111111111",
        "\u{0}",
        "\u{feff}",
        "25.0000001",
        "99999999999999999999999999",
        "true",
        "null",
        "[]",
    ];
    let mut rng = Rng(0x6275_696c_6465_7231);
    for i in 0..384 {
        let mut v =
            serde_json::json!({ "__config": serde_json::to_value(base_cfg()).expect("config") });
        for field in ["sender", "recipient", "amount", "mint", "memo", "reference"] {
            if rng.below(4) > 0 {
                v[field] = serde_json::json!(pool[rng.below(pool.len())]);
            }
        }
        let raw = v.to_string();
        let mut rpc = spl_transcript(mint_resp(6));
        let case = format!("random arguments #{i}: {raw:.200}");
        if let Ok(out) = no_panic(&case, || run(&raw, &mut rpc)) {
            let parsed: serde_json::Value = serde_json::from_str(&out).expect("output is JSON");
            let d = decode_unsigned_tx(
                &case,
                parsed["unsigned_transaction_base64"]
                    .as_str()
                    .expect("transaction bytes"),
            );
            assert!(d.len <= PACKET_DATA_SIZE, "{case}: {} bytes", d.len);
            for (program, indexes, _) in &d.instructions {
                assert!(*program < d.keys, "{case}: program index past the key list");
                for index in indexes {
                    assert!(*index < d.keys, "{case}: account index past the key list");
                }
            }
        }
    }
}
