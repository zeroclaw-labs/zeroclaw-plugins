//! Host tests for the spl-transfer-build core: mocked RPC, no network, no
//! wasm toolchain. Covers the happy paths (SOL, SPL with/without ATA
//! creation, durable nonce) and the fail-closed paths (policy refusals,
//! injection attempts, decimal mismatches, RPC failures).

use std::collections::BTreeMap;

use spl_transfer_build::builder::{plan, run, Args, BuildError, Lookups};

const SENDER: &str = "9B5XszUGdMaxCZ7uSQhPzdks5ZQSmWxrmzCSvtJ6Ns6g";
const RECIP: &str = "mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN";
const OTHER: &str = "SysvarC1ock11111111111111111111111111111111";
const USDC_DEV: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const NONCE_ACCT: &str = "8XkoSVfNbLKKzcpsTCyzysXbygqrGrbW8t5RS6Wxsdb1";

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

/// Mock transport: pattern-matches on the request method and replays
/// captured devnet response shapes.
struct MockRpc {
    /// (method substring, response) pairs, consumed in order of match.
    responses: Vec<(&'static str, String)>,
    pub calls: Vec<String>,
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

fn blockhash_resp() -> String {
    r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"blockhash":"J7rBdM6AecPDEZp8aPq5iPSNKVkU5Q76F3oAV4eW5wsW","lastValidBlockHeight":100}}}"#.to_string()
}

fn account_missing_resp() -> String {
    r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":null}}"#.to_string()
}

fn mint_resp(decimals: u8) -> String {
    // 82-byte mint: decimals at 44, initialized at 45.
    let mut data = [0u8; 82];
    data[44] = decimals;
    data[45] = 1;
    let b64 = {
        // reuse the crate's encoder through a tiny local shim
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in data.chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            s.push(T[(n >> 18) as usize & 63] as char);
            s.push(T[(n >> 12) as usize & 63] as char);
            s.push(if c.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            s.push(if c.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        s
    };
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{"data":["{b64}","base64"],"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","lamports":1,"executable":false,"rentEpoch":0,"space":82}}}}}}"#
    )
}

fn nonce_resp(authority_b58: &str) -> String {
    let auth = bs58_decode32(authority_b58);
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&auth);
    data.extend_from_slice(&[0xCD; 32]);
    data.extend_from_slice(&5000u64.to_le_bytes());
    let b64 = base64(&data);
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{"data":["{b64}","base64"],"owner":"11111111111111111111111111111111","lamports":1447680,"executable":false,"rentEpoch":0,"space":80}}}}}}"#
    )
}

fn bs58_decode32(s: &str) -> [u8; 32] {
    // minimal base58 decode for fixtures
    const ALPHA: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num = vec![0u8];
    for c in s.chars() {
        let d = ALPHA.find(c).unwrap() as u32;
        let mut carry = d;
        for b in num.iter_mut().rev() {
            let v = (*b as u32) * 58 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    for c in s.chars() {
        if c == '1' {
            num.insert(0, 0);
        } else {
            break;
        }
    }
    let start = num.len().saturating_sub(32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&num[start..]);
    out
}

fn base64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
}

// ---------- happy paths ----------

#[test]
fn sol_transfer_fresh_blockhash() {
    let mut rpc = MockRpc::new(vec![("getLatestBlockhash", blockhash_resp())]);
    let out = run(&args("0.05", None, base_cfg()), &mut rpc).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v["unsigned_transaction_base64"].as_str().unwrap().len() > 100);
    assert_eq!(v["durable_nonce"], false);
    let s = v["summary"].as_str().unwrap();
    assert!(s.contains("UNSIGNED") && s.contains("0.05 SOL") && s.contains("holds no keys"));
    assert!(s.contains("sign within"), "fresh-blockhash warning present");
}

#[test]
fn spl_transfer_creates_missing_ata() {
    let mut rpc = MockRpc::new(vec![
        ("getLatestBlockhash", blockhash_resp()),
        (USDC_DEV, mint_resp(6)),
        // any other getAccountInfo (the dst ATA) → missing
        ("getAccountInfo", account_missing_resp()),
    ]);
    let out = run(&args("25", Some(USDC_DEV), base_cfg()), &mut rpc).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v["summary"].as_str().unwrap().contains("25 mint"));
    // mint lookup + ata lookup + blockhash = 3 calls
    assert_eq!(rpc.calls.len(), 3);
}

#[test]
fn durable_nonce_mode() {
    let mut c = base_cfg();
    c.insert("nonce_account".into(), NONCE_ACCT.into());
    let mut rpc = MockRpc::new(vec![
        (NONCE_ACCT, nonce_resp(SENDER)),
        (USDC_DEV, mint_resp(6)),
        ("getAccountInfo", account_missing_resp()),
    ]);
    let out = run(&args("25", Some(USDC_DEV), c), &mut rpc).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["durable_nonce"], true);
    assert!(v["summary"]
        .as_str()
        .unwrap()
        .contains("safe to approve later"));
    // no getLatestBlockhash call in nonce mode
    assert!(!rpc.calls.iter().any(|c| c.contains("getLatestBlockhash")));
}

// ---------- fail-closed paths ----------

#[test]
fn refuses_recipient_off_allowlist() {
    let mut v: serde_json::Value = serde_json::from_str(&args("0.05", None, base_cfg())).unwrap();
    v["recipient"] = serde_json::json!(OTHER);
    let mut rpc = MockRpc::new(vec![]);
    let err = run(&v.to_string(), &mut rpc).unwrap_err();
    assert!(matches!(err, BuildError::Refused { .. }));
    assert!(err.to_string().contains("not on the operator's allowlist"));
    assert!(rpc.calls.is_empty(), "refused BEFORE any network call");
}

#[test]
fn refuses_over_cap() {
    let mut rpc = MockRpc::new(vec![]);
    let err = run(&args("0.2", None, base_cfg()), &mut rpc).unwrap_err();
    assert!(err
        .to_string()
        .contains("exceeds the operator's per-transfer cap"));
    assert!(rpc.calls.is_empty());
}

#[test]
fn refuses_unknown_mint() {
    let mut rpc = MockRpc::new(vec![]);
    let err = run(&args("1", Some(OTHER), base_cfg()), &mut rpc).unwrap_err();
    assert!(err.to_string().contains("not in the operator's cap list"));
    assert!(rpc.calls.is_empty());
}

#[test]
fn injection_cannot_spoof_config() {
    // A malicious caller supplies its own __config with a fat cap and its own
    // recipient. serde(deny_unknown_fields) + the host's __config stripping
    // both stand in the way; here we simulate the *tool-level* guarantee:
    // whatever lands in __config IS the policy, and a caller-supplied
    // recipient outside it is refused. The transcript for the README.
    let evil_cfg = cfg(&[
        ("rpc_url", "https://api.devnet.solana.com"),
        ("allow_recipients", RECIP), // operator's real allowlist
        ("caps", "SOL:0.1:9"),
    ]);
    let mut v: serde_json::Value = serde_json::from_str(&args("0.05", None, evil_cfg)).unwrap();
    v["recipient"] = serde_json::json!(OTHER); // attacker's wallet
    let mut rpc = MockRpc::new(vec![]);
    let err = run(&v.to_string(), &mut rpc).unwrap_err();
    assert!(matches!(err, BuildError::Refused { .. }));
    assert!(rpc.calls.is_empty(), "no transaction bytes, no network");
}

#[test]
fn unknown_args_rejected() {
    // deny_unknown_fields: an injected "rpc_url" or "skip_checks" arg fails.
    let mut v: serde_json::Value = serde_json::from_str(&args("0.05", None, base_cfg())).unwrap();
    v["rpc_url"] = serde_json::json!("https://evil.example");
    let mut rpc = MockRpc::new(vec![]);
    let err = run(&v.to_string(), &mut rpc).unwrap_err();
    assert!(matches!(err, BuildError::BadArgs(_)));
}

#[test]
fn misspelled_config_key_fails_closed() {
    let mut c = base_cfg();
    c.insert("max_amout".into(), "999".into());
    let mut rpc = MockRpc::new(vec![]);
    let err = run(&args("0.05", None, c), &mut rpc).unwrap_err();
    assert!(err.to_string().contains("unknown config key"));
}

#[test]
fn decimal_mismatch_fails_closed() {
    // Operator wrote the cap at 6 decimals but the mint is really 9: refuse
    // rather than silently move 1000x the intended amount.
    let mut rpc = MockRpc::new(vec![
        ("getLatestBlockhash", blockhash_resp()),
        (USDC_DEV, mint_resp(9)),
        ("getAccountInfo", account_missing_resp()),
    ]);
    let err = run(&args("25", Some(USDC_DEV), base_cfg()), &mut rpc).unwrap_err();
    assert!(err.to_string().contains("decimals"), "{err}");
}

#[test]
fn nonce_wrong_authority_refused() {
    let mut c = base_cfg();
    c.insert("nonce_account".into(), NONCE_ACCT.into());
    let mut rpc = MockRpc::new(vec![(NONCE_ACCT, nonce_resp(RECIP))]); // authority != sender
    let err = run(&args("0.05", None, c), &mut rpc).unwrap_err();
    assert!(err.to_string().contains("authority"), "{err}");
}

#[test]
fn rpc_error_propagates_no_tx() {
    let mut rpc = MockRpc::new(vec![(
        "getLatestBlockhash",
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"node is behind"}}"#
            .to_string(),
    )]);
    let err = run(&args("0.05", None, base_cfg()), &mut rpc).unwrap_err();
    assert!(matches!(err, BuildError::Rpc(_)));
}

#[test]
fn plan_is_pure() {
    // plan() alone never touches the network: policy refusals happen before
    // any Lookups call by construction.
    let raw = args("0.05", None, base_cfg());
    let a: Args = serde_json::from_str(&raw).unwrap();
    assert!(plan(&a).is_ok());
}

#[test]
fn amount_must_be_string() {
    let raw =
        format!(r#"{{"sender":"{SENDER}","recipient":"{RECIP}","amount":25,"__config":{{}}}}"#);
    let mut rpc = MockRpc::new(vec![]);
    assert!(matches!(
        run(&raw, &mut rpc).unwrap_err(),
        BuildError::BadArgs(_)
    ));
}
