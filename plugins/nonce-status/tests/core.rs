//! Host tests for nonce-status: mocked RPC, no network, no wasm toolchain.

use std::collections::BTreeMap;

use nonce_status::core::{run, Lookups, StatusError};

const NONCE_ACCT: &str = "8XkoSVfNbLKKzcpsTCyzysXbygqrGrbW8t5RS6Wxsdb1";
const AUTHORITY: &str = "9B5XszUGdMaxCZ7uSQhPzdks5ZQSmWxrmzCSvtJ6Ns6g";

fn cfg(with_nonce: bool) -> BTreeMap<String, String> {
    let mut m: BTreeMap<String, String> = [(
        "rpc_url".to_string(),
        "https://api.devnet.solana.com".to_string(),
    )]
    .into();
    if with_nonce {
        m.insert("nonce_account".into(), NONCE_ACCT.into());
    }
    m
}

fn args(config: BTreeMap<String, String>) -> String {
    serde_json::json!({ "__config": config }).to_string()
}

struct MockRpc {
    response: Option<String>,
    calls: usize,
}

impl Lookups for MockRpc {
    fn rpc(&mut self, _body: &str) -> Result<String, String> {
        self.calls += 1;
        self.response
            .clone()
            .ok_or_else(|| "mock: no response".into())
    }
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

fn account_resp(data: &[u8], owner: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{"data":["{}","base64"],"owner":"{owner}","lamports":1447680,"executable":false,"rentEpoch":0,"space":{}}}}}}}"#,
        base64(data),
        data.len()
    )
}

fn nonce_data(version: u32, state: u32) -> Vec<u8> {
    let mut d = Vec::with_capacity(80);
    d.extend_from_slice(&version.to_le_bytes());
    d.extend_from_slice(&state.to_le_bytes());
    // authority = AUTHORITY decoded via the pubkey type in the core crate
    let auth = solana_core_wasi::pubkey::Pubkey::parse(AUTHORITY).unwrap();
    d.extend_from_slice(&auth.0);
    d.extend_from_slice(&[0xCD; 32]);
    d.extend_from_slice(&5000u64.to_le_bytes());
    d
}

#[test]
fn ready_nonce_reports_authority_and_nonce() {
    let mut rpc = MockRpc {
        response: Some(account_resp(
            &nonce_data(1, 1),
            "11111111111111111111111111111111",
        )),
        calls: 0,
    };
    let out = run(&args(cfg(true)), &mut rpc).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ready"], true);
    let s = v["summary"].as_str().unwrap();
    assert!(
        s.contains("READY") && s.contains(AUTHORITY) && s.contains("5000"),
        "{s}"
    );
    assert_eq!(rpc.calls, 1);
}

#[test]
fn missing_account_gives_create_instructions() {
    let mut rpc = MockRpc {
        response: Some(
            r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":null}}"#.into(),
        ),
        calls: 0,
    };
    let out = run(&args(cfg(true)), &mut rpc).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ready"], false);
    assert!(v["summary"]
        .as_str()
        .unwrap()
        .contains("create-nonce-account"));
}

#[test]
fn wrong_owner_flagged() {
    let mut rpc = MockRpc {
        response: Some(account_resp(
            &nonce_data(1, 1),
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        )),
        calls: 0,
    };
    let out = run(&args(cfg(true)), &mut rpc).unwrap();
    assert!(out.contains("NOT A NONCE ACCOUNT"));
}

#[test]
fn legacy_version_unusable() {
    let mut rpc = MockRpc {
        response: Some(account_resp(
            &nonce_data(0, 1),
            "11111111111111111111111111111111",
        )),
        calls: 0,
    };
    let out = run(&args(cfg(true)), &mut rpc).unwrap();
    assert!(out.contains("UNUSABLE") && out.contains("legacy"));
}

#[test]
fn uninitialized_reported() {
    let mut rpc = MockRpc {
        response: Some(account_resp(
            &nonce_data(1, 0),
            "11111111111111111111111111111111",
        )),
        calls: 0,
    };
    let out = run(&args(cfg(true)), &mut rpc).unwrap();
    assert!(out.contains("UNINITIALIZED"));
}

#[test]
fn explicit_account_argument_overrides_config() {
    let mut rpc = MockRpc {
        response: Some(account_resp(
            &nonce_data(1, 1),
            "11111111111111111111111111111111",
        )),
        calls: 0,
    };
    let raw = serde_json::json!({ "account": NONCE_ACCT, "__config": cfg(false) }).to_string();
    let out = run(&raw, &mut rpc).unwrap();
    assert!(out.contains("READY"));
}

// ---------- fail-closed paths ----------

#[test]
fn no_account_anywhere_is_config_error() {
    let mut rpc = MockRpc {
        response: None,
        calls: 0,
    };
    let err = run(&args(cfg(false)), &mut rpc).unwrap_err();
    assert!(matches!(err, StatusError::Config(_)));
    assert_eq!(rpc.calls, 0, "no network call without an account");
}

#[test]
fn unknown_config_key_fails_closed() {
    let mut c = cfg(true);
    c.insert("rcp_url".into(), "https://typo.example".into());
    let mut rpc = MockRpc {
        response: None,
        calls: 0,
    };
    let err = run(&args(c), &mut rpc).unwrap_err();
    assert!(err.to_string().contains("unknown config key"));
}

#[test]
fn injected_unknown_arg_rejected() {
    let raw = serde_json::json!({ "account": NONCE_ACCT, "rpc_url": "https://evil.example", "__config": cfg(true) })
        .to_string();
    let mut rpc = MockRpc {
        response: None,
        calls: 0,
    };
    assert!(matches!(
        run(&raw, &mut rpc).unwrap_err(),
        StatusError::BadArgs(_)
    ));
}

#[test]
fn http_rpc_rejected() {
    let mut c = cfg(true);
    c.insert("rpc_url".into(), "http://insecure.example".into());
    let mut rpc = MockRpc {
        response: None,
        calls: 0,
    };
    assert!(matches!(
        run(&args(c), &mut rpc).unwrap_err(),
        StatusError::Config(_)
    ));
}
