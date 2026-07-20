//! Host tests for nonce-vault-init: mocked RPC, no network, no wasm.

use std::cell::RefCell;
use std::collections::HashMap;

use aval_core::codec::{b64_decode, b64_encode};
use aval_core::message::parse_transaction;
use aval_core::nonce::NONCE_ACCOUNT_SIZE;
use aval_core::pubkey::{create_with_seed, system_program, Pubkey};
use aval_core::rpc::HttpPost;
use nonce_vault_init::init::{build_init, InitArgs, DEFAULT_SEED};

struct MockHttp {
    responses: RefCell<Vec<String>>,
}

impl MockHttp {
    fn new(responses: Vec<String>) -> Self {
        Self {
            responses: RefCell::new(responses.into_iter().rev().collect()),
        }
    }
}

impl HttpPost for MockHttp {
    fn post_json(&self, _url: &str, _body: &str) -> Result<String, String> {
        self.responses
            .borrow_mut()
            .pop()
            .ok_or_else(|| "mock exhausted: unexpected extra RPC call".to_string())
    }
}

fn pk(n: u8) -> Pubkey {
    let mut b = [0u8; 32];
    b[0] = n;
    b[31] = n;
    Pubkey(b)
}

fn args(authority: &Pubkey, seed: Option<&str>) -> InitArgs {
    serde_json::from_value(serde_json::json!({
        "authority": authority.to_base58(),
        "seed": seed,
        "__config": HashMap::from([("rpc_url".to_string(), "http://mock".to_string())]),
    }))
    .unwrap()
}

fn missing_account_json() -> String {
    r#"{"jsonrpc":"2.0","id":1,"result":{"value":null}}"#.to_string()
}

#[test]
fn builds_the_setup_transaction() {
    let authority = pk(1);
    let http = MockHttp::new(vec![
        missing_account_json(),
        r#"{"jsonrpc":"2.0","id":1,"result":1447680}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"value":{"blockhash":"11111111111111111111111111111111"}}}"#.to_string(),
    ]);

    let out = build_init(&http, &args(&authority, None)).unwrap();
    let expected_addr = create_with_seed(&authority, DEFAULT_SEED, &system_program()).unwrap();
    assert_eq!(out.nonce_account, expected_addr.to_base58());
    assert!(out.summary.contains("Sign promptly"));

    let tx = b64_decode(&out.transaction_base64.unwrap()).unwrap();
    let parsed = parse_transaction(&tx).unwrap();
    assert_eq!(parsed.num_required_signatures, 1);
    assert_eq!(parsed.account_keys[0], authority);
    assert_eq!(parsed.instructions.len(), 2);

    // CreateAccountWithSeed: discriminant 3, then base pubkey, seed, rent,
    // space, owner.
    let create = &parsed.instructions[0];
    assert_eq!(&create.data[..4], &[3, 0, 0, 0]);
    assert_eq!(&create.data[4..36], &authority.0);
    let seed_len = u64::from_le_bytes(create.data[36..44].try_into().unwrap()) as usize;
    assert_eq!(&create.data[44..44 + seed_len], DEFAULT_SEED.as_bytes());
    let space_off = 44 + seed_len + 8;
    assert_eq!(
        u64::from_le_bytes(create.data[space_off..space_off + 8].try_into().unwrap()),
        NONCE_ACCOUNT_SIZE
    );

    // InitializeNonceAccount: discriminant 6 + authority.
    let init = &parsed.instructions[1];
    assert_eq!(&init.data[..4], &[6, 0, 0, 0]);
    assert_eq!(&init.data[4..36], &authority.0);
    assert_eq!(parsed.account(init, 0), Some(&expected_addr));
}

#[test]
fn reports_existing_vault_instead_of_rebuilding() {
    let authority = pk(1);
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&authority.0);
    data.extend_from_slice(&[9u8; 32]);
    data.extend_from_slice(&5000u64.to_le_bytes());
    let existing = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"value":{{"lamports":1447680,"owner":"{}","data":["{}","base64"]}}}}}}"#,
        system_program().to_base58(),
        b64_encode(&data)
    );
    let http = MockHttp::new(vec![existing]);

    let out = build_init(&http, &args(&authority, None)).unwrap();
    assert!(out.transaction_base64.is_none());
    assert!(out.summary.contains("already exists"));
}

#[test]
fn refuses_foreign_authority_on_existing_account() {
    let authority = pk(1);
    let stranger = pk(9);
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&stranger.0);
    data.extend_from_slice(&[9u8; 32]);
    data.extend_from_slice(&5000u64.to_le_bytes());
    let existing = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"value":{{"lamports":1447680,"owner":"{}","data":["{}","base64"]}}}}}}"#,
        system_program().to_base58(),
        b64_encode(&data)
    );
    let http = MockHttp::new(vec![existing]);
    let err = build_init(&http, &args(&authority, None)).unwrap_err();
    assert!(err.contains("authority is not"), "{err}");
}

#[test]
fn fails_closed_on_bad_input() {
    let http = MockHttp::new(vec![]);
    // Free-text authority.
    let bad = args(&pk(1), None);
    let mut bad: InitArgs = bad;
    bad.authority = "my main wallet".to_string();
    assert!(build_init(&http, &bad).unwrap_err().contains("authority rejected"));

    // Hostile seed characters.
    let http = MockHttp::new(vec![]);
    let err = build_init(&http, &args(&pk(1), Some("../../etc"))).unwrap_err();
    assert!(err.contains("seed may only contain"), "{err}");

    // Unknown argument fields are a parse error (injection surface closed).
    let smuggled: Result<InitArgs, _> = serde_json::from_value(serde_json::json!({
        "authority": pk(1).to_base58(),
        "make_me_signer": true,
    }));
    assert!(smuggled.is_err());
}
