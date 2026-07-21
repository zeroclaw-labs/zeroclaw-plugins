use std::cell::RefCell;
use std::collections::HashMap;

use base64::Engine;
use serde_json::{json, Value};
use solana_core::keys::Pubkey;
use solana_core::nonce::NONCE_ACCOUNT_SIZE;
use solana_core::rpc::{HttpClient, Rpc};
use solana_core::{CoreError, CoreResult};

const RPC_URL: &str = "https://rpc.test";

struct MapHttp {
    responses: HashMap<String, Value>,
    requests: RefCell<Vec<(String, Value)>>,
}

impl MapHttp {
    fn new(responses: HashMap<String, Value>) -> Self {
        Self {
            responses,
            requests: RefCell::new(Vec::new()),
        }
    }

    fn with_response(url: &str, body: Value, response: Value) -> Self {
        let mut responses = HashMap::new();
        responses.insert(fingerprint(url, &body), response);
        Self::new(responses)
    }
}

impl HttpClient for MapHttp {
    fn post_json(&self, url: &str, body: &Value) -> CoreResult<Value> {
        self.requests
            .borrow_mut()
            .push((url.to_string(), body.clone()));
        self.responses
            .get(&fingerprint(url, body))
            .cloned()
            .ok_or_else(|| CoreError::msg(format!("missing mock response for {url}: {body}")))
    }
}

fn fingerprint(url: &str, body: &Value) -> String {
    format!("{url}\n{body}")
}

fn initialized_nonce_fixture(authority: &Pubkey, durable_nonce: &[u8; 32], fee: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(NONCE_ACCOUNT_SIZE);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(authority.as_bytes());
    data.extend_from_slice(durable_nonce);
    data.extend_from_slice(&fee.to_le_bytes());
    data
}

#[test]
fn get_account_data_decodes_base64_and_get_nonce_parses_it() {
    let nonce_account = Pubkey::new([2u8; 32]);
    let authority = Pubkey::new([3u8; 32]);
    let durable_nonce = [9u8; 32];
    let nonce_data = initialized_nonce_fixture(&authority, &durable_nonce, 5_000);
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce_data);
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            nonce_account.to_base58(),
            { "encoding": "base64" }
        ]
    });
    let http = MapHttp::with_response(
        RPC_URL,
        body,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "value": {
                    "data": [nonce_b64, "base64"]
                }
            }
        }),
    );
    let rpc = Rpc {
        url: RPC_URL,
        http: &http,
    };

    assert_eq!(rpc.get_account_data(&nonce_account).unwrap(), nonce_data);
    let parsed = rpc.get_nonce(&nonce_account).unwrap();

    assert_eq!(parsed.authority, authority);
    assert_eq!(parsed.durable_nonce, durable_nonce);
    assert_eq!(parsed.fee_calculator_lamports_per_signature, 5_000);
}

#[test]
fn get_signatures_for_address_returns_signature_metadata() {
    let address = Pubkey::new([4u8; 32]);
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [
            address.to_base58(),
            { "limit": 2 }
        ]
    });
    let http = MapHttp::with_response(
        RPC_URL,
        body,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [
                { "signature": "sig-one", "blockTime": 123, "err": null },
                { "signature": "sig-two", "err": { "InstructionError": [0, "Custom"] } }
            ]
        }),
    );
    let rpc = Rpc {
        url: RPC_URL,
        http: &http,
    };

    let signatures = rpc.get_signatures_for_address(&address, 2).unwrap();

    assert_eq!(signatures.len(), 2);
    assert_eq!(signatures[0].signature, "sig-one");
    assert_eq!(signatures[0].block_time, Some(123));
    assert_eq!(signatures[0].err, None);
    assert_eq!(signatures[1].signature, "sig-two");
    assert_eq!(
        signatures[1].err,
        Some(json!({ "InstructionError": [0, "Custom"] }))
    );
}

#[test]
fn get_transaction_memo_extracts_only_memo_and_metadata() {
    let signature = "txsig";
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            { "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0 }
        ]
    });
    let http = MapHttp::with_response(
        RPC_URL,
        body,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "blockTime": 456,
                "transaction": {
                    "message": {
                        "instructions": [
                            {
                                "programId": "11111111111111111111111111111111",
                                "parsed": { "type": "transfer" }
                            },
                            {
                                "programId": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                                "parsed": "ZCDEPIN|durable memo",
                                "fatBlob": "this must not be copied to the return value"
                            }
                        ]
                    }
                }
            }
        }),
    );
    let rpc = Rpc {
        url: RPC_URL,
        http: &http,
    };

    let memo = rpc.get_transaction_memo(signature).unwrap().unwrap();

    assert_eq!(memo.signature, signature);
    assert_eq!(memo.block_time, Some(456));
    assert_eq!(memo.memo, "ZCDEPIN|durable memo");
}

#[test]
fn get_transaction_memo_returns_none_when_no_memo_instruction_exists() {
    let signature = "txsig";
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            { "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0 }
        ]
    });
    let http = MapHttp::with_response(
        RPC_URL,
        body,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "blockTime": 456,
                "transaction": {
                    "message": {
                        "instructions": []
                    }
                }
            }
        }),
    );
    let rpc = Rpc {
        url: RPC_URL,
        http: &http,
    };

    assert_eq!(rpc.get_transaction_memo(signature).unwrap(), None);
}

#[test]
fn empty_url_is_rejected_before_http_call() {
    let address = Pubkey::new([4u8; 32]);
    let http = MapHttp::new(HashMap::new());
    let rpc = Rpc {
        url: "",
        http: &http,
    };

    let err = rpc.get_signatures_for_address(&address, 1).unwrap_err();

    assert!(err.to_string().contains("rpc url is empty"));
    assert!(http.requests.borrow().is_empty());
}

#[test]
fn rpc_error_object_maps_to_core_error() {
    let address = Pubkey::new([4u8; 32]);
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [
            address.to_base58(),
            { "limit": 1 }
        ]
    });
    let http = MapHttp::with_response(
        RPC_URL,
        body,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32000,
                "message": "node is unhealthy",
                "data": { "huge": "omitted from error text" }
            }
        }),
    );
    let rpc = Rpc {
        url: RPC_URL,
        http: &http,
    };

    let err = rpc.get_signatures_for_address(&address, 1).unwrap_err();

    assert_eq!(err.to_string(), "rpc error -32000: node is unhealthy");
}
