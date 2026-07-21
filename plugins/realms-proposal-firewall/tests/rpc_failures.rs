#[allow(dead_code)]
#[path = "../src/config.rs"]
mod config;
#[allow(dead_code)]
#[path = "../src/pubkey.rs"]
mod pubkey;
#[allow(dead_code)]
#[path = "../src/rpc.rs"]
mod rpc;

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use pubkey::Pubkey;
use rpc::{
    RpcClient, RpcError, RpcLimits, Transport, TransportError, TransportResponse,
    MAX_MULTIPLE_ACCOUNTS,
};
use serde_json::{json, Value};

const URL: &str = "https://rpc.example.invalid/secret-token";
const ADDRESS: &str = "6wR1jdhhJ31bbdRNXva8MxqsgsNLKTxargcdAyZ7FcRj";
const OWNER: &str = "GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw";

#[derive(Clone)]
struct MockTransport {
    state: Arc<Mutex<MockState>>,
}

struct MockState {
    replies: VecDeque<Result<TransportResponse, TransportError>>,
    requests: Vec<(String, Vec<u8>, usize)>,
}

impl MockTransport {
    fn new(replies: impl IntoIterator<Item = Result<TransportResponse, TransportError>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(MockState {
                replies: replies.into_iter().collect(),
                requests: Vec::new(),
            })),
        }
    }

    fn requests(&self) -> Vec<(String, Vec<u8>, usize)> {
        self.state.lock().unwrap().requests.clone()
    }
}

impl Transport for MockTransport {
    fn post(
        &self,
        url: &str,
        body: &[u8],
        max_response_bytes: usize,
    ) -> Result<TransportResponse, TransportError> {
        let mut state = self.state.lock().unwrap();
        state
            .requests
            .push((url.to_owned(), body.to_vec(), max_response_bytes));
        state.replies.pop_front().expect("missing mock reply")
    }
}

fn ok(value: Value) -> Result<TransportResponse, TransportError> {
    Ok(TransportResponse {
        status: 200,
        body: serde_json::to_vec(&value).unwrap(),
    })
}

fn status(status: u16, body: &str) -> Result<TransportResponse, TransportError> {
    Ok(TransportResponse {
        status,
        body: body.as_bytes().to_vec(),
    })
}

fn envelope(id: u64, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn account(data: &[u8]) -> Value {
    json!({
        "lamports": 42,
        "owner": OWNER,
        "executable": false,
        "rentEpoch": 7,
        "space": data.len(),
        "data": [STANDARD.encode(data), "base64"]
    })
}

fn account_result(id: u64, slot: u64, value: Value) -> Value {
    envelope(id, json!({"context": {"slot": slot}, "value": value}))
}

fn address() -> Pubkey {
    ADDRESS.parse().unwrap()
}

fn limits(response: usize, account: usize, total: usize) -> RpcLimits {
    RpcLimits {
        max_response_bytes: response,
        max_account_bytes: account,
        max_total_account_bytes: total,
    }
}

#[test]
fn genesis_hash_success_uses_fixed_request_and_generated_ids() {
    let transport = MockTransport::new([
        ok(envelope(1, json!(ADDRESS))),
        ok(envelope(2, json!(ADDRESS))),
    ]);
    let client = RpcClient::new(URL, transport.clone());

    assert_eq!(client.get_genesis_hash().unwrap(), address());
    assert_eq!(client.get_genesis_hash().unwrap(), address());

    let requests = transport.requests();
    let first: Value = serde_json::from_slice(&requests[0].1).unwrap();
    let second: Value = serde_json::from_slice(&requests[1].1).unwrap();
    assert_eq!(requests[0].0, URL);
    assert_eq!(
        first,
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "getGenesisHash", "params": []
        })
    );
    assert_eq!(second["id"], 2);
}

#[test]
fn account_success_requires_finalized_base64_and_forwards_min_slot() {
    let transport = MockTransport::new([ok(account_result(1, 99, account(b"snapshot")))]);
    let client = RpcClient::new(URL, transport.clone());

    let read = client.get_account_info(&address(), Some(90)).unwrap();
    assert_eq!(read.context_slot, 99);
    assert_eq!(read.account.lamports, 42);
    assert_eq!(read.account.owner, OWNER.parse().unwrap());
    assert!(!read.account.executable);
    assert_eq!(read.account.data, b"snapshot");

    let request: Value = serde_json::from_slice(&transport.requests()[0].1).unwrap();
    assert_eq!(request["method"], "getAccountInfo");
    assert_eq!(request["params"][0], ADDRESS);
    assert_eq!(request["params"][1]["commitment"], "finalized");
    assert_eq!(request["params"][1]["encoding"], "base64");
    assert_eq!(request["params"][1]["minContextSlot"], 90);
}

#[test]
fn account_request_omits_min_slot_when_not_supplied() {
    let transport = MockTransport::new([ok(account_result(1, 99, account(b"snapshot")))]);
    let client = RpcClient::new(URL, transport.clone());
    client.get_account_info(&address(), None).unwrap();

    let request: Value = serde_json::from_slice(&transport.requests()[0].1).unwrap();
    assert!(request["params"][1].get("minContextSlot").is_none());
    assert_eq!(request["params"][1]["commitment"], "finalized");
}

#[test]
fn multiple_accounts_preserves_nulls_and_request_shape() {
    let second = Pubkey::new([9; 32]);
    let addresses = [address(), second];
    let transport =
        MockTransport::new([ok(account_result(1, 101, json!([account(b"one"), null])))]);
    let client = RpcClient::new(URL, transport.clone());

    let read = client.get_multiple_accounts(&addresses, Some(100)).unwrap();
    assert_eq!(read.context_slot, 101);
    assert_eq!(read.accounts[0].as_ref().unwrap().data, b"one");
    assert_eq!(read.accounts[1], None);

    let request: Value = serde_json::from_slice(&transport.requests()[0].1).unwrap();
    assert_eq!(request["method"], "getMultipleAccounts");
    assert_eq!(request["params"][0], json!([address(), second]));
    assert_eq!(request["params"][1]["commitment"], "finalized");
    assert_eq!(request["params"][1]["minContextSlot"], 100);
}

#[test]
fn transport_timeout_retries_exactly_once() {
    let transport = MockTransport::new([
        Err(TransportError::Timeout),
        ok(envelope(1, json!(ADDRESS))),
    ]);
    let client = RpcClient::new(URL, transport.clone());
    assert!(client.get_genesis_hash().is_ok());
    let requests = transport.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].1, requests[1].1);
}

#[test]
fn transport_failure_stops_after_second_attempt() {
    let transport =
        MockTransport::new([Err(TransportError::Connection), Err(TransportError::Other)]);
    let client = RpcClient::new(URL, transport.clone());
    assert_eq!(client.get_genesis_hash(), Err(RpcError::Transport));
    assert_eq!(transport.requests().len(), 2);
}

#[test]
fn transport_size_limit_is_never_retried() {
    let transport = MockTransport::new([Err(TransportError::ResponseTooLarge)]);
    let client = RpcClient::new(URL, transport.clone());
    assert_eq!(client.get_genesis_hash(), Err(RpcError::ResponseTooLarge));
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn retryable_http_statuses_retry_once() {
    for retryable in [429, 500, 599] {
        let transport = MockTransport::new([
            status(retryable, "provider secret"),
            ok(envelope(1, json!(ADDRESS))),
        ]);
        let client = RpcClient::new(URL, transport.clone());
        assert!(client.get_genesis_hash().is_ok());
        assert_eq!(transport.requests().len(), 2);
    }
}

#[test]
fn http_400_does_not_retry() {
    let transport = MockTransport::new([status(400, "provider secret")]);
    let client = RpcClient::new(URL, transport.clone());
    assert_eq!(client.get_genesis_hash(), Err(RpcError::HttpStatus));
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn malformed_json_does_not_retry() {
    let transport = MockTransport::new([status(200, "not json")]);
    let client = RpcClient::new(URL, transport.clone());
    assert_eq!(client.get_genesis_hash(), Err(RpcError::MalformedJson));
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn rejects_wrong_version_id_and_contradictory_envelope_without_retry() {
    let cases = [
        (
            json!({"jsonrpc": "1.0", "id": 1, "result": ADDRESS}),
            RpcError::InvalidJsonRpcVersion,
        ),
        (
            json!({"jsonrpc": "2.0", "id": 2, "result": ADDRESS}),
            RpcError::MismatchedResponseId,
        ),
        (
            json!({"jsonrpc": "2.0", "id": 1, "result": ADDRESS,
                "error": {"code": -1, "message": "secret"}}),
            RpcError::InvalidResponseShape,
        ),
    ];
    for (body, expected) in cases {
        let transport = MockTransport::new([ok(body)]);
        let client = RpcClient::new(URL, transport.clone());
        assert_eq!(client.get_genesis_hash(), Err(expected));
        assert_eq!(transport.requests().len(), 1);
    }
}

#[test]
fn validates_json_rpc_error_shape_without_exposing_message() {
    let transport = MockTransport::new([ok(json!({
        "jsonrpc": "2.0", "id": 1,
        "error": {"code": -32000, "message": "provider secret", "data": ADDRESS}
    }))]);
    let client = RpcClient::new(URL, transport);
    let error = client.get_genesis_hash().unwrap_err();
    assert_eq!(error, RpcError::RemoteError);
    assert_sanitized(error);

    let transport = MockTransport::new([ok(json!({
        "jsonrpc": "2.0", "id": 1, "error": {"code": "bad", "message": 3}
    }))]);
    assert_eq!(
        RpcClient::new(URL, transport).get_genesis_hash(),
        Err(RpcError::InvalidResponseShape)
    );
}

#[test]
fn rejects_null_single_account_and_stale_context() {
    let transport = MockTransport::new([ok(account_result(1, 10, Value::Null))]);
    assert_eq!(
        RpcClient::new(URL, transport).get_account_info(&address(), None),
        Err(RpcError::NullAccount)
    );

    let transport = MockTransport::new([ok(account_result(1, 9, account(b"x")))]);
    assert_eq!(
        RpcClient::new(URL, transport).get_account_info(&address(), Some(10)),
        Err(RpcError::StaleContext)
    );
}

#[test]
fn rejects_invalid_base64_and_non_base64_encoding() {
    let mut invalid = account(b"x");
    invalid["data"] = json!(["%%%", "base64"]);
    let transport = MockTransport::new([ok(account_result(1, 10, invalid))]);
    assert_eq!(
        RpcClient::new(URL, transport).get_account_info(&address(), None),
        Err(RpcError::InvalidBase64)
    );

    let mut wrong_encoding = account(b"x");
    wrong_encoding["data"] = json!(["eA==", "base64+zstd"]);
    let transport = MockTransport::new([ok(account_result(1, 10, wrong_encoding))]);
    assert_eq!(
        RpcClient::new(URL, transport).get_account_info(&address(), None),
        Err(RpcError::InvalidDataEncoding)
    );
}

#[test]
fn rejects_malformed_account_fields_and_owner() {
    for field in ["lamports", "executable", "owner", "data"] {
        let mut value = account(b"x");
        value.as_object_mut().unwrap().remove(field);
        let transport = MockTransport::new([ok(account_result(1, 10, value))]);
        assert!(RpcClient::new(URL, transport)
            .get_account_info(&address(), None)
            .is_err());
    }

    let mut value = account(b"x");
    value["owner"] = json!("not-a-pubkey");
    let transport = MockTransport::new([ok(account_result(1, 10, value))]);
    assert_eq!(
        RpcClient::new(URL, transport).get_account_info(&address(), None),
        Err(RpcError::InvalidOwner)
    );

    for malformed_lamports in [json!(-1), json!(1.5), json!("42"), json!(null)] {
        let mut value = account(b"x");
        value["lamports"] = malformed_lamports;
        let transport = MockTransport::new([ok(account_result(1, 10, value))]);
        assert_eq!(
            RpcClient::new(URL, transport).get_account_info(&address(), None),
            Err(RpcError::InvalidAccount)
        );
    }
}

#[test]
fn rejects_oversized_account_and_aggregate_data() {
    let transport = MockTransport::new([ok(account_result(1, 10, account(b"12345")))]);
    let client = RpcClient::with_limits(URL, transport, limits(4096, 4, 8));
    assert_eq!(
        client.get_account_info(&address(), None),
        Err(RpcError::AccountTooLarge)
    );

    let transport = MockTransport::new([ok(account_result(1, 10, account(b"1234")))]);
    let client = RpcClient::with_limits(URL, transport, limits(4096, 4, 3));
    assert_eq!(
        client.get_account_info(&address(), None),
        Err(RpcError::AggregateDataTooLarge)
    );

    let addresses = [address(), Pubkey::new([7; 32])];
    let transport = MockTransport::new([ok(account_result(
        1,
        10,
        json!([account(b"123"), account(b"456")]),
    ))]);
    let client = RpcClient::with_limits(URL, transport, limits(4096, 4, 5));
    assert_eq!(
        client.get_multiple_accounts(&addresses, None),
        Err(RpcError::AggregateDataTooLarge)
    );
}

#[test]
fn rejects_oversized_response_before_json_parse() {
    let transport = MockTransport::new([status(200, "this body is too long")]);
    let client = RpcClient::with_limits(URL, transport.clone(), limits(4, 4, 4));
    assert_eq!(client.get_genesis_hash(), Err(RpcError::ResponseTooLarge));
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(transport.requests()[0].2, 4);
}

#[test]
fn rejects_duplicates_and_more_than_one_hundred_without_network_access() {
    let transport = MockTransport::new([]);
    let client = RpcClient::new(URL, transport.clone());
    assert_eq!(
        client.get_multiple_accounts(&[address(), address()], None),
        Err(RpcError::DuplicateAddress)
    );
    let too_many: Vec<_> = (0..=MAX_MULTIPLE_ACCOUNTS)
        .map(|index| Pubkey::new([index as u8; 32]))
        .collect();
    assert_eq!(
        client.get_multiple_accounts(&too_many, None),
        Err(RpcError::TooManyAddresses)
    );
    assert!(transport.requests().is_empty());
}

#[test]
fn rejects_multiple_account_cardinality_mismatch() {
    let addresses = [address(), Pubkey::new([8; 32])];
    let transport = MockTransport::new([ok(account_result(1, 10, json!([account(b"x")])))]);
    assert_eq!(
        RpcClient::new(URL, transport).get_multiple_accounts(&addresses, None),
        Err(RpcError::CardinalityMismatch)
    );
}

#[test]
fn all_errors_are_sanitized() {
    for error in [
        RpcError::Transport,
        RpcError::HttpStatus,
        RpcError::MalformedJson,
        RpcError::RemoteError,
        RpcError::InvalidOwner,
        RpcError::InvalidBase64,
    ] {
        assert_sanitized(error);
    }
    for error in [
        TransportError::Timeout,
        TransportError::Connection,
        TransportError::ResponseTooLarge,
        TransportError::Other,
    ] {
        let message = error.to_string();
        assert!(!message.contains(URL));
        assert!(!message.contains(ADDRESS));
        assert!(!message.contains("secret"));
    }
}

fn assert_sanitized(error: RpcError) {
    let message = error.to_string();
    assert!(!message.contains(URL));
    assert!(!message.contains(ADDRESS));
    assert!(!message.contains("secret"));
    assert!(!message.contains("provider"));
}
