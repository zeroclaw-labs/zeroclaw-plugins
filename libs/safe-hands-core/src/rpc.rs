//! RPC boundary: one trait, three implementations.
//!
//! `SolanaJsonRpcTransport` (waki, wasm-only) talks to a real endpoint;
//! `MockTransport` answers from canned envelopes so every host test runs
//! offline. The policy engine never sees HTTP — only this trait.

use serde_json::{json, Value};

/// Minimal JSON-RPC transport. Implementations must be deterministic given the
/// same request.
pub trait RpcTransport {
    fn call(&self, method: &str, params: Value) -> Result<Value, String>;
}

/// Build a JSON-RPC 2.0 request envelope.
pub fn envelope(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

/// Canned-answer transport for host tests. Answers are matched by method name;
/// a missing method is an error, never a guess.
#[derive(Default)]
pub struct MockTransport {
    pub responses: std::collections::HashMap<String, Value>,
    calls: std::cell::RefCell<Vec<(String, Value)>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, method: &str, response: Value) -> Self {
        self.responses.insert(method.to_string(), response);
        self
    }

    /// Return the exact method/params pairs observed by this mock.
    pub fn calls(&self) -> Vec<(String, Value)> {
        self.calls.borrow().clone()
    }
}

impl RpcTransport for MockTransport {
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.calls.borrow_mut().push((method.to_string(), params));
        self.responses
            .get(method)
            .cloned()
            .ok_or_else(|| format!("mock transport has no fixture for {method}"))
    }
}

/// Failing transport: every call errors. Used by fail-closed tests.
pub struct DownTransport;

impl RpcTransport for DownTransport {
    fn call(&self, method: &str, _params: Value) -> Result<Value, String> {
        Err(format!("endpoint unreachable during {method}"))
    }
}

/// Fetch and fail-closed validate a classic SPL Token Mint account.
///
/// Safe v0.1 accepts only the exact 82-byte classic Mint layout. The RPC
/// envelope, owner, base64 tuple, both COption tags, and initialized flag must
/// all be trustworthy before the mint decimals are returned.
pub fn fetch_classic_mint_decimals(rpc: &dyn RpcTransport, mint: &str) -> Result<u8, String> {
    let response = rpc.call("getAccountInfo", json!([mint, {"encoding": "base64"}]))?;
    let envelope = response
        .as_object()
        .ok_or_else(|| "getAccountInfo response must be a JSON object".to_string())?;
    if let Some(error) = envelope.get("error").filter(|error| !error.is_null()) {
        return Err(format!("getAccountInfo JSON-RPC error: {error}"));
    }
    let result = envelope
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| "getAccountInfo missing or malformed result object".to_string())?;
    let value = result
        .get("value")
        .ok_or_else(|| "getAccountInfo missing result.value".to_string())?;
    if value.is_null() {
        return Err("getAccountInfo result.value is null".to_string());
    }
    let account = value
        .as_object()
        .ok_or_else(|| "getAccountInfo result.value must be an object".to_string())?;
    let owner = account
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| "mint account owner missing or malformed".to_string())?;
    if owner != crate::crypto::TOKEN_PROGRAM {
        return Err(format!(
            "mint account owner must be classic SPL Token ({}), got {owner}",
            crate::crypto::TOKEN_PROGRAM
        ));
    }
    let data = account
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| "mint account data missing or malformed".to_string())?;
    if data.len() != 2 || data[1].as_str() != Some("base64") {
        return Err("mint account data must be an exact [base64, \"base64\"] tuple".to_string());
    }
    let encoded = data[0]
        .as_str()
        .ok_or_else(|| "mint account base64 payload missing or malformed".to_string())?;
    let bytes = crate::codec::base64_decode(encoded, 512)?;
    if bytes.len() != 82 {
        return Err(format!(
            "classic SPL Mint data must be exactly 82 bytes, got {}",
            bytes.len()
        ));
    }
    for (name, range) in [("mint_authority", 0..4), ("freeze_authority", 46..50)] {
        let tag = u32::from_le_bytes(
            bytes[range]
                .try_into()
                .map_err(|_| format!("classic SPL Mint {name} COption tag is truncated"))?,
        );
        if tag > 1 {
            return Err(format!(
                "classic SPL Mint {name} COption tag must be little-endian 0 or 1, got {tag}"
            ));
        }
    }
    if bytes[45] != 1 {
        return Err("classic SPL Mint initialized byte must be exactly 1".to_string());
    }
    Ok(bytes[44])
}

/// Fetch and fail-closed validate a System program durable Nonce account,
/// returning its stored nonce (used in place of a recent blockhash) as base58.
///
/// A durable nonce is what lets an approval-gated payment survive a human
/// taking their time: the transaction's validity is pinned to this value
/// rather than to a blockhash that dies in about ninety seconds. Because that
/// widens the window in which a signed transaction stays valid, every field of
/// the account is proven before the value is trusted: the exact 80-byte
/// versioned layout, System program ownership, `Current` version, `Initialized`
/// state, and the expected authority.
pub fn fetch_durable_nonce(
    rpc: &dyn RpcTransport,
    nonce_account: &str,
    expected_authority: &str,
) -> Result<String, String> {
    let response = rpc.call(
        "getAccountInfo",
        json!([nonce_account, {"encoding": "base64"}]),
    )?;
    if let Some(error) = non_null_rpc_error(&response) {
        return Err(format!("getAccountInfo JSON-RPC error: {error}"));
    }
    let value = response
        .pointer("/result/value")
        .ok_or_else(|| "getAccountInfo missing result.value".to_string())?;
    if value.is_null() {
        return Err(format!("nonce account {nonce_account} does not exist"));
    }
    let account = value
        .as_object()
        .ok_or_else(|| "getAccountInfo result.value must be an object".to_string())?;
    let owner = account
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| "nonce account owner missing or malformed".to_string())?;
    if owner != crate::crypto::SYSTEM_PROGRAM {
        return Err(format!(
            "nonce account owner must be the System program ({}), got {owner}",
            crate::crypto::SYSTEM_PROGRAM
        ));
    }
    let data = account
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| "nonce account data missing or malformed".to_string())?;
    if data.len() != 2 || data[1].as_str() != Some("base64") {
        return Err("nonce account data must be an exact [base64, \"base64\"] tuple".to_string());
    }
    let bytes = crate::codec::base64_decode(
        data[0]
            .as_str()
            .ok_or_else(|| "nonce account base64 payload missing or malformed".to_string())?,
        512,
    )?;
    if bytes.len() != 80 {
        return Err(format!(
            "durable nonce account data must be exactly 80 bytes, got {}",
            bytes.len()
        ));
    }
    let version = u32::from_le_bytes(bytes[0..4].try_into().expect("checked length"));
    if version != 1 {
        return Err(format!(
            "durable nonce account version must be 1 (Current), got {version}"
        ));
    }
    let state = u32::from_le_bytes(bytes[4..8].try_into().expect("checked length"));
    if state != 1 {
        return Err(format!(
            "durable nonce account must be Initialized (state 1), got {state}"
        ));
    }
    let authority = crate::bs58::encode(&bytes[8..40]).into_string();
    if authority != expected_authority {
        return Err(format!(
            "durable nonce authority is {authority}, but the configured nonce_authority is {expected_authority}"
        ));
    }
    let nonce = crate::bs58::encode(&bytes[40..72]).into_string();
    if bytes[40..72].iter().all(|byte| *byte == 0) {
        return Err("durable nonce value is all zeros — the account is not usable".to_string());
    }
    Ok(nonce)
}

/// Bind every classic SPL `TransferChecked` instruction to the decimals in its
/// on-chain Mint account.
///
/// Decoding proves the instruction shape, while this check proves that byte 9
/// of each instruction agrees with the exact classic Mint account used by that
/// instruction. Distinct mints are fetched once; conflicting declarations for
/// the same mint are rejected before any policy can return ALLOW.
pub fn verify_classic_transfer_mints(
    rpc: &dyn RpcTransport,
    tx: &crate::decode::DecodedTx,
) -> Result<(), String> {
    let mut expected_decimals = std::collections::BTreeMap::<String, u8>::new();
    for instruction in &tx.raw_instructions {
        if instruction.program_id.to_string() != crate::crypto::TOKEN_PROGRAM
            || instruction.data.first() != Some(&crate::ix::TOKEN_IX_TRANSFER_CHECKED)
        {
            continue;
        }
        if instruction.data.len() != 10 {
            return Err("classic SPL TransferChecked data must be exactly 10 bytes".to_string());
        }
        let mint = instruction
            .accounts
            .get(1)
            .ok_or_else(|| "classic SPL TransferChecked is missing its mint account".to_string())?
            .pubkey
            .to_string();
        let declared = instruction.data[9];
        if let Some(previous) = expected_decimals.insert(mint.clone(), declared) {
            if previous != declared {
                return Err(format!(
                    "classic SPL TransferChecked declarations disagree for mint {mint}: {previous} vs {declared}"
                ));
            }
        }
    }

    for (mint, declared) in expected_decimals {
        let actual = fetch_classic_mint_decimals(rpc, &mint)?;
        if actual != declared {
            return Err(format!(
                "classic SPL TransferChecked declares {declared} decimals for mint {mint}, but the Mint account declares {actual}"
            ));
        }
    }
    Ok(())
}

/// Strict result of simulation evidence collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimulationOutcome {
    Ok {
        simulation_slot: u64,
        current_slot: u64,
    },
    Stale {
        simulation_slot: u64,
        current_slot: u64,
    },
    Failed {
        reason: String,
    },
    Unavailable {
        reason: String,
    },
}

/// Simulate a decoded transaction and verify that its context slot is recent.
///
/// A canonical full unsigned transaction is always submitted, even when the
/// decoder input was a bare message. Missing or malformed evidence is never
/// treated as successful simulation.
pub fn simulate_strict(
    rpc: &dyn RpcTransport,
    tx: &crate::decode::DecodedTx,
    max_slot_age: u64,
) -> SimulationOutcome {
    let transaction = match crate::codec::unsigned_transaction_base64(
        &tx.serialized_message,
        tx.required_signatures,
    ) {
        Ok(transaction) => transaction,
        Err(reason) => return SimulationOutcome::Unavailable { reason },
    };
    let response = match rpc.call(
        "simulateTransaction",
        json!([transaction, {
            "encoding": "base64",
            "commitment": "confirmed",
            "sigVerify": false,
            "replaceRecentBlockhash": false
        }]),
    ) {
        Ok(response) => response,
        Err(reason) => return SimulationOutcome::Unavailable { reason },
    };
    if let Some(error) = non_null_rpc_error(&response) {
        return SimulationOutcome::Failed {
            reason: format!("simulateTransaction JSON-RPC error: {error}"),
        };
    }
    let Some(value) = response.pointer("/result/value") else {
        return SimulationOutcome::Unavailable {
            reason: "simulateTransaction missing result.value".to_string(),
        };
    };
    let Some(simulation_error) = value.get("err") else {
        return SimulationOutcome::Unavailable {
            reason: "simulateTransaction missing result.value.err".to_string(),
        };
    };
    if !simulation_error.is_null() {
        return SimulationOutcome::Failed {
            reason: format!("simulation failed: {simulation_error}"),
        };
    }
    let Some(simulation_slot) = response
        .pointer("/result/context/slot")
        .and_then(Value::as_u64)
    else {
        return SimulationOutcome::Unavailable {
            reason: "simulateTransaction missing or malformed result.context.slot".to_string(),
        };
    };

    let slot_response = match rpc.call("getSlot", json!([{"commitment": "confirmed"}])) {
        Ok(response) => response,
        Err(reason) => return SimulationOutcome::Unavailable { reason },
    };
    if let Some(error) = non_null_rpc_error(&slot_response) {
        return SimulationOutcome::Failed {
            reason: format!("getSlot JSON-RPC error: {error}"),
        };
    }
    let Some(current_slot) = slot_response.get("result").and_then(Value::as_u64) else {
        return SimulationOutcome::Unavailable {
            reason: "getSlot missing or malformed result".to_string(),
        };
    };

    if simulation_slot > current_slot || current_slot.saturating_sub(simulation_slot) > max_slot_age
    {
        SimulationOutcome::Stale {
            simulation_slot,
            current_slot,
        }
    } else {
        SimulationOutcome::Ok {
            simulation_slot,
            current_slot,
        }
    }
}

fn non_null_rpc_error(response: &Value) -> Option<&Value> {
    response.get("error").filter(|error| !error.is_null())
}

/// Real JSON-RPC transport over wasi:http (blocking `waki` client).
/// Compiled only for the wasm component; host tests never link it.
#[cfg(target_family = "wasm")]
pub struct WakiTransport {
    pub url: String,
}

#[cfg(target_family = "wasm")]
impl WakiTransport {
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

#[cfg(target_family = "wasm")]
impl RpcTransport for WakiTransport {
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = envelope(method, params);
        waki::Client::new()
            .post(&self.url)
            .json(&body)
            .send()
            .map_err(|e| format!("rpc transport error: {e}"))?
            .json::<Value>()
            .map_err(|e| format!("rpc response parse error: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_answers_and_records() {
        let rpc = MockTransport::new().with("getBalance", json!({"result": {"value": 42}}));
        let out = rpc.call("getBalance", json!([])).expect("fixture");
        assert_eq!(out["result"]["value"], 42);
        assert_eq!(rpc.calls()[0], ("getBalance".to_string(), json!([])));
    }

    #[test]
    fn missing_fixture_is_error_not_guess() {
        let rpc = MockTransport::new();
        assert!(rpc.call("getBalance", json!([])).is_err());
    }

    #[test]
    fn strict_simulation_submits_full_unsigned_transaction() {
        use solana_hash::Hash;
        use solana_message::Message;
        use solana_pubkey::Pubkey;

        let payer = Pubkey::new_from_array([1; 32]);
        let recipient = Pubkey::new_from_array([2; 32]);
        let mut message = Message::new(
            &[crate::ix::system_transfer(&payer, &recipient, 1)],
            Some(&payer),
        );
        message.recent_blockhash = Hash::new_from_array([3; 32]);
        let message_bytes = bincode::serialize(&message).expect("message");
        let decoded = crate::decode::decode(&message_bytes).expect("decode bare message");
        let rpc = MockTransport::new()
            .with(
                "simulateTransaction",
                json!({"result":{"context":{"slot":100},"value":{"err":null}}}),
            )
            .with("getSlot", json!({"result": 110}));

        assert_eq!(
            simulate_strict(&rpc, &decoded, 10),
            SimulationOutcome::Ok {
                simulation_slot: 100,
                current_slot: 110
            }
        );
        let calls = rpc.calls();
        assert_eq!(calls[0].0, "simulateTransaction");
        assert_eq!(
            calls[1],
            ("getSlot".to_string(), json!([{"commitment":"confirmed"}]))
        );
        let submitted = calls[0].1[0].as_str().expect("base64 transaction");
        let wire = crate::codec::base64_decode(submitted, 10_000).expect("wire");
        assert_eq!(wire[0], 1, "one signature slot");
        assert!(wire[1..65].iter().all(|byte| *byte == 0));
        assert_eq!(&wire[65..], message_bytes.as_slice());
    }

    #[test]
    fn strict_simulation_rejects_failure_stale_future_and_malformed_evidence() {
        use solana_hash::Hash;
        use solana_message::Message;
        use solana_pubkey::Pubkey;

        let payer = Pubkey::new_from_array([1; 32]);
        let recipient = Pubkey::new_from_array([2; 32]);
        let mut message = Message::new(
            &[crate::ix::system_transfer(&payer, &recipient, 1)],
            Some(&payer),
        );
        message.recent_blockhash = Hash::new_from_array([3; 32]);
        let decoded =
            crate::decode::decode(&bincode::serialize(&message).expect("message")).expect("decode");

        let failed = MockTransport::new().with(
            "simulateTransaction",
            json!({"result":{"context":{"slot":100},"value":{"err":{"InstructionError":[0,"Custom"]}}}}),
        );
        assert!(matches!(
            simulate_strict(&failed, &decoded, 10),
            SimulationOutcome::Failed { .. }
        ));

        for (simulation_slot, current_slot) in [(89, 100), (101, 100)] {
            let rpc = MockTransport::new()
                .with(
                    "simulateTransaction",
                    json!({"result":{"context":{"slot":simulation_slot},"value":{"err":null}}}),
                )
                .with("getSlot", json!({"result": current_slot}));
            assert!(matches!(
                simulate_strict(&rpc, &decoded, 10),
                SimulationOutcome::Stale { .. }
            ));
        }

        let malformed = MockTransport::new().with(
            "simulateTransaction",
            json!({"result":{"context":{"slot":100},"value":{}}}),
        );
        assert!(matches!(
            simulate_strict(&malformed, &decoded, 10),
            SimulationOutcome::Unavailable { .. }
        ));
        let rpc_error = MockTransport::new().with(
            "simulateTransaction",
            json!({"error":{"code":-32000,"message":"rejected"}}),
        );
        assert!(matches!(
            simulate_strict(&rpc_error, &decoded, 10),
            SimulationOutcome::Failed { .. }
        ));
    }

    #[test]
    fn classic_mint_proof_validates_exact_layout_and_coption_tags() {
        let mint_response = |data: Vec<u8>, owner: &str| {
            json!({"result":{"value":{
                "owner": owner,
                "data": [crate::codec::base64_encode(&data), "base64"]
            }}})
        };
        let mut valid = vec![0u8; 82];
        valid[0..4].copy_from_slice(&1u32.to_le_bytes());
        valid[44] = 6;
        valid[45] = 1;
        valid[46..50].copy_from_slice(&0u32.to_le_bytes());
        let rpc = MockTransport::new().with(
            "getAccountInfo",
            mint_response(valid.clone(), crate::crypto::TOKEN_PROGRAM),
        );
        assert_eq!(fetch_classic_mint_decimals(&rpc, "mint"), Ok(6));

        for range in [0..4, 46..50] {
            let mut malformed = valid.clone();
            malformed[range].copy_from_slice(&2u32.to_le_bytes());
            let rpc = MockTransport::new().with(
                "getAccountInfo",
                mint_response(malformed, crate::crypto::TOKEN_PROGRAM),
            );
            assert!(fetch_classic_mint_decimals(&rpc, "mint").is_err());
        }
    }

    #[test]
    fn transfer_checked_decimals_are_bound_to_classic_mint_evidence() {
        use solana_hash::Hash;
        use solana_message::Message;
        use solana_pubkey::Pubkey;

        let payer = Pubkey::new_from_array([1; 32]);
        let mint = Pubkey::new_from_array([2; 32]);
        let source = Pubkey::new_from_array([3; 32]);
        let destination_a = Pubkey::new_from_array([4; 32]);
        let destination_b = Pubkey::new_from_array([5; 32]);
        let token_program = crate::ix::spl_token_program();
        let mut message = Message::new(
            &[
                crate::ix::transfer_checked(
                    &token_program,
                    &source,
                    &mint,
                    &destination_a,
                    &payer,
                    1,
                    6,
                ),
                crate::ix::transfer_checked(
                    &token_program,
                    &source,
                    &mint,
                    &destination_b,
                    &payer,
                    2,
                    6,
                ),
            ],
            Some(&payer),
        );
        message.recent_blockhash = Hash::new_from_array([7; 32]);
        let decoded =
            crate::decode::decode(&bincode::serialize(&message).expect("message")).expect("decode");

        let mint_response = |decimals| {
            let mut data = vec![0u8; 82];
            data[44] = decimals;
            data[45] = 1;
            json!({"result":{"value":{
                "owner":crate::crypto::TOKEN_PROGRAM,
                "data":[crate::codec::base64_encode(&data),"base64"]
            }}})
        };
        let matching = MockTransport::new().with("getAccountInfo", mint_response(6));
        assert_eq!(verify_classic_transfer_mints(&matching, &decoded), Ok(()));
        assert_eq!(
            matching
                .calls()
                .iter()
                .filter(|(method, _)| method == "getAccountInfo")
                .count(),
            1,
            "a repeated mint must be fetched once"
        );

        let mismatched = MockTransport::new().with("getAccountInfo", mint_response(9));
        let error = verify_classic_transfer_mints(&mismatched, &decoded).unwrap_err();
        assert!(error.contains("declares 6 decimals"));
        assert!(error.contains("declares 9"));

        let mut conflicting_message = Message::new(
            &[
                crate::ix::transfer_checked(
                    &token_program,
                    &source,
                    &mint,
                    &destination_a,
                    &payer,
                    1,
                    6,
                ),
                crate::ix::transfer_checked(
                    &token_program,
                    &source,
                    &mint,
                    &destination_b,
                    &payer,
                    2,
                    9,
                ),
            ],
            Some(&payer),
        );
        conflicting_message.recent_blockhash = Hash::new_from_array([7; 32]);
        let conflicting = crate::decode::decode(
            &bincode::serialize(&conflicting_message).expect("conflicting message"),
        )
        .expect("decode conflicting message");
        let error = verify_classic_transfer_mints(&MockTransport::new(), &conflicting).unwrap_err();
        assert!(error.contains("declarations disagree"));
    }

    #[test]
    fn classic_mint_proof_rejects_untrusted_rpc_evidence() {
        let mut valid = vec![0u8; 82];
        valid[44] = 6;
        valid[45] = 1;
        let valid_b64 = crate::codec::base64_encode(&valid);
        let cases = [
            json!([]),
            json!({"error":{"code":-32000,"message":"rejected"}}),
            json!({"result":{"value":null}}),
            json!({"result":{"value":{"owner":crate::crypto::TOKEN_2022_PROGRAM,"data":[valid_b64.clone(),"base64"]}}}),
            json!({"result":{"value":{"owner":crate::crypto::TOKEN_PROGRAM,"data":["AA==","base64"]}}}),
            json!({"result":{"value":{"owner":crate::crypto::TOKEN_PROGRAM,"data":[valid_b64.clone(),"jsonParsed"]}}}),
        ];
        for response in cases {
            let rpc = MockTransport::new().with("getAccountInfo", response);
            assert!(fetch_classic_mint_decimals(&rpc, "mint").is_err());
        }

        valid[45] = 0;
        let rpc = MockTransport::new().with(
            "getAccountInfo",
            json!({"result":{"value":{"owner":crate::crypto::TOKEN_PROGRAM,"data":[crate::codec::base64_encode(&valid),"base64"]}}}),
        );
        assert!(fetch_classic_mint_decimals(&rpc, "mint").is_err());
    }

    fn nonce_account_bytes(
        version: u32,
        state: u32,
        authority: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Vec<u8> {
        let mut data = vec![0u8; 80];
        data[0..4].copy_from_slice(&version.to_le_bytes());
        data[4..8].copy_from_slice(&state.to_le_bytes());
        data[8..40].copy_from_slice(authority);
        data[40..72].copy_from_slice(nonce);
        data
    }

    fn nonce_response(data: Vec<u8>, owner: &str) -> Value {
        json!({"result": {"value": {
            "owner": owner,
            "data": [crate::codec::base64_encode(&data), "base64"]
        }}})
    }

    #[test]
    fn durable_nonce_is_returned_only_from_a_fully_proven_account() {
        let authority = [7u8; 32];
        let nonce = [9u8; 32];
        let authority_b58 = crate::bs58::encode(authority).into_string();
        let expected = crate::bs58::encode(nonce).into_string();
        let rpc = MockTransport::new().with(
            "getAccountInfo",
            nonce_response(
                nonce_account_bytes(1, 1, &authority, &nonce),
                crate::crypto::SYSTEM_PROGRAM,
            ),
        );
        assert_eq!(
            fetch_durable_nonce(&rpc, "nonce", &authority_b58),
            Ok(expected)
        );
    }

    #[test]
    fn a_nonce_account_that_cannot_be_fully_explained_is_refused() {
        let authority = [7u8; 32];
        let nonce = [9u8; 32];
        let authority_b58 = crate::bs58::encode(authority).into_string();
        let other_authority = crate::bs58::encode([8u8; 32]).into_string();

        let cases: Vec<(&str, Value, &str)> = vec![
            (
                "wrong owner",
                nonce_response(
                    nonce_account_bytes(1, 1, &authority, &nonce),
                    crate::crypto::TOKEN_PROGRAM,
                ),
                &authority_b58,
            ),
            (
                "uninitialized",
                nonce_response(
                    nonce_account_bytes(1, 0, &authority, &nonce),
                    crate::crypto::SYSTEM_PROGRAM,
                ),
                &authority_b58,
            ),
            (
                "unknown version",
                nonce_response(
                    nonce_account_bytes(2, 1, &authority, &nonce),
                    crate::crypto::SYSTEM_PROGRAM,
                ),
                &authority_b58,
            ),
            (
                "all-zero nonce",
                nonce_response(
                    nonce_account_bytes(1, 1, &authority, &[0u8; 32]),
                    crate::crypto::SYSTEM_PROGRAM,
                ),
                &authority_b58,
            ),
            (
                "authority mismatch",
                nonce_response(
                    nonce_account_bytes(1, 1, &authority, &nonce),
                    crate::crypto::SYSTEM_PROGRAM,
                ),
                &other_authority,
            ),
            (
                "short data",
                nonce_response(vec![0u8; 40], crate::crypto::SYSTEM_PROGRAM),
                &authority_b58,
            ),
            (
                "missing account",
                json!({"result": {"value": null}}),
                &authority_b58,
            ),
            (
                "rpc error",
                json!({"error": {"code": -32000, "message": "no"}}),
                &authority_b58,
            ),
        ];
        for (name, response, expected_authority) in cases {
            let rpc = MockTransport::new().with("getAccountInfo", response);
            assert!(
                fetch_durable_nonce(&rpc, "nonce", expected_authority).is_err(),
                "{name}: expected refusal"
            );
        }
    }

    #[test]
    fn down_transport_fails_closed() {
        assert!(DownTransport.call("getBalance", json!([])).is_err());
    }
}
