//! Pure finalized-transaction quorum logic.
//!
//! This module has no WIT/WASI or configuration dependency. The component shim
//! supplies fixed RPC response bodies; this module validates and fingerprints
//! them, then applies fail-closed 2-of-3 classification.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};

use crate::core::{
    decode_pubkey, sha256_hex, validate_attestation_signature, AttestationPlan, CoreError,
    COMPUTE_BUDGET_PROGRAM_ID, COMPUTE_UNIT_LIMIT, MEMO_PROGRAM_ID, PROGRAM_ID,
};

pub const STATUS_REQUEST_ID: u64 = 11;
pub const TRANSACTION_REQUEST_ID: u64 = 12;
pub const REQUIRED_QUORUM: usize = 2;
pub const MAX_QUORUM_PROVIDERS: usize = 3;
pub const MAX_QUORUM_RESPONSE_BYTES: usize = 512 * 1024;

const MAX_TRANSACTION_BASE64_CHARS: usize = 8 * 1024;
const MAX_TRANSACTION_BYTES: usize = 4 * 1024;
const MAX_META_ERR_BYTES: usize = 8 * 1024;
const MAX_RETURN_DATA_BASE64_CHARS: usize = 4 * 1024;
const MAX_RETURN_DATA_BYTES: usize = 2 * 1024;

pub fn validate_transaction_signature(signature: &str) -> Result<(), CoreError> {
    validate_attestation_signature(signature)
}

/// Construct the only two JSON-RPC requests the receipt quorum may issue.
pub fn quorum_request_bodies(signature: &str) -> Result<[String; 2], CoreError> {
    validate_transaction_signature(signature)?;
    let status = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": STATUS_REQUEST_ID,
        "method": "getSignatureStatuses",
        "params": [[signature], {"searchTransactionHistory": true}],
    }))
    .map_err(|_| CoreError("REQUEST_SERIALIZATION_ERROR"))?;
    let transaction = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": TRANSACTION_REQUEST_ID,
        "method": "getTransaction",
        "params": [signature, {
            "commitment": "finalized",
            "encoding": "base64",
            "maxSupportedTransactionVersion": 0
        }],
    }))
    .map_err(|_| CoreError("REQUEST_SERIALIZATION_ERROR"))?;
    Ok([status, transaction])
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FinalizedStatus {
    slot: u64,
    meta_err_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StatusObservation {
    Finalized(FinalizedStatus),
    Lagging(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompleteTransaction {
    slot: u64,
    transaction_sha256: String,
    meta_err_sha256: String,
    return_data_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransactionObservation {
    Complete(CompleteTransaction),
    Lagging(&'static str),
}

fn parse_rpc_result(body: &str, expected_id: u64) -> Result<Value, CoreError> {
    if body.len() > MAX_QUORUM_RESPONSE_BYTES {
        return Err(CoreError("QUORUM_RESPONSE_TOO_LARGE"));
    }
    let envelope: Value =
        serde_json::from_str(body).map_err(|_| CoreError("MALFORMED_QUORUM_RPC_RESPONSE"))?;
    let envelope = envelope
        .as_object()
        .ok_or(CoreError("MALFORMED_QUORUM_RPC_RESPONSE"))?;
    if envelope.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(CoreError("MALFORMED_QUORUM_RPC_RESPONSE"));
    }
    if envelope.get("id").and_then(Value::as_u64) != Some(expected_id) {
        return Err(CoreError("QUORUM_RESPONSE_ID_MISMATCH"));
    }
    if envelope.get("error").is_some_and(|error| !error.is_null()) {
        return Err(CoreError("QUORUM_JSON_RPC_ERROR"));
    }
    envelope
        .get("result")
        .cloned()
        .ok_or(CoreError("MALFORMED_QUORUM_RPC_RESPONSE"))
}

fn parse_status(body: &str) -> Result<StatusObservation, CoreError> {
    let result = parse_rpc_result(body, STATUS_REQUEST_ID)?;
    let result = result
        .as_object()
        .ok_or(CoreError("INVALID_SIGNATURE_STATUS_RESPONSE"))?;
    let context_slot = result
        .get("context")
        .and_then(Value::as_object)
        .and_then(|context| context.get("slot"))
        .and_then(Value::as_u64)
        .ok_or(CoreError("INVALID_SIGNATURE_STATUS_RESPONSE"))?;
    let values = result
        .get("value")
        .and_then(Value::as_array)
        .ok_or(CoreError("INVALID_SIGNATURE_STATUS_RESPONSE"))?;
    if values.len() != 1 {
        return Err(CoreError("INVALID_SIGNATURE_STATUS_RESPONSE"));
    }
    let Some(status) = values[0].as_object() else {
        return if values[0].is_null() {
            Ok(StatusObservation::Lagging("SIGNATURE_STATUS_NOT_FOUND"))
        } else {
            Err(CoreError("INVALID_SIGNATURE_STATUS_RESPONSE"))
        };
    };
    let slot = status
        .get("slot")
        .and_then(Value::as_u64)
        .ok_or(CoreError("INVALID_SIGNATURE_STATUS_RESPONSE"))?;
    if slot > context_slot {
        return Err(CoreError("INVALID_SIGNATURE_STATUS_RESPONSE"));
    }
    match status.get("confirmationStatus") {
        Some(Value::String(value)) if value == "finalized" => {}
        Some(Value::String(value)) if value == "confirmed" || value == "processed" => {
            return Ok(StatusObservation::Lagging("STATUS_NOT_FINALIZED"));
        }
        Some(Value::Null) => return Ok(StatusObservation::Lagging("STATUS_NOT_FINALIZED")),
        _ => return Err(CoreError("INVALID_SIGNATURE_STATUS_RESPONSE")),
    }
    let err = status
        .get("err")
        .ok_or(CoreError("INVALID_SIGNATURE_STATUS_RESPONSE"))?;
    Ok(StatusObservation::Finalized(FinalizedStatus {
        slot,
        meta_err_sha256: canonical_json_digest(err, MAX_META_ERR_BYTES)?,
    }))
}

fn parse_transaction(
    body: &str,
    expected_signature: &str,
) -> Result<TransactionObservation, CoreError> {
    let result = parse_rpc_result(body, TRANSACTION_REQUEST_ID)?;
    if result.is_null() {
        return Ok(TransactionObservation::Lagging(
            "FINALIZED_TRANSACTION_NOT_AVAILABLE",
        ));
    }
    let result = result
        .as_object()
        .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_RESPONSE"))?;
    let slot = result
        .get("slot")
        .and_then(Value::as_u64)
        .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_RESPONSE"))?;
    let transaction = decode_transaction(
        result
            .get("transaction")
            .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_RESPONSE"))?,
    )?;
    verify_first_signature(&transaction, expected_signature)?;

    let meta = result
        .get("meta")
        .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_RESPONSE"))?;
    if meta.is_null() {
        return Ok(TransactionObservation::Lagging(
            "FINALIZED_TRANSACTION_METADATA_UNAVAILABLE",
        ));
    }
    let meta = meta
        .as_object()
        .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_RESPONSE"))?;
    let err = meta
        .get("err")
        .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_RESPONSE"))?;
    Ok(TransactionObservation::Complete(CompleteTransaction {
        slot,
        transaction_sha256: sha256_hex(&transaction),
        meta_err_sha256: canonical_json_digest(err, MAX_META_ERR_BYTES)?,
        return_data_sha256: return_data_digest(meta.get("returnData"))?,
    }))
}

fn decode_transaction(value: &Value) -> Result<Vec<u8>, CoreError> {
    let encoded = match value {
        Value::String(encoded) => encoded.as_str(),
        Value::Array(parts)
            if parts.len() == 2 && parts.get(1).and_then(Value::as_str) == Some("base64") =>
        {
            parts[0]
                .as_str()
                .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_ENCODING"))?
        }
        _ => return Err(CoreError("INVALID_FINALIZED_TRANSACTION_ENCODING")),
    };
    if encoded.is_empty() || encoded.len() > MAX_TRANSACTION_BASE64_CHARS {
        return Err(CoreError("FINALIZED_TRANSACTION_TOO_LARGE"));
    }
    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| CoreError("INVALID_FINALIZED_TRANSACTION_ENCODING"))?;
    if decoded.is_empty() || decoded.len() > MAX_TRANSACTION_BYTES {
        return Err(CoreError("FINALIZED_TRANSACTION_TOO_LARGE"));
    }
    Ok(decoded)
}

fn verify_first_signature(transaction: &[u8], expected: &str) -> Result<(), CoreError> {
    let expected = bs58::decode(expected)
        .into_vec()
        .map_err(|_| CoreError("INVALID_TRANSACTION_SIGNATURE"))?;
    if expected.len() != 64 {
        return Err(CoreError("INVALID_TRANSACTION_SIGNATURE"));
    }
    let (signature_count, prefix_len) = decode_short_u16(transaction)?;
    if signature_count == 0 || signature_count > 64 {
        return Err(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"));
    }
    let signatures_len = signature_count
        .checked_mul(64)
        .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"))?;
    let message_offset = prefix_len
        .checked_add(signatures_len)
        .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"))?;
    if message_offset >= transaction.len() || prefix_len + 64 > transaction.len() {
        return Err(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"));
    }
    if transaction[prefix_len..prefix_len + 64] != expected {
        return Err(CoreError("FINALIZED_TRANSACTION_SIGNATURE_MISMATCH"));
    }
    Ok(())
}

fn decode_short_u16(bytes: &[u8]) -> Result<(usize, usize), CoreError> {
    let mut value = 0usize;
    for index in 0..3 {
        let byte = *bytes
            .get(index)
            .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"))?;
        let payload = (byte & 0x7f) as usize;
        value |= payload << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && payload == 0 {
                return Err(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"));
            }
            if value > u16::MAX as usize {
                return Err(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"));
            }
            return Ok((value, index + 1));
        }
    }
    Err(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttestationBinding {
    pub finalized_slot: u64,
    pub transaction_sha256: String,
    pub payer: String,
    pub memo_receipt_sha256: String,
    pub instruction_sha256: String,
    pub predicate_result: bool,
}

/// Bind a finalized transaction response to the fresh TxLINE proof plan.
///
/// The accepted wire shape is intentionally narrow: one legacy signature,
/// five fixed static accounts, and exactly ComputeBudget, Memo, then TxLINE
/// `validate_stat` instructions. This prevents unrelated successful
/// transactions from being reused as sports settlement evidence.
pub fn verify_attestation_response(
    body: &str,
    signature: &str,
    fixture_id: u64,
    sequence: u64,
    plan: &AttestationPlan,
) -> Result<AttestationBinding, CoreError> {
    validate_transaction_signature(signature)?;
    let result = parse_rpc_result(body, TRANSACTION_REQUEST_ID)?;
    let result = result
        .as_object()
        .ok_or(CoreError("FINALIZED_TRANSACTION_NOT_AVAILABLE"))?;
    let slot = result
        .get("slot")
        .and_then(Value::as_u64)
        .filter(|slot| *slot > 0)
        .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_RESPONSE"))?;
    let transaction = decode_transaction(
        result
            .get("transaction")
            .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_RESPONSE"))?,
    )?;
    verify_first_signature(&transaction, signature)?;

    let meta = result
        .get("meta")
        .and_then(Value::as_object)
        .ok_or(CoreError("FINALIZED_TRANSACTION_METADATA_UNAVAILABLE"))?;
    if !meta.get("err").is_some_and(Value::is_null) {
        return Err(CoreError("FINALIZED_TRANSACTION_FAILED"));
    }
    verify_predicate_return(meta.get("returnData"), plan.predicate_result)?;

    let wire = parse_attestation_wire(&transaction)?;
    let expected_daily = plan.daily_scores_pda_bytes;
    let expected_program =
        decode_pubkey(PROGRAM_ID).map_err(|_| CoreError("INVALID_PROGRAM_ID"))?;
    let expected_compute = decode_pubkey(COMPUTE_BUDGET_PROGRAM_ID)
        .map_err(|_| CoreError("INVALID_COMPUTE_PROGRAM_ID"))?;
    let expected_memo =
        decode_pubkey(MEMO_PROGRAM_ID).map_err(|_| CoreError("INVALID_MEMO_PROGRAM_ID"))?;
    if wire.header != [1, 0, 4]
        || wire.accounts.len() != 5
        || wire.accounts[1] != expected_daily
        || wire.accounts[2] != expected_program
        || wire.accounts[3] != expected_compute
        || wire.accounts[4] != expected_memo
        || wire.instructions.len() != 3
    {
        return Err(CoreError("ATTESTATION_ACCOUNT_LAYOUT_MISMATCH"));
    }

    let expected_compute_data = {
        let mut data = vec![2];
        data.extend_from_slice(&COMPUTE_UNIT_LIMIT.to_le_bytes());
        data
    };
    let compute = &wire.instructions[0];
    if compute.program_index != 3
        || !compute.account_indices.is_empty()
        || compute.data != expected_compute_data
    {
        return Err(CoreError("ATTESTATION_COMPUTE_INSTRUCTION_MISMATCH"));
    }

    let memo = &wire.instructions[1];
    if memo.program_index != 4 || memo.account_indices != [0] {
        return Err(CoreError("ATTESTATION_MEMO_INSTRUCTION_MISMATCH"));
    }
    let memo_text =
        std::str::from_utf8(&memo.data).map_err(|_| CoreError("ATTESTATION_MEMO_INVALID"))?;
    let memo_receipt_sha256 =
        parse_strict_memo(memo_text, fixture_id, sequence, &plan.predicate_compact)?;

    let validate = &wire.instructions[2];
    if validate.program_index != 2
        || validate.account_indices != [1]
        || validate.data != plan.instruction
    {
        return Err(CoreError("ATTESTATION_VALIDATE_INSTRUCTION_MISMATCH"));
    }

    Ok(AttestationBinding {
        finalized_slot: slot,
        transaction_sha256: sha256_hex(&transaction),
        payer: bs58::encode(wire.accounts[0]).into_string(),
        memo_receipt_sha256,
        instruction_sha256: plan.instruction_sha256.clone(),
        predicate_result: plan.predicate_result,
    })
}

fn verify_predicate_return(value: Option<&Value>, expected: bool) -> Result<(), CoreError> {
    let value = value
        .and_then(Value::as_object)
        .ok_or(CoreError("MISSING_FINALIZED_RETURN_DATA"))?;
    if value.get("programId").and_then(Value::as_str) != Some(PROGRAM_ID) {
        return Err(CoreError("RETURN_PROGRAM_MISMATCH"));
    }
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or(CoreError("INVALID_FINALIZED_RETURN_DATA"))?;
    if data.len() != 2 || data[1].as_str() != Some("base64") {
        return Err(CoreError("INVALID_FINALIZED_RETURN_DATA"));
    }
    let decoded = BASE64_STANDARD
        .decode(
            data[0]
                .as_str()
                .ok_or(CoreError("INVALID_FINALIZED_RETURN_DATA"))?,
        )
        .map_err(|_| CoreError("INVALID_FINALIZED_RETURN_DATA"))?;
    let expected_byte = u8::from(expected);
    if decoded != [expected_byte] {
        return Err(CoreError("PREDICATE_RETURN_MISMATCH"));
    }
    Ok(())
}

fn parse_strict_memo(
    memo: &str,
    fixture_id: u64,
    sequence: u64,
    predicate: &str,
) -> Result<String, CoreError> {
    let parts: Vec<_> = memo.split(" | ").collect();
    if parts.len() != 5 || parts[0] != "SettleTrace v1" {
        return Err(CoreError("ATTESTATION_MEMO_INVALID"));
    }
    let receipt_hash = parts[3]
        .strip_prefix("receiptHash=")
        .ok_or(CoreError("ATTESTATION_MEMO_INVALID"))?;
    if receipt_hash.len() != 64
        || !receipt_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CoreError("ATTESTATION_MEMO_INVALID"));
    }
    let expected = format!(
        "SettleTrace v1 | fixture={fixture_id} | seq={sequence} | receiptHash={receipt_hash} | predicate={predicate}"
    );
    if memo != expected {
        return Err(CoreError("ATTESTATION_MEMO_MISMATCH"));
    }
    Ok(receipt_hash.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAttestationWire {
    header: [u8; 3],
    accounts: Vec<[u8; 32]>,
    instructions: Vec<CompiledInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompiledInstruction {
    program_index: u8,
    account_indices: Vec<u8>,
    data: Vec<u8>,
}

fn parse_attestation_wire(transaction: &[u8]) -> Result<ParsedAttestationWire, CoreError> {
    let (signature_count, signature_prefix) = decode_short_u16(transaction)?;
    if signature_count != 1 {
        return Err(CoreError("ATTESTATION_SIGNATURE_COUNT_MISMATCH"));
    }
    let message_offset = signature_prefix
        .checked_add(64)
        .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"))?;
    let mut reader = WireReader::new(
        transaction
            .get(message_offset..)
            .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"))?,
    );
    if reader.peek()? & 0x80 != 0 {
        return Err(CoreError("UNSUPPORTED_VERSIONED_ATTESTATION"));
    }
    let header = [reader.byte()?, reader.byte()?, reader.byte()?];
    let account_count = reader.shortvec()?;
    if !(1..=32).contains(&account_count) {
        return Err(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"));
    }
    let mut accounts = Vec::with_capacity(account_count);
    for _ in 0..account_count {
        accounts.push(
            reader
                .bytes(32)?
                .try_into()
                .map_err(|_| CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"))?,
        );
    }
    reader.bytes(32)?; // recent blockhash; identity is irrelevant to the receipt binding.
    let instruction_count = reader.shortvec()?;
    if instruction_count > 16 {
        return Err(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"));
    }
    let mut instructions = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        let program_index = reader.byte()?;
        let account_len = reader.shortvec()?;
        if account_len > 32 {
            return Err(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"));
        }
        let account_indices = reader.bytes(account_len)?.to_vec();
        let data_len = reader.shortvec()?;
        if data_len > 2 * 1024 {
            return Err(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"));
        }
        let data = reader.bytes(data_len)?.to_vec();
        instructions.push(CompiledInstruction {
            program_index,
            account_indices,
            data,
        });
    }
    if !reader.finished() {
        return Err(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"));
    }
    Ok(ParsedAttestationWire {
        header,
        accounts,
        instructions,
    })
}

struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn peek(&self) -> Result<u8, CoreError> {
        self.bytes
            .get(self.offset)
            .copied()
            .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"))
    }

    fn byte(&mut self) -> Result<u8, CoreError> {
        let byte = self.peek()?;
        self.offset += 1;
        Ok(byte)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], CoreError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn shortvec(&mut self) -> Result<usize, CoreError> {
        let (value, len) = decode_short_u16(
            self.bytes
                .get(self.offset..)
                .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"))?,
        )?;
        self.offset = self
            .offset
            .checked_add(len)
            .ok_or(CoreError("INVALID_FINALIZED_TRANSACTION_WIRE_FORMAT"))?;
        Ok(value)
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn canonical_json_digest(value: &Value, cap: usize) -> Result<String, CoreError> {
    let encoded = serde_json::to_vec(value).map_err(|_| CoreError("CANONICAL_JSON_ERROR"))?;
    if encoded.len() > cap {
        return Err(CoreError("QUORUM_DIGEST_INPUT_TOO_LARGE"));
    }
    Ok(sha256_hex(encoded))
}

fn return_data_digest(value: Option<&Value>) -> Result<String, CoreError> {
    let Some(value) = value else {
        return Ok(sha256_hex(b"sports-settlement-receipt:return-data:none:v1"));
    };
    if value.is_null() {
        return Ok(sha256_hex(b"sports-settlement-receipt:return-data:none:v1"));
    }
    let value = value
        .as_object()
        .ok_or(CoreError("INVALID_FINALIZED_RETURN_DATA"))?;
    if value.len() != 2 {
        return Err(CoreError("INVALID_FINALIZED_RETURN_DATA"));
    }
    let program_id = value
        .get("programId")
        .and_then(Value::as_str)
        .ok_or(CoreError("INVALID_FINALIZED_RETURN_DATA"))?;
    let program_id_bytes = bs58::decode(program_id)
        .into_vec()
        .map_err(|_| CoreError("INVALID_FINALIZED_RETURN_DATA"))?;
    if program_id_bytes.len() != 32 {
        return Err(CoreError("INVALID_FINALIZED_RETURN_DATA"));
    }
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or(CoreError("INVALID_FINALIZED_RETURN_DATA"))?;
    if data.len() != 2 || data[1].as_str() != Some("base64") {
        return Err(CoreError("INVALID_FINALIZED_RETURN_DATA"));
    }
    let encoded = data[0]
        .as_str()
        .ok_or(CoreError("INVALID_FINALIZED_RETURN_DATA"))?;
    if encoded.len() > MAX_RETURN_DATA_BASE64_CHARS {
        return Err(CoreError("FINALIZED_RETURN_DATA_TOO_LARGE"));
    }
    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| CoreError("INVALID_FINALIZED_RETURN_DATA"))?;
    if decoded.len() > MAX_RETURN_DATA_BYTES {
        return Err(CoreError("FINALIZED_RETURN_DATA_TOO_LARGE"));
    }
    let mut material = b"sports-settlement-receipt:return-data:v1\0".to_vec();
    material.extend_from_slice(&(program_id.len() as u32).to_be_bytes());
    material.extend_from_slice(program_id.as_bytes());
    material.extend_from_slice(&(decoded.len() as u32).to_be_bytes());
    material.extend_from_slice(&decoded);
    Ok(sha256_hex(material))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderState {
    Complete,
    Lagging,
    Diverged,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    slot: u64,
    transaction_sha256: String,
    meta_err_sha256: String,
    return_data_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderEvidence {
    pub provider: u8,
    pub state: ProviderState,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta_err_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_data_sha256: Option<String>,
    #[serde(skip)]
    fingerprint: Option<Fingerprint>,
}

impl ProviderEvidence {
    fn empty(provider: u8, state: ProviderState, code: &str) -> Self {
        Self {
            provider,
            state,
            code: code.to_owned(),
            status_slot: None,
            transaction_slot: None,
            transaction_sha256: None,
            meta_err_sha256: None,
            return_data_sha256: None,
            fingerprint: None,
        }
    }

    pub fn unknown(provider: u8, code: &str) -> Self {
        Self::empty(provider, ProviderState::Unknown, code)
    }

    /// Convert an otherwise complete provider into an explicit contradiction
    /// when the transaction does not bind the requested sports proof exactly.
    pub fn binding_diverged(mut self, code: &str) -> Self {
        self.state = ProviderState::Diverged;
        self.code = code.to_owned();
        self.fingerprint = None;
        self
    }
}

/// Inspect one provider from already-bounded response bodies or stable transport errors.
pub fn inspect_provider(
    provider: u8,
    signature: &str,
    status_response: Result<&str, &'static str>,
    transaction_response: Result<&str, &'static str>,
) -> ProviderEvidence {
    if let Err(error) = validate_transaction_signature(signature) {
        return ProviderEvidence::unknown(provider, error.code());
    }
    let status = match status_response {
        Ok(body) => match parse_status(body) {
            Ok(status) => status,
            Err(error) => return ProviderEvidence::unknown(provider, error.code()),
        },
        Err(code) => return ProviderEvidence::unknown(provider, code),
    };
    let transaction = match transaction_response {
        Ok(body) => match parse_transaction(body, signature) {
            Ok(transaction) => transaction,
            Err(error) => return ProviderEvidence::unknown(provider, error.code()),
        },
        Err(code) => return ProviderEvidence::unknown(provider, code),
    };

    match (status, transaction) {
        (StatusObservation::Lagging(_), TransactionObservation::Lagging(_)) => {
            ProviderEvidence::empty(
                provider,
                ProviderState::Lagging,
                "STATUS_AND_TRANSACTION_LAGGING",
            )
        }
        (StatusObservation::Lagging(_), TransactionObservation::Complete(transaction)) => {
            let mut evidence = ProviderEvidence::empty(
                provider,
                ProviderState::Diverged,
                "STATUS_TRANSACTION_AVAILABILITY_CONFLICT",
            );
            evidence.transaction_slot = Some(transaction.slot);
            evidence.transaction_sha256 = Some(transaction.transaction_sha256);
            evidence.meta_err_sha256 = Some(transaction.meta_err_sha256);
            evidence.return_data_sha256 = Some(transaction.return_data_sha256);
            evidence
        }
        (StatusObservation::Finalized(status), TransactionObservation::Lagging(code)) => {
            let mut evidence = ProviderEvidence::empty(provider, ProviderState::Lagging, code);
            evidence.status_slot = Some(status.slot);
            evidence.meta_err_sha256 = Some(status.meta_err_sha256);
            evidence
        }
        (StatusObservation::Finalized(status), TransactionObservation::Complete(transaction)) => {
            let mut evidence =
                ProviderEvidence::empty(provider, ProviderState::Complete, "COMPLETE");
            evidence.status_slot = Some(status.slot);
            evidence.transaction_slot = Some(transaction.slot);
            evidence.transaction_sha256 = Some(transaction.transaction_sha256.clone());
            evidence.meta_err_sha256 = Some(transaction.meta_err_sha256.clone());
            evidence.return_data_sha256 = Some(transaction.return_data_sha256.clone());
            if status.slot != transaction.slot {
                evidence.state = ProviderState::Diverged;
                evidence.code = "INTRA_PROVIDER_SLOT_MISMATCH".to_owned();
                return evidence;
            }
            if status.meta_err_sha256 != transaction.meta_err_sha256 {
                evidence.state = ProviderState::Diverged;
                evidence.code = "INTRA_PROVIDER_META_ERR_MISMATCH".to_owned();
                return evidence;
            }
            evidence.fingerprint = Some(Fingerprint {
                slot: transaction.slot,
                transaction_sha256: transaction.transaction_sha256,
                meta_err_sha256: transaction.meta_err_sha256,
                return_data_sha256: transaction.return_data_sha256,
            });
            evidence
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuorumVerdict {
    Consistent,
    Lagging,
    Diverged,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuorumDecision {
    pub verdict: QuorumVerdict,
    pub required: usize,
    pub configured: usize,
    pub complete: usize,
    pub lagging: usize,
    pub diverged: usize,
    pub unknown: usize,
    pub code: String,
    pub providers: Vec<ProviderEvidence>,
}

/// Classify two or three provider observations. Any contradiction wins over a majority.
pub fn classify_quorum(providers: Vec<ProviderEvidence>) -> QuorumDecision {
    let configured = providers.len();
    let complete = providers
        .iter()
        .filter(|provider| provider.state == ProviderState::Complete)
        .count();
    let lagging = providers
        .iter()
        .filter(|provider| provider.state == ProviderState::Lagging)
        .count();
    let diverged = providers
        .iter()
        .filter(|provider| provider.state == ProviderState::Diverged)
        .count();
    let unknown = providers
        .iter()
        .filter(|provider| provider.state == ProviderState::Unknown)
        .count();
    let fingerprints: Vec<&Fingerprint> = providers
        .iter()
        .filter_map(|provider| provider.fingerprint.as_ref())
        .collect();
    let cross_provider_divergence = fingerprints
        .first()
        .is_some_and(|first| fingerprints.iter().skip(1).any(|other| *other != *first));

    let (verdict, code) = if !(2..=MAX_QUORUM_PROVIDERS).contains(&configured) {
        (QuorumVerdict::Unknown, "INVALID_QUORUM_PROVIDER_COUNT")
    } else if diverged > 0 || cross_provider_divergence {
        (QuorumVerdict::Diverged, "FINALIZED_EVIDENCE_DIVERGED")
    } else if complete >= REQUIRED_QUORUM {
        (QuorumVerdict::Consistent, "FINALIZED_EVIDENCE_CONSISTENT")
    } else if unknown == 0 && lagging > 0 {
        (QuorumVerdict::Lagging, "FINALIZED_EVIDENCE_QUORUM_LAGGING")
    } else {
        (QuorumVerdict::Unknown, "FINALIZED_EVIDENCE_QUORUM_UNKNOWN")
    };
    QuorumDecision {
        verdict,
        required: REQUIRED_QUORUM,
        configured,
        complete,
        lagging,
        diverged,
        unknown,
        code: code.to_owned(),
        providers,
    }
}
