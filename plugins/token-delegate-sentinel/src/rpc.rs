use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::address::Address;
use crate::config::SentinelConfig;
use crate::token_account::{
    decode_mint_account, decode_token_account, MintAccount, ProgramKind, TokenAccount,
};

pub const MINT_BATCH_SIZE: usize = 100;

pub trait HttpTransport {
    fn post_json(
        &self,
        url: &str,
        request: &str,
        max_bytes: usize,
    ) -> Result<String, TransportError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    Unavailable,
    ResponseTooLarge,
    InvalidResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcError {
    TransportUnavailable,
    ResponseTooLarge,
    InvalidJson,
    ProtocolViolation,
    ServerRejected,
    InvalidGenesisHash,
    ContextSlotTooOld,
    TooManyAccounts,
    InvalidAccountAddress,
    WrongAccountProgram,
    InvalidAccountData,
    DuplicateAccount,
    InvalidMintData,
}

impl RpcError {
    pub fn code(self) -> &'static str {
        match self {
            Self::TransportUnavailable => "RPC_UNAVAILABLE",
            Self::ResponseTooLarge => "RPC_RESPONSE_TOO_LARGE",
            Self::InvalidJson => "RPC_INVALID_JSON",
            Self::ProtocolViolation => "RPC_PROTOCOL_VIOLATION",
            Self::ServerRejected => "RPC_SERVER_REJECTED",
            Self::InvalidGenesisHash => "RPC_GENESIS_HASH_INVALID",
            Self::ContextSlotTooOld => "RPC_CONTEXT_SLOT_TOO_OLD",
            Self::TooManyAccounts => "RPC_ACCOUNT_LIMIT_EXCEEDED",
            Self::InvalidAccountAddress => "RPC_ACCOUNT_ADDRESS_INVALID",
            Self::WrongAccountProgram => "RPC_ACCOUNT_PROGRAM_INVALID",
            Self::InvalidAccountData => "RPC_ACCOUNT_DATA_INVALID",
            Self::DuplicateAccount => "RPC_ACCOUNT_DUPLICATE",
            Self::InvalidMintData => "RPC_MINT_DATA_INVALID",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountBatch {
    pub slot: u64,
    pub accounts: Vec<TokenAccount>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintBatch {
    pub slots: Vec<u64>,
    pub mints: BTreeMap<(ProgramKind, Address), Option<MintAccount>>,
}

#[derive(Deserialize)]
struct Envelope {
    jsonrpc: String,
    id: Value,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

pub fn fetch_genesis_hash<T: HttpTransport>(
    config: &SentinelConfig,
    transport: &T,
) -> Result<Address, RpcError> {
    let result = call(config, transport, 1, "getGenesisHash", json!([]))?;
    let hash = result.as_str().ok_or(RpcError::ProtocolViolation)?;
    Address::parse(hash).map_err(|_| RpcError::InvalidGenesisHash)
}

pub fn fetch_token_accounts<T: HttpTransport>(
    config: &SentinelConfig,
    transport: &T,
    program: ProgramKind,
    request_id: u64,
    min_context_slot: Option<u64>,
    account_limit: usize,
) -> Result<AccountBatch, RpcError> {
    let mut options = json!({ "commitment": "finalized", "encoding": "base64" });
    if let Some(slot) = min_context_slot {
        options["minContextSlot"] = json!(slot);
    }
    let result = call(
        config,
        transport,
        request_id,
        "getTokenAccountsByOwner",
        json!([
            config.owner.to_string(),
            { "programId": program.program_id() },
            options
        ]),
    )?;
    let slot = context_slot(&result, min_context_slot)?;
    let values = result
        .get("value")
        .and_then(Value::as_array)
        .ok_or(RpcError::ProtocolViolation)?;
    if values.len() > account_limit {
        return Err(RpcError::TooManyAccounts);
    }

    let mut accounts = Vec::with_capacity(values.len());
    for value in values {
        let public_key = value
            .get("pubkey")
            .and_then(Value::as_str)
            .ok_or(RpcError::ProtocolViolation)?;
        let address = Address::parse(public_key).map_err(|_| RpcError::InvalidAccountAddress)?;
        let account = value.get("account").ok_or(RpcError::ProtocolViolation)?;
        validate_account_header(account, program)?;
        let decoded = decode_account_data(
            account,
            RpcError::InvalidAccountData,
            config.max_response_bytes,
        )?;
        validate_declared_space(account, decoded.len(), RpcError::InvalidAccountData)?;
        let parsed = decode_token_account(address, program, &decoded)
            .map_err(|_| RpcError::InvalidAccountData)?;
        if parsed.owner != config.owner {
            return Err(RpcError::InvalidAccountData);
        }
        accounts.push(parsed);
    }
    accounts.sort_by_key(|account| account.address);
    if accounts
        .windows(2)
        .any(|pair| pair[0].address == pair[1].address)
    {
        return Err(RpcError::DuplicateAccount);
    }
    Ok(AccountBatch { slot, accounts })
}

pub fn fetch_mints<T: HttpTransport>(
    config: &SentinelConfig,
    transport: &T,
    accounts: &[TokenAccount],
    min_context_slot: u64,
) -> Result<MintBatch, RpcError> {
    let keys: Vec<(ProgramKind, Address)> = accounts
        .iter()
        .filter(|account| account.delegate.is_some())
        .map(|account| (account.program, account.mint))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut mints = BTreeMap::new();
    let mut slots = Vec::new();

    for (batch_index, batch) in keys.chunks(MINT_BATCH_SIZE).enumerate() {
        let id = 4_u64
            .checked_add(batch_index as u64)
            .ok_or(RpcError::ProtocolViolation)?;
        let addresses: Vec<String> = batch
            .iter()
            .map(|(_, address)| address.to_string())
            .collect();
        let result = call(
            config,
            transport,
            id,
            "getMultipleAccounts",
            json!([
                addresses,
                {
                    "commitment": "finalized",
                    "encoding": "base64",
                    "minContextSlot": min_context_slot
                }
            ]),
        )?;
        let slot = context_slot(&result, Some(min_context_slot))?;
        slots.push(slot);
        let values = result
            .get("value")
            .and_then(Value::as_array)
            .ok_or(RpcError::ProtocolViolation)?;
        if values.len() != batch.len() {
            return Err(RpcError::ProtocolViolation);
        }

        for ((program, address), value) in batch.iter().copied().zip(values) {
            if value.is_null() {
                mints.insert((program, address), None);
                continue;
            }
            validate_account_header(value, program).map_err(|_| RpcError::InvalidMintData)?;
            let decoded =
                decode_account_data(value, RpcError::InvalidMintData, config.max_response_bytes)
                    .map_err(|_| RpcError::InvalidMintData)?;
            validate_declared_space(value, decoded.len(), RpcError::InvalidMintData)?;
            let mint = decode_mint_account(address, program, &decoded)
                .map_err(|_| RpcError::InvalidMintData)?;
            mints.insert((program, address), Some(mint));
        }
    }

    Ok(MintBatch { slots, mints })
}

fn context_slot(result: &Value, minimum: Option<u64>) -> Result<u64, RpcError> {
    let slot = result
        .get("context")
        .and_then(|context| context.get("slot"))
        .and_then(Value::as_u64)
        .ok_or(RpcError::ProtocolViolation)?;
    if minimum.is_some_and(|minimum| slot < minimum) {
        return Err(RpcError::ContextSlotTooOld);
    }
    Ok(slot)
}

fn validate_account_header(account: &Value, program: ProgramKind) -> Result<(), RpcError> {
    if account.get("executable").and_then(Value::as_bool) != Some(false)
        || account.get("owner").and_then(Value::as_str) != Some(program.program_id())
    {
        return Err(RpcError::WrongAccountProgram);
    }
    Ok(())
}

fn decode_account_data(
    account: &Value,
    error: RpcError,
    max_encoded_bytes: usize,
) -> Result<Vec<u8>, RpcError> {
    let data = account.get("data").and_then(Value::as_array).ok_or(error)?;
    if data.len() != 2 || data.get(1).and_then(Value::as_str) != Some("base64") {
        return Err(error);
    }
    let encoded = data.first().and_then(Value::as_str).ok_or(error)?;
    if encoded.len() > max_encoded_bytes {
        return Err(error);
    }
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| error)
}

fn validate_declared_space(
    account: &Value,
    decoded_len: usize,
    error: RpcError,
) -> Result<(), RpcError> {
    if let Some(space) = account.get("space") {
        let declared = space.as_u64().ok_or(error)?;
        if usize::try_from(declared).ok() != Some(decoded_len) {
            return Err(error);
        }
    }
    Ok(())
}

fn call<T: HttpTransport>(
    config: &SentinelConfig,
    transport: &T,
    id: u64,
    method: &str,
    params: Value,
) -> Result<Value, RpcError> {
    let request = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
    .to_string();
    let body = transport
        .post_json(&config.rpc_url, &request, config.max_response_bytes)
        .map_err(|error| match error {
            TransportError::Unavailable => RpcError::TransportUnavailable,
            TransportError::ResponseTooLarge => RpcError::ResponseTooLarge,
            TransportError::InvalidResponse => RpcError::InvalidJson,
        })?;
    if body.len() > config.max_response_bytes {
        return Err(RpcError::ResponseTooLarge);
    }
    let duplicate_checked: NoDuplicateValue =
        serde_json::from_str(&body).map_err(|_| RpcError::InvalidJson)?;
    let envelope: Envelope =
        serde_json::from_value(duplicate_checked.0).map_err(|_| RpcError::InvalidJson)?;
    if envelope.jsonrpc != "2.0" || envelope.id.as_u64() != Some(id) {
        return Err(RpcError::ProtocolViolation);
    }
    if envelope.error.is_some() {
        return Err(RpcError::ServerRejected);
    }
    envelope.result.ok_or(RpcError::ProtocolViolation)
}

struct NoDuplicateValue(Value);

impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

struct NoDuplicateVisitor;

impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = NoDuplicateValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(NoDuplicateValue)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(NoDuplicateValue(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NoDuplicateValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<NoDuplicateValue>()? {
            values.push(value.0);
        }
        Ok(NoDuplicateValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, NoDuplicateValue>()? {
            if values.insert(key, value.0).is_some() {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(NoDuplicateValue(Value::Object(values)))
    }
}
