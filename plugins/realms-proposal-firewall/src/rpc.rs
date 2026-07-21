use std::{
    collections::HashSet,
    error::Error,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Map, Value};

use crate::{config::Config, pubkey::Pubkey};

pub const MAX_MULTIPLE_ACCOUNTS: usize = 100;
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_ACCOUNT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_ACCOUNT_BYTES: usize = 2 * 1024 * 1024;

/// A deliberately small blocking HTTP boundary. Implementations must map their
/// native errors to one of the non-sensitive variants below.
pub trait Transport {
    fn post(
        &self,
        url: &str,
        body: &[u8],
        max_response_bytes: usize,
    ) -> Result<TransportResponse, TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    Timeout,
    Connection,
    ResponseTooLarge,
    Other,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Timeout => "RPC transport timed out",
            Self::Connection => "RPC transport failed",
            Self::ResponseTooLarge => "RPC response exceeded the transport limit",
            Self::Other => "RPC transport failed",
        })
    }
}

impl Error for TransportError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcLimits {
    pub max_response_bytes: usize,
    pub max_account_bytes: usize,
    pub max_total_account_bytes: usize,
}

impl Default for RpcLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_account_bytes: DEFAULT_MAX_ACCOUNT_BYTES,
            max_total_account_bytes: DEFAULT_MAX_TOTAL_ACCOUNT_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    pub lamports: u64,
    pub owner: Pubkey,
    pub executable: bool,
    /// Exact bytes returned by RPC, retained for final snapshot comparison.
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRead {
    pub context_slot: u64,
    pub account: Account,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultipleAccountsRead {
    pub context_slot: u64,
    pub accounts: Vec<Option<Account>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcError {
    Transport,
    HttpStatus,
    ResponseTooLarge,
    RequestIdExhausted,
    MalformedJson,
    InvalidJsonRpcVersion,
    MismatchedResponseId,
    InvalidResponseShape,
    RemoteError,
    InvalidResult,
    NullAccount,
    StaleContext,
    InvalidAccount,
    InvalidOwner,
    InvalidDataEncoding,
    InvalidBase64,
    AccountTooLarge,
    AggregateDataTooLarge,
    TooManyAddresses,
    DuplicateAddress,
    CardinalityMismatch,
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Transport => "RPC transport failed",
            Self::HttpStatus => "RPC returned an unacceptable HTTP status",
            Self::ResponseTooLarge => "RPC response exceeded the configured limit",
            Self::RequestIdExhausted => "RPC request ID space exhausted",
            Self::MalformedJson => "RPC returned malformed JSON",
            Self::InvalidJsonRpcVersion => "RPC returned an invalid JSON-RPC version",
            Self::MismatchedResponseId => "RPC returned a mismatched request ID",
            Self::InvalidResponseShape => "RPC returned an invalid response shape",
            Self::RemoteError => "RPC returned a JSON-RPC error",
            Self::InvalidResult => "RPC returned an invalid result",
            Self::NullAccount => "RPC account result was null",
            Self::StaleContext => "RPC context slot was stale",
            Self::InvalidAccount => "RPC returned invalid account fields",
            Self::InvalidOwner => "RPC returned an invalid account owner",
            Self::InvalidDataEncoding => "RPC returned an invalid account data encoding",
            Self::InvalidBase64 => "RPC returned invalid base64 account data",
            Self::AccountTooLarge => "RPC account data exceeded the configured limit",
            Self::AggregateDataTooLarge => {
                "RPC aggregate account data exceeded the configured limit"
            }
            Self::TooManyAddresses => "RPC account request exceeded the address limit",
            Self::DuplicateAddress => "RPC account request contained a duplicate address",
            Self::CardinalityMismatch => "RPC account result cardinality did not match the request",
        })
    }
}

impl Error for RpcError {}

pub struct RpcClient<T> {
    rpc_url: String,
    transport: T,
    limits: RpcLimits,
    next_id: AtomicU64,
}

impl<T: Transport> RpcClient<T> {
    pub fn from_config(config: &Config, transport: T) -> Self {
        Self::new(config.rpc_url.clone(), transport)
    }

    pub fn new(rpc_url: impl Into<String>, transport: T) -> Self {
        Self::with_limits(rpc_url, transport, RpcLimits::default())
    }

    pub fn with_limits(rpc_url: impl Into<String>, transport: T, limits: RpcLimits) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            transport,
            limits,
            next_id: AtomicU64::new(1),
        }
    }

    pub fn get_genesis_hash(&self) -> Result<Pubkey, RpcError> {
        let id = self.next_request_id()?;
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "getGenesisHash",
            "params": [],
        });
        let result = self.call(id, &request)?;
        let hash = result.as_str().ok_or(RpcError::InvalidResult)?;
        hash.parse().map_err(|_| RpcError::InvalidResult)
    }

    pub fn get_account_info(
        &self,
        address: &Pubkey,
        min_context_slot: Option<u64>,
    ) -> Result<AccountRead, RpcError> {
        let id = self.next_request_id()?;
        let options = account_options(min_context_slot);
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "getAccountInfo",
            "params": [address, options],
        });
        let result = self.call(id, &request)?;
        let (context_slot, value) = parse_context_result(&result, min_context_slot)?;
        if value.is_null() {
            return Err(RpcError::NullAccount);
        }
        let (account, data_len) = parse_account(value, self.limits)?;
        if data_len > self.limits.max_total_account_bytes {
            return Err(RpcError::AggregateDataTooLarge);
        }
        Ok(AccountRead {
            context_slot,
            account,
        })
    }

    pub fn get_multiple_accounts(
        &self,
        addresses: &[Pubkey],
        min_context_slot: Option<u64>,
    ) -> Result<MultipleAccountsRead, RpcError> {
        if addresses.len() > MAX_MULTIPLE_ACCOUNTS {
            return Err(RpcError::TooManyAddresses);
        }
        let mut unique = HashSet::with_capacity(addresses.len());
        if addresses.iter().any(|address| !unique.insert(*address)) {
            return Err(RpcError::DuplicateAddress);
        }

        let id = self.next_request_id()?;
        let options = account_options(min_context_slot);
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "getMultipleAccounts",
            "params": [addresses, options],
        });
        let result = self.call(id, &request)?;
        let (context_slot, value) = parse_context_result(&result, min_context_slot)?;
        let values = value.as_array().ok_or(RpcError::InvalidResult)?;
        if values.len() != addresses.len() {
            return Err(RpcError::CardinalityMismatch);
        }

        let mut total_bytes = 0usize;
        let mut accounts = Vec::with_capacity(values.len());
        for value in values {
            if value.is_null() {
                accounts.push(None);
                continue;
            }
            let (account, data_len) = parse_account(value, self.limits)?;
            total_bytes = total_bytes
                .checked_add(data_len)
                .ok_or(RpcError::AggregateDataTooLarge)?;
            if total_bytes > self.limits.max_total_account_bytes {
                return Err(RpcError::AggregateDataTooLarge);
            }
            accounts.push(Some(account));
        }

        Ok(MultipleAccountsRead {
            context_slot,
            accounts,
        })
    }

    fn next_request_id(&self) -> Result<u64, RpcError> {
        self.next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| RpcError::RequestIdExhausted)
    }

    fn call(&self, id: u64, request: &Value) -> Result<Value, RpcError> {
        let body = serde_json::to_vec(request).map_err(|_| RpcError::InvalidResponseShape)?;
        let response = self.send_with_retry(&body)?;
        let value: Value =
            serde_json::from_slice(&response).map_err(|_| RpcError::MalformedJson)?;
        parse_envelope(value, id)
    }

    fn send_with_retry(&self, body: &[u8]) -> Result<Vec<u8>, RpcError> {
        for attempt in 0..2 {
            let response =
                match self
                    .transport
                    .post(&self.rpc_url, body, self.limits.max_response_bytes)
                {
                    Ok(response) => response,
                    Err(TransportError::ResponseTooLarge) => {
                        return Err(RpcError::ResponseTooLarge)
                    }
                    Err(_) if attempt == 0 => continue,
                    Err(_) => return Err(RpcError::Transport),
                };

            if response.body.len() > self.limits.max_response_bytes {
                return Err(RpcError::ResponseTooLarge);
            }
            if response.status == 429 || (500..=599).contains(&response.status) {
                if attempt == 0 {
                    continue;
                }
                return Err(RpcError::HttpStatus);
            }
            if response.status != 200 {
                return Err(RpcError::HttpStatus);
            }
            return Ok(response.body);
        }
        Err(RpcError::Transport)
    }
}

fn account_options(min_context_slot: Option<u64>) -> Value {
    let mut options = Map::new();
    options.insert("encoding".to_owned(), Value::String("base64".to_owned()));
    options.insert(
        "commitment".to_owned(),
        Value::String("finalized".to_owned()),
    );
    if let Some(slot) = min_context_slot {
        options.insert("minContextSlot".to_owned(), Value::from(slot));
    }
    Value::Object(options)
}

fn parse_envelope(value: Value, expected_id: u64) -> Result<Value, RpcError> {
    let object = value.as_object().ok_or(RpcError::InvalidResponseShape)?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(RpcError::InvalidJsonRpcVersion);
    }
    if object.get("id").and_then(Value::as_u64) != Some(expected_id) {
        return Err(RpcError::MismatchedResponseId);
    }

    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    if has_result == has_error {
        return Err(RpcError::InvalidResponseShape);
    }
    if has_error {
        let error = object
            .get("error")
            .and_then(Value::as_object)
            .ok_or(RpcError::InvalidResponseShape)?;
        if error.get("code").and_then(Value::as_i64).is_none()
            || error.get("message").and_then(Value::as_str).is_none()
        {
            return Err(RpcError::InvalidResponseShape);
        }
        return Err(RpcError::RemoteError);
    }
    object
        .get("result")
        .cloned()
        .ok_or(RpcError::InvalidResponseShape)
}

fn parse_context_result(
    result: &Value,
    min_context_slot: Option<u64>,
) -> Result<(u64, &Value), RpcError> {
    let result = result.as_object().ok_or(RpcError::InvalidResult)?;
    let context = result
        .get("context")
        .and_then(Value::as_object)
        .ok_or(RpcError::InvalidResult)?;
    let slot = context
        .get("slot")
        .and_then(Value::as_u64)
        .ok_or(RpcError::InvalidResult)?;
    if min_context_slot.is_some_and(|minimum| slot < minimum) {
        return Err(RpcError::StaleContext);
    }
    let value = result.get("value").ok_or(RpcError::InvalidResult)?;
    Ok((slot, value))
}

fn parse_account(value: &Value, limits: RpcLimits) -> Result<(Account, usize), RpcError> {
    let account = value.as_object().ok_or(RpcError::InvalidAccount)?;
    let lamports = account
        .get("lamports")
        .and_then(Value::as_u64)
        .ok_or(RpcError::InvalidAccount)?;
    let executable = account
        .get("executable")
        .and_then(Value::as_bool)
        .ok_or(RpcError::InvalidAccount)?;
    let owner = account
        .get("owner")
        .and_then(Value::as_str)
        .ok_or(RpcError::InvalidOwner)?
        .parse()
        .map_err(|_| RpcError::InvalidOwner)?;

    let encoded_data = account
        .get("data")
        .and_then(Value::as_array)
        .filter(|data| data.len() == 2)
        .ok_or(RpcError::InvalidDataEncoding)?;
    let encoded = encoded_data[0]
        .as_str()
        .ok_or(RpcError::InvalidDataEncoding)?;
    if encoded_data[1].as_str() != Some("base64") {
        return Err(RpcError::InvalidDataEncoding);
    }

    let encoded_groups = limits.max_account_bytes.div_ceil(3);
    let max_encoded_len = encoded_groups.saturating_mul(4);
    if encoded.len() > max_encoded_len {
        return Err(RpcError::AccountTooLarge);
    }
    let data = STANDARD
        .decode(encoded)
        .map_err(|_| RpcError::InvalidBase64)?;
    if data.len() > limits.max_account_bytes {
        return Err(RpcError::AccountTooLarge);
    }
    let data_len = data.len();
    Ok((
        Account {
            lamports,
            owner,
            executable,
            data,
        },
        data_len,
    ))
}
