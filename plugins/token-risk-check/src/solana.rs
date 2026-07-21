use std::collections::BTreeSet;
use std::fmt;

use base64::Engine;
use serde_json::Value;

pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const LEGACY_MINT_LEN: usize = 82;
pub const TOKEN_ACCOUNT_BASE_LEN: usize = 165;
pub const TOKEN_2022_TLV_START: usize = 166;
pub const MAX_ACCOUNT_DATA_BYTES: usize = 4096;
pub const MAX_LARGEST_ACCOUNTS: usize = 20;
pub const MAX_TLV_ENTRIES: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    InvalidMint,
    InvalidProgram,
    InvalidLength,
    InvalidOption,
    Uninitialized,
    InvalidAccountType,
    InvalidPadding,
    InvalidTlv,
    Duplicate,
    OutOfOrder,
    TooMany,
    InvalidRpc,
    RpcError,
    MissingValue,
    InvalidAmount,
    BoundExceeded,
    Mismatch,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::InvalidMint => "invalid mint",
                Self::InvalidProgram => "invalid token program",
                Self::InvalidLength => "invalid account length",
                Self::InvalidOption => "non-canonical option",
                Self::Uninitialized => "uninitialized account",
                Self::InvalidAccountType => "invalid account type",
                Self::InvalidPadding => "invalid account padding",
                Self::InvalidTlv => "invalid token-2022 extension data",
                Self::Duplicate => "duplicate account or extension",
                Self::OutOfOrder => "extension records are out of order",
                Self::TooMany => "too many records",
                Self::InvalidRpc => "invalid RPC response",
                Self::RpcError => "RPC returned an error",
                Self::MissingValue => "RPC value is unavailable",
                Self::InvalidAmount => "invalid token amount",
                Self::BoundExceeded => "response bound exceeded",
                Self::Mismatch => "account evidence mismatch",
            }
        )
    }
}

impl std::error::Error for ParseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferFeeSchedule {
    pub epoch: u64,
    pub maximum_fee: u64,
    pub basis_points: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferFeeConfig {
    pub config_authority: Option<[u8; 32]>,
    pub withdraw_authority: Option<[u8; 32]>,
    pub withheld_amount: u64,
    pub older: TransferFeeSchedule,
    pub newer: TransferFeeSchedule,
}

impl TransferFeeConfig {
    pub fn active_at(&self, epoch: u64) -> &TransferFeeSchedule {
        if epoch >= self.newer.epoch {
            &self.newer
        } else {
            &self.older
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct MintExtensions {
    pub transfer_fee: Option<TransferFeeConfig>,
    pub transfer_hook_present: bool,
    pub transfer_hook_authority: Option<[u8; 32]>,
    pub transfer_hook_program: Option<[u8; 32]>,
    pub permanent_delegate_present: bool,
    pub permanent_delegate: Option<[u8; 32]>,
    pub unknown_types: Vec<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintAccount {
    pub program: &'static str,
    pub mint_authority: Option<[u8; 32]>,
    pub supply: u64,
    pub decimals: u8,
    pub freeze_authority: Option<[u8; 32]>,
    pub extensions: MintExtensions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenAccount {
    pub address: [u8; 32],
    pub owner: [u8; 32],
    pub amount: u64,
    pub frozen: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawAccount {
    pub owner_program: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextValue<T> {
    pub slot: u64,
    pub value: T,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LargestAccount {
    pub address: String,
    pub amount: u64,
}

pub fn validate_mint(value: &str) -> Result<[u8; 32], ParseError> {
    if !(32..=44).contains(&value.len()) || value.chars().any(char::is_whitespace) {
        return Err(ParseError::InvalidMint);
    }
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| ParseError::InvalidMint)?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| ParseError::InvalidMint)?;
    if bs58::encode(bytes).into_string() != value {
        return Err(ParseError::InvalidMint);
    }
    Ok(bytes)
}

pub fn pubkey_string(bytes: &[u8; 32]) -> String {
    bs58::encode(bytes).into_string()
}

fn read_u16(data: &[u8]) -> Result<u16, ParseError> {
    Ok(u16::from_le_bytes(
        data.try_into().map_err(|_| ParseError::InvalidLength)?,
    ))
}

fn read_u32(data: &[u8]) -> Result<u32, ParseError> {
    Ok(u32::from_le_bytes(
        data.try_into().map_err(|_| ParseError::InvalidLength)?,
    ))
}

fn read_u64(data: &[u8]) -> Result<u64, ParseError> {
    Ok(u64::from_le_bytes(
        data.try_into().map_err(|_| ParseError::InvalidLength)?,
    ))
}

fn array32(data: &[u8]) -> Result<[u8; 32], ParseError> {
    data.try_into().map_err(|_| ParseError::InvalidLength)
}

fn coption(data: &[u8]) -> Result<Option<[u8; 32]>, ParseError> {
    if data.len() != 36 {
        return Err(ParseError::InvalidLength);
    }
    match read_u32(&data[..4])? {
        0 => Ok(None),
        1 => Ok(Some(array32(&data[4..36])?)),
        _ => Err(ParseError::InvalidOption),
    }
}

fn optional_nonzero(data: &[u8]) -> Result<Option<[u8; 32]>, ParseError> {
    let key = array32(data)?;
    Ok((key != [0; 32]).then_some(key))
}

pub fn parse_mint_account(program: &str, data: &[u8]) -> Result<MintAccount, ParseError> {
    let program = match program {
        TOKEN_PROGRAM_ID => TOKEN_PROGRAM_ID,
        TOKEN_2022_PROGRAM_ID => TOKEN_2022_PROGRAM_ID,
        _ => return Err(ParseError::InvalidProgram),
    };
    if data.len() > MAX_ACCOUNT_DATA_BYTES {
        return Err(ParseError::BoundExceeded);
    }
    if data.len() != LEGACY_MINT_LEN
        && !(program == TOKEN_2022_PROGRAM_ID && data.len() >= TOKEN_2022_TLV_START)
    {
        return Err(ParseError::InvalidLength);
    }
    if data[45] != 1 {
        return Err(ParseError::Uninitialized);
    }
    let mut mint = MintAccount {
        program,
        mint_authority: coption(&data[0..36])?,
        supply: read_u64(&data[36..44])?,
        decimals: data[44],
        freeze_authority: coption(&data[46..82])?,
        extensions: MintExtensions::default(),
    };
    if data.len() == LEGACY_MINT_LEN {
        return Ok(mint);
    }
    if data[82..165].iter().any(|b| *b != 0) {
        return Err(ParseError::InvalidPadding);
    }
    if data[165] != 1 {
        return Err(ParseError::InvalidAccountType);
    }
    mint.extensions = parse_tlv(&data[TOKEN_2022_TLV_START..])?;
    Ok(mint)
}

fn parse_tlv(data: &[u8]) -> Result<MintExtensions, ParseError> {
    let mut result = MintExtensions::default();
    let mut seen = BTreeSet::new();
    let mut offset = 0;
    let mut previous = 0_u16;
    while offset < data.len() {
        if data[offset..].iter().all(|b| *b == 0) {
            break;
        }
        if data.len() - offset < 4 {
            return Err(ParseError::InvalidTlv);
        }
        let kind = read_u16(&data[offset..offset + 2])?;
        let len = read_u16(&data[offset + 2..offset + 4])? as usize;
        offset += 4;
        if kind == 0 || data.len() - offset < len {
            return Err(ParseError::InvalidTlv);
        }
        if !seen.insert(kind) {
            return Err(ParseError::Duplicate);
        }
        if kind <= previous {
            return Err(ParseError::OutOfOrder);
        }
        if seen.len() > MAX_TLV_ENTRIES {
            return Err(ParseError::TooMany);
        }
        previous = kind;
        let body = &data[offset..offset + len];
        match kind {
            1 => result.transfer_fee = Some(parse_transfer_fee(body)?),
            12 => {
                if len != 32 {
                    return Err(ParseError::InvalidTlv);
                }
                result.permanent_delegate_present = true;
                result.permanent_delegate = optional_nonzero(body)?;
            }
            14 => {
                if len != 64 {
                    return Err(ParseError::InvalidTlv);
                }
                result.transfer_hook_present = true;
                result.transfer_hook_authority = optional_nonzero(&body[..32])?;
                result.transfer_hook_program = optional_nonzero(&body[32..])?;
            }
            _ => result.unknown_types.push(kind),
        }
        offset += len;
    }
    Ok(result)
}

fn parse_transfer_fee(data: &[u8]) -> Result<TransferFeeConfig, ParseError> {
    if data.len() != 108 {
        return Err(ParseError::InvalidTlv);
    }
    let schedule = |offset: usize| -> Result<TransferFeeSchedule, ParseError> {
        let basis_points = read_u16(&data[offset + 16..offset + 18])?;
        if basis_points > 10_000 {
            return Err(ParseError::InvalidAmount);
        }
        Ok(TransferFeeSchedule {
            epoch: read_u64(&data[offset..offset + 8])?,
            maximum_fee: read_u64(&data[offset + 8..offset + 16])?,
            basis_points,
        })
    };
    let older = schedule(72)?;
    let newer = schedule(90)?;
    if newer.epoch < older.epoch {
        return Err(ParseError::InvalidTlv);
    }
    Ok(TransferFeeConfig {
        config_authority: optional_nonzero(&data[..32])?,
        withdraw_authority: optional_nonzero(&data[32..64])?,
        withheld_amount: read_u64(&data[64..72])?,
        older,
        newer,
    })
}

pub fn parse_token_account(
    address: &str,
    expected_program: &str,
    expected_mint: &[u8; 32],
    owner_program: &str,
    data: &[u8],
) -> Result<TokenAccount, ParseError> {
    if owner_program != expected_program {
        return Err(ParseError::InvalidProgram);
    }
    if data.len() < TOKEN_ACCOUNT_BASE_LEN || data.len() > MAX_ACCOUNT_DATA_BYTES {
        return Err(ParseError::InvalidLength);
    }
    if expected_program == TOKEN_PROGRAM_ID && data.len() != TOKEN_ACCOUNT_BASE_LEN {
        return Err(ParseError::InvalidLength);
    }
    if expected_program == TOKEN_2022_PROGRAM_ID
        && data.len() > TOKEN_ACCOUNT_BASE_LEN
        && data.get(TOKEN_ACCOUNT_BASE_LEN) != Some(&2)
    {
        return Err(ParseError::InvalidAccountType);
    }
    if array32(&data[..32])? != *expected_mint {
        return Err(ParseError::Mismatch);
    }
    let state = data[108];
    if state != 1 && state != 2 {
        return Err(if state == 0 {
            ParseError::Uninitialized
        } else {
            ParseError::Mismatch
        });
    }
    Ok(TokenAccount {
        address: validate_mint(address)?,
        owner: array32(&data[32..64])?,
        amount: read_u64(&data[64..72])?,
        frozen: state == 2,
    })
}

fn rpc_envelope(body: &str, id: u64) -> Result<Value, ParseError> {
    let value: Value = serde_json::from_str(body).map_err(|_| ParseError::InvalidRpc)?;
    let object = value.as_object().ok_or(ParseError::InvalidRpc)?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || object.get("id").and_then(Value::as_u64) != Some(id)
    {
        return Err(ParseError::InvalidRpc);
    }
    if object.contains_key("error") {
        return Err(ParseError::RpcError);
    }
    object.get("result").cloned().ok_or(ParseError::InvalidRpc)
}

fn context_slot(result: &Value) -> Result<u64, ParseError> {
    result
        .get("context")
        .and_then(|v| v.get("slot"))
        .and_then(Value::as_u64)
        .ok_or(ParseError::InvalidRpc)
}

fn raw_account(value: &Value) -> Result<RawAccount, ParseError> {
    let owner_program = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or(ParseError::InvalidRpc)?;
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or(ParseError::InvalidRpc)?;
    if data.len() != 2 || data[1].as_str() != Some("base64") {
        return Err(ParseError::InvalidRpc);
    }
    let encoded = data[0].as_str().ok_or(ParseError::InvalidRpc)?;
    if encoded.len() > MAX_ACCOUNT_DATA_BYTES * 2 {
        return Err(ParseError::BoundExceeded);
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| ParseError::InvalidRpc)?;
    if decoded.len() > MAX_ACCOUNT_DATA_BYTES {
        return Err(ParseError::BoundExceeded);
    }
    Ok(RawAccount {
        owner_program: owner_program.to_string(),
        data: decoded,
    })
}

pub fn parse_account_info_response(
    body: &str,
    id: u64,
) -> Result<ContextValue<RawAccount>, ParseError> {
    let result = rpc_envelope(body, id)?;
    let slot = context_slot(&result)?;
    let value = result.get("value").ok_or(ParseError::InvalidRpc)?;
    if value.is_null() {
        return Err(ParseError::MissingValue);
    }
    Ok(ContextValue {
        slot,
        value: raw_account(value)?,
    })
}

pub fn parse_largest_response(
    body: &str,
    id: u64,
) -> Result<ContextValue<Vec<LargestAccount>>, ParseError> {
    let result = rpc_envelope(body, id)?;
    let slot = context_slot(&result)?;
    let rows = result
        .get("value")
        .and_then(Value::as_array)
        .ok_or(ParseError::InvalidRpc)?;
    if rows.len() > MAX_LARGEST_ACCOUNTS {
        return Err(ParseError::TooMany);
    }
    let mut addresses = BTreeSet::new();
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let address = row
            .get("address")
            .and_then(Value::as_str)
            .ok_or(ParseError::InvalidRpc)?;
        validate_mint(address)?;
        if !addresses.insert(address.to_string()) {
            return Err(ParseError::Duplicate);
        }
        let amount = row
            .get("amount")
            .and_then(Value::as_str)
            .ok_or(ParseError::InvalidRpc)?
            .parse::<u64>()
            .map_err(|_| ParseError::InvalidAmount)?;
        parsed.push(LargestAccount {
            address: address.to_string(),
            amount,
        });
    }
    Ok(ContextValue {
        slot,
        value: parsed,
    })
}

pub fn parse_multiple_accounts_response(
    body: &str,
    id: u64,
    expected: usize,
) -> Result<ContextValue<Vec<RawAccount>>, ParseError> {
    let result = rpc_envelope(body, id)?;
    let slot = context_slot(&result)?;
    let rows = result
        .get("value")
        .and_then(Value::as_array)
        .ok_or(ParseError::InvalidRpc)?;
    if rows.len() != expected || rows.len() > MAX_LARGEST_ACCOUNTS {
        return Err(ParseError::Mismatch);
    }
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        if row.is_null() {
            return Err(ParseError::MissingValue);
        }
        parsed.push(raw_account(row)?);
    }
    Ok(ContextValue {
        slot,
        value: parsed,
    })
}

pub fn parse_epoch_response(body: &str, id: u64) -> Result<u64, ParseError> {
    rpc_envelope(body, id)?
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or(ParseError::InvalidRpc)
}
