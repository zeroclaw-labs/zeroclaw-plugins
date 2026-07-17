use std::fmt;

use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Serialize};
use url::Url;

const LEGACY_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskError {
    InvalidMint,
    InvalidRpcUrl,
    MalformedRpcResponse,
    JsonRpcError,
    NullAccount,
    ZeroSupply,
    InvalidLargestAccount,
    InconsistentSupply,
    InconsistentSlots,
    UnsupportedTokenProgram,
}

impl fmt::Display for RiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMint => f.write_str("mint must be a 32-byte base58 public key"),
            Self::InvalidRpcUrl => {
                f.write_str("RPC URL must be HTTPS without credentials, query, or fragment")
            }
            Self::MalformedRpcResponse => f.write_str("RPC response is malformed or incomplete"),
            Self::JsonRpcError => f.write_str("RPC response contains an error"),
            Self::NullAccount => f.write_str("mint account does not exist"),
            Self::ZeroSupply => f.write_str("mint supply must be greater than zero"),
            Self::InvalidLargestAccount => f.write_str("largest account amount is invalid"),
            Self::InconsistentSupply => f.write_str("largest account amounts exceed mint supply"),
            Self::InconsistentSlots => f.write_str("RPC evidence slots do not match"),
            Self::UnsupportedTokenProgram => {
                f.write_str("mint owner is not a supported token program")
            }
        }
    }
}

impl std::error::Error for RiskError {}

pub fn validate_mint(mint: &str) -> Result<(), RiskError> {
    let decoded = bs58::decode(mint)
        .into_vec()
        .map_err(|_| RiskError::InvalidMint)?;
    if decoded.len() != 32 {
        return Err(RiskError::InvalidMint);
    }
    Ok(())
}

pub fn validate_rpc_url(raw: &str) -> Result<String, RiskError> {
    let url = Url::parse(raw).map_err(|_| RiskError::InvalidRpcUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RiskError::InvalidRpcUrl);
    }
    Ok(url.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Red,
    Amber,
    Green,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reason {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    pub token_program: String,
    pub supply: String,
    pub decimals: u8,
    pub mint_authority_revoked: bool,
    pub freeze_authority_revoked: bool,
    pub top_account_bps: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Slots {
    pub account: u64,
    pub largest_accounts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskReport {
    pub verdict: Verdict,
    pub reasons: Vec<Reason>,
    pub evidence: Evidence,
    pub limitations: Vec<String>,
    pub slots: Slots,
}

pub fn assess(mint: &str, account_json: &str, largest_json: &str) -> Result<RiskReport, RiskError> {
    validate_mint(mint)?;

    let account: AccountResult = decode_rpc(account_json)?;
    let largest: LargestResult = decode_rpc(largest_json)?;
    let account_value = account.value.ok_or(RiskError::NullAccount)?;

    if account.context.slot != largest.context.slot {
        return Err(RiskError::InconsistentSlots);
    }

    let token_program = token_program_name(&account_value.owner)?;
    let info = account_value.data.parsed.info;
    let supply = parse_amount(&info.supply)?;
    if supply == 0 {
        return Err(RiskError::ZeroSupply);
    }

    let amounts = largest
        .value
        .iter()
        .map(|account| parse_amount(&account.amount))
        .collect::<Result<Vec<_>, _>>()?;
    let top_amount = amounts
        .iter()
        .copied()
        .max()
        .ok_or(RiskError::InvalidLargestAccount)?;
    let total_largest = amounts.into_iter().try_fold(0_u128, |total, amount| {
        total
            .checked_add(amount)
            .ok_or(RiskError::InconsistentSupply)
    })?;
    if top_amount > supply || total_largest > supply {
        return Err(RiskError::InconsistentSupply);
    }
    let top_account_bps = top_amount
        .checked_mul(10_000)
        .ok_or(RiskError::InvalidLargestAccount)?
        / supply;

    Ok(RiskReport {
        verdict: Verdict::Green,
        reasons: Vec::new(),
        evidence: Evidence {
            token_program: token_program.to_owned(),
            supply: info.supply,
            decimals: info.decimals,
            mint_authority_revoked: authority_is_revoked(info.mint_authority)?,
            freeze_authority_revoked: authority_is_revoked(info.freeze_authority)?,
            top_account_bps: Some(
                u16::try_from(top_account_bps).map_err(|_| RiskError::InvalidLargestAccount)?,
            ),
        },
        limitations: vec![
            "LP_STATUS_NOT_CHECKED".to_owned(),
            "TOP_ACCOUNTS_ARE_NOT_UNIQUE_HOLDERS".to_owned(),
        ],
        slots: Slots {
            account: account.context.slot,
            largest_accounts: largest.context.slot,
        },
    })
}

fn decode_rpc<T: DeserializeOwned>(body: &str) -> Result<T, RiskError> {
    let response: RpcResponse<T> =
        serde_json::from_str(body).map_err(|_| RiskError::MalformedRpcResponse)?;
    if response.jsonrpc != "2.0" {
        return Err(RiskError::MalformedRpcResponse);
    }
    if response.error.is_some() {
        return Err(RiskError::JsonRpcError);
    }
    response.result.ok_or(RiskError::MalformedRpcResponse)
}

fn token_program_name(owner: &str) -> Result<&'static str, RiskError> {
    match owner {
        LEGACY_TOKEN_PROGRAM => Ok("spl-token"),
        TOKEN_2022_PROGRAM => Ok("token-2022"),
        _ => Err(RiskError::UnsupportedTokenProgram),
    }
}

fn parse_amount(raw: &str) -> Result<u128, RiskError> {
    raw.parse().map_err(|_| RiskError::InvalidLargestAccount)
}

fn authority_is_revoked(authority: Authority) -> Result<bool, RiskError> {
    match authority {
        Authority::Missing => Err(RiskError::MalformedRpcResponse),
        Authority::Revoked => Ok(true),
        Authority::Active => Ok(false),
    }
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    jsonrpc: String,
    #[serde(default)]
    error: Option<IgnoredAny>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct AccountResult {
    context: RpcContext,
    value: Option<AccountValue>,
}

#[derive(Deserialize)]
struct LargestResult {
    context: RpcContext,
    value: Vec<LargestAccount>,
}

#[derive(Deserialize)]
struct RpcContext {
    slot: u64,
}

#[derive(Deserialize)]
struct AccountValue {
    owner: String,
    data: ParsedData,
}

#[derive(Deserialize)]
struct ParsedData {
    parsed: ParsedAccount,
}

#[derive(Deserialize)]
struct ParsedAccount {
    info: MintInfo,
}

#[derive(Deserialize)]
struct MintInfo {
    #[serde(default, rename = "mintAuthority")]
    mint_authority: Authority,
    supply: String,
    decimals: u8,
    #[serde(default, rename = "freezeAuthority")]
    freeze_authority: Authority,
}

#[derive(Deserialize)]
struct LargestAccount {
    amount: String,
}

#[derive(Default)]
enum Authority {
    #[default]
    Missing,
    Revoked,
    Active,
}

impl<'de> Deserialize<'de> for Authority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer).map(|authority| match authority {
            Some(_) => Self::Active,
            None => Self::Revoked,
        })
    }
}
