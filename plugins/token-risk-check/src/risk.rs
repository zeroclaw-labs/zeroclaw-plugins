use std::fmt;

use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Serialize};
use url::Url;

const LEGACY_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const CONCENTRATION_THRESHOLD_BPS: u128 = 5_000;
const MAX_FORWARD_SLOT_SKEW: u64 = 32;
const MAX_REASONS: usize = 12;
const MAX_ERROR_TEXT_CHARS: usize = 160;
const MAX_EXTENSION_NAME_CHARS: usize = 32;
const MAX_SERIALIZED_REPORT_BYTES: usize = 8 * 1024;

pub const ACCOUNT_REQUEST_ID: u64 = 1;
pub const LARGEST_ACCOUNTS_REQUEST_ID: u64 = 2;

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
    ResponseIdMismatch,
    InvalidAuthority,
    UnsupportedTokenProgram,
    InvalidExecuteArgs,
}

impl fmt::Display for RiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMint => f.write_str("mint must be a 32-byte base58 public key"),
            Self::InvalidRpcUrl => {
                f.write_str(
                    "RPC URL must be HTTPS without credentials or fragment; only one non-empty api-key query is allowed",
                )
            }
            Self::MalformedRpcResponse => f.write_str("RPC response is malformed or incomplete"),
            Self::JsonRpcError => f.write_str("RPC response contains an error"),
            Self::NullAccount => f.write_str("mint account does not exist"),
            Self::ZeroSupply => f.write_str("mint supply must be greater than zero"),
            Self::InvalidLargestAccount => f.write_str("largest account amount is invalid"),
            Self::InconsistentSupply => f.write_str("largest account amounts exceed mint supply"),
            Self::InconsistentSlots => {
                f.write_str("RPC evidence slots are reversed or too far apart")
            }
            Self::ResponseIdMismatch => f.write_str("RPC response ID does not match its request"),
            Self::InvalidAuthority => f.write_str("authority must be a 32-byte base58 public key"),
            Self::UnsupportedTokenProgram => {
                f.write_str("mint owner is not a supported token program")
            }
            Self::InvalidExecuteArgs => f.write_str("tool arguments are invalid"),
        }
    }
}

impl std::error::Error for RiskError {}

impl RiskError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidMint => "INVALID_MINT",
            Self::InvalidRpcUrl => "INVALID_RPC_URL",
            Self::MalformedRpcResponse => "MALFORMED_RPC_RESPONSE",
            Self::JsonRpcError => "JSON_RPC_ERROR",
            Self::NullAccount => "NULL_ACCOUNT",
            Self::ZeroSupply => "ZERO_SUPPLY",
            Self::InvalidLargestAccount => "INVALID_LARGEST_ACCOUNT",
            Self::InconsistentSupply => "INCONSISTENT_SUPPLY",
            Self::InconsistentSlots => "INCONSISTENT_SLOTS",
            Self::ResponseIdMismatch => "RESPONSE_ID_MISMATCH",
            Self::InvalidAuthority => "INVALID_AUTHORITY",
            Self::UnsupportedTokenProgram => "UNSUPPORTED_TOKEN_PROGRAM",
            Self::InvalidExecuteArgs => "INVALID_EXECUTE_ARGS",
        }
    }
}

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
    let query_is_allowed = match url.query() {
        None => true,
        Some(_) => {
            let mut pairs = url.query_pairs();
            matches!(pairs.next(), Some((key, value))
                if key == "api-key"
                    && !value.is_empty()
                    && value.len() <= 128
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
                && pairs.next().is_none()
        }
    };
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !query_is_allowed
        || url.fragment().is_some()
    {
        return Err(RiskError::InvalidRpcUrl);
    }
    Ok(url.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteArgs {
    pub mint: String,
    #[serde(rename = "__config")]
    pub config: ExecuteConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteConfig {
    pub rpc_url: String,
}

pub fn parse_execute_args(raw: &str) -> Result<ExecuteArgs, RiskError> {
    let mut args: ExecuteArgs =
        serde_json::from_str(raw).map_err(|_| RiskError::InvalidExecuteArgs)?;
    validate_mint(&args.mint)?;
    args.config.rpc_url = validate_rpc_url(&args.config.rpc_url)?;
    Ok(args)
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

pub fn unknown_report(code: &str, message: &str) -> RiskReport {
    RiskReport {
        verdict: Verdict::Unknown,
        reasons: vec![Reason {
            code: truncate_chars(code, MAX_ERROR_TEXT_CHARS),
            message: truncate_chars(message, MAX_ERROR_TEXT_CHARS),
        }],
        evidence: Evidence {
            token_program: "unknown".to_owned(),
            supply: "unknown".to_owned(),
            decimals: 0,
            mint_authority_revoked: false,
            freeze_authority_revoked: false,
            top_account_bps: None,
        },
        limitations: vec!["EVIDENCE_UNAVAILABLE".to_owned()],
        slots: Slots {
            account: 0,
            largest_accounts: 0,
        },
    }
}

pub fn serialize_report(report: &RiskReport) -> String {
    if report.reasons.len() > MAX_REASONS {
        return serialize_minimal_unknown();
    }

    match serde_json::to_string(report) {
        Ok(output) if output.len() <= MAX_SERIALIZED_REPORT_BYTES => output,
        Ok(_) | Err(_) => serialize_minimal_unknown(),
    }
}

fn serialize_minimal_unknown() -> String {
    let fallback = unknown_report("OUTPUT_TOO_LARGE", "Risk report exceeded output size limit");
    serde_json::to_string(&fallback).unwrap_or_else(|_| {
        "{\"verdict\":\"unknown\",\"reasons\":[],\"evidence\":{\"token_program\":\"unknown\",\"supply\":\"unknown\",\"decimals\":0,\"mint_authority_revoked\":false,\"freeze_authority_revoked\":false,\"top_account_bps\":null},\"limitations\":[\"EVIDENCE_UNAVAILABLE\"],\"slots\":{\"account\":0,\"largest_accounts\":0}}".to_owned()
    })
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

pub fn assess(mint: &str, account_json: &str, largest_json: &str) -> Result<RiskReport, RiskError> {
    validate_mint(mint)?;

    let account: AccountResult = decode_rpc(account_json, ACCOUNT_REQUEST_ID)?;
    let largest: LargestResult = decode_rpc(largest_json, LARGEST_ACCOUNTS_REQUEST_ID)?;
    let account_value = account.value.ok_or(RiskError::NullAccount)?;

    let slot_skew = largest
        .context
        .slot
        .checked_sub(account.context.slot)
        .filter(|skew| *skew <= MAX_FORWARD_SLOT_SKEW)
        .ok_or(RiskError::InconsistentSlots)?;

    let token_program = token_program_name(&account_value.owner)?;
    let parsed = account_value.data.parsed;
    if parsed.account_type != "mint" {
        return Err(RiskError::MalformedRpcResponse);
    }
    let info = parsed.info;
    if !info.is_initialized {
        return Err(RiskError::MalformedRpcResponse);
    }
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
    if top_amount == 0 {
        return Err(RiskError::InvalidLargestAccount);
    }
    if top_amount > supply || total_largest > supply {
        return Err(RiskError::InconsistentSupply);
    }
    let top_account_bps = top_amount
        .checked_mul(10_000)
        .ok_or(RiskError::InvalidLargestAccount)?
        / supply;
    let mint_authority_revoked = authority_is_revoked(&info.mint_authority)?;
    let freeze_authority_revoked = authority_is_revoked(&info.freeze_authority)?;

    let mut rules = Vec::new();
    if slot_skew > 0 {
        rules.push(rule(
            RuleSeverity::Amber,
            "EVIDENCE_SLOT_SKEW",
            "RPC evidence is recent but not from one atomic slot",
        ));
    }
    if !mint_authority_revoked {
        rules.push(rule(
            RuleSeverity::Amber,
            "MINT_AUTHORITY_ACTIVE",
            "Mint authority is active",
        ));
    }
    if !freeze_authority_revoked {
        rules.push(rule(
            RuleSeverity::Amber,
            "FREEZE_AUTHORITY_ACTIVE",
            "Freeze authority is active",
        ));
    }
    if top_account_bps >= CONCENTRATION_THRESHOLD_BPS {
        rules.push(rule(
            RuleSeverity::Amber,
            "TOP_ACCOUNT_CONCENTRATED",
            "Largest token account holds at least 50% of supply",
        ));
    }
    if token_program == "token-2022" {
        let ExtensionsEvidence::Present(extensions) = &info.extensions else {
            return Err(RiskError::MalformedRpcResponse);
        };
        rules.extend(token_2022_extension_rules(extensions)?);
    }

    let (verdict, reasons, reasons_truncated) = finalize_rules(rules);
    let mut limitations = vec![
        "LP_STATUS_NOT_CHECKED".to_owned(),
        "TOP_ACCOUNTS_ARE_NOT_UNIQUE_HOLDERS".to_owned(),
    ];
    if slot_skew > 0 {
        limitations.push("EVIDENCE_SLOT_SKEW".to_owned());
    }
    if reasons_truncated {
        limitations.push("REASONS_TRUNCATED".to_owned());
    }

    Ok(RiskReport {
        verdict,
        reasons,
        evidence: Evidence {
            token_program: token_program.to_owned(),
            supply: info.supply,
            decimals: info.decimals,
            mint_authority_revoked,
            freeze_authority_revoked,
            top_account_bps: Some(
                u16::try_from(top_account_bps).map_err(|_| RiskError::InvalidLargestAccount)?,
            ),
        },
        limitations,
        slots: Slots {
            account: account.context.slot,
            largest_accounts: largest.context.slot,
        },
    })
}

fn decode_rpc<T: DeserializeOwned>(body: &str, expected_id: u64) -> Result<T, RiskError> {
    let response: RpcResponse<T> =
        serde_json::from_str(body).map_err(|_| RiskError::MalformedRpcResponse)?;
    if response.jsonrpc != "2.0" {
        return Err(RiskError::MalformedRpcResponse);
    }
    if response.error_present {
        return Err(RiskError::JsonRpcError);
    }
    if response.id != Some(expected_id) {
        return Err(RiskError::ResponseIdMismatch);
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

fn authority_is_revoked(authority: &Authority) -> Result<bool, RiskError> {
    match authority {
        Authority::Missing => Err(RiskError::MalformedRpcResponse),
        Authority::Revoked => Ok(true),
        Authority::Active(authority) => {
            validate_mint(authority).map_err(|_| RiskError::InvalidAuthority)?;
            Ok(false)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RuleSeverity {
    Red,
    Amber,
}

impl RuleSeverity {
    fn verdict(self) -> Verdict {
        match self {
            Self::Red => Verdict::Red,
            Self::Amber => Verdict::Amber,
        }
    }
}

struct Rule {
    severity: RuleSeverity,
    reason: Reason,
}

fn rule(severity: RuleSeverity, code: &str, message: &str) -> Rule {
    Rule {
        severity,
        reason: Reason {
            code: code.to_owned(),
            message: message.to_owned(),
        },
    }
}

fn token_2022_extension_rules(extensions: &[TokenExtension]) -> Result<Vec<Rule>, RiskError> {
    extensions
        .iter()
        .map(|extension| match extension.extension.as_str() {
            "transferFeeConfig" => Ok(Some(rule(
                RuleSeverity::Amber,
                "TRANSFER_FEE",
                "Token-2022 transfer fee is configured",
            ))),
            "transferHook" => Ok(Some(rule(
                RuleSeverity::Red,
                "TRANSFER_HOOK",
                "Token-2022 transfer hook is configured",
            ))),
            "permanentDelegate" => Ok(Some(rule(
                RuleSeverity::Red,
                "PERMANENT_DELEGATE",
                "Token-2022 permanent delegate is configured",
            ))),
            "defaultAccountState" => {
                if extension.default_state_is_frozen()? {
                    Ok(Some(rule(
                        RuleSeverity::Amber,
                        "DEFAULT_FROZEN",
                        "Token-2022 default account state is frozen",
                    )))
                } else {
                    Ok(None)
                }
            }
            "confidentialTransferMint" => Ok(Some(rule(
                RuleSeverity::Red,
                "CONFIDENTIAL_TRANSFER",
                "Token-2022 confidential transfer is configured",
            ))),
            "nonTransferable" => Ok(Some(rule(
                RuleSeverity::Red,
                "NON_TRANSFERABLE",
                "Token-2022 token is non-transferable",
            ))),
            _ => Ok(Some(Rule {
                severity: RuleSeverity::Amber,
                reason: Reason {
                    code: "UNKNOWN_EXTENSION".to_owned(),
                    message: format!(
                        "Unrecognized Token-2022 extension: {}",
                        truncate_chars(&extension.extension, MAX_EXTENSION_NAME_CHARS)
                    ),
                },
            })),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|rules| rules.into_iter().flatten().collect())
}

fn finalize_rules(mut rules: Vec<Rule>) -> (Verdict, Vec<Reason>, bool) {
    rules.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.reason.code.cmp(&right.reason.code))
    });

    let verdict = rules
        .first()
        .map(|rule| rule.severity.verdict())
        .unwrap_or(Verdict::Green);
    let reasons_truncated = rules.len() > MAX_REASONS;
    rules.truncate(MAX_REASONS);
    let reasons = rules.into_iter().map(|rule| rule.reason).collect();

    (verdict, reasons, reasons_truncated)
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    jsonrpc: String,
    #[serde(default)]
    id: Option<u64>,
    #[serde(default, rename = "error", deserialize_with = "error_is_present")]
    error_present: bool,
    result: Option<T>,
}

fn error_is_present<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    IgnoredAny::deserialize(deserializer)?;
    Ok(true)
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
    #[serde(rename = "type")]
    account_type: String,
}

#[derive(Deserialize)]
struct MintInfo {
    #[serde(default, rename = "mintAuthority")]
    mint_authority: Authority,
    supply: String,
    decimals: u8,
    #[serde(rename = "isInitialized")]
    is_initialized: bool,
    #[serde(default)]
    extensions: ExtensionsEvidence,
    #[serde(default, rename = "freezeAuthority")]
    freeze_authority: Authority,
}

#[derive(Deserialize)]
struct TokenExtension {
    extension: String,
    #[serde(default)]
    state: serde_json::Value,
}

#[derive(Default)]
enum ExtensionsEvidence {
    #[default]
    Missing,
    Present(Vec<TokenExtension>),
}

impl<'de> Deserialize<'de> for ExtensionsEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Vec::<TokenExtension>::deserialize(deserializer).map(Self::Present)
    }
}

impl TokenExtension {
    fn default_state_is_frozen(&self) -> Result<bool, RiskError> {
        let state = self
            .state
            .as_object()
            .ok_or(RiskError::MalformedRpcResponse)?;
        let account_state = state
            .get("accountState")
            .and_then(serde_json::Value::as_str)
            .ok_or(RiskError::MalformedRpcResponse)?;
        match account_state {
            "frozen" => Ok(true),
            "initialized" => Ok(false),
            _ => Err(RiskError::MalformedRpcResponse),
        }
    }
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
    Active(String),
}

impl<'de> Deserialize<'de> for Authority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer).map(|authority| match authority {
            Some(authority) => Self::Active(authority),
            None => Self::Revoked,
        })
    }
}
