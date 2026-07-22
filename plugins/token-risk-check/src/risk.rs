//! Pure Solana token-risk core.
//!
//! This module contains no WASM or HTTP dependency. The component shim gathers
//! read-only JSON evidence and passes it here, while host tests exercise the
//! same parsing, owner aggregation, scoring, and compact report rendering.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;
use serde_json::Value;

pub const LEGACY_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
pub const DEFAULT_MARKET_BASE_URL: &str = "https://api.dexscreener.com/token-pairs/v1/solana";
pub const DEFAULT_SECURITY_BASE_URL: &str =
    "https://api.gopluslabs.io/api/v1/solana/token_security";
pub const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;

pub fn append_bounded_body(
    body: &mut Vec<u8>,
    chunk: &[u8],
    max_bytes: usize,
) -> Result<(), String> {
    if chunk.len() > max_bytes.saturating_sub(body.len()) {
        return Err("HTTP response exceeds the configured limit".to_string());
    }
    body.extend_from_slice(chunk);
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub struct RiskConfig {
    pub rpc_url: String,
    pub rpc_fallback_url: Option<String>,
    pub market_base_url: String,
    pub security_base_url: String,
    pub require_market_data: bool,
    pub require_lp_status: bool,
    pub min_liquidity_usd: f64,
    pub top1_amber_pct: f64,
    pub top1_red_pct: f64,
    pub top10_amber_pct: f64,
    pub top10_red_pct: f64,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            rpc_url: DEFAULT_RPC_URL.to_string(),
            rpc_fallback_url: None,
            market_base_url: DEFAULT_MARKET_BASE_URL.to_string(),
            security_base_url: DEFAULT_SECURITY_BASE_URL.to_string(),
            require_market_data: true,
            require_lp_status: true,
            min_liquidity_usd: 25_000.0,
            top1_amber_pct: 20.0,
            top1_red_pct: 50.0,
            top10_amber_pct: 50.0,
            top10_red_pct: 80.0,
        }
    }
}

impl RiskConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let mut cfg = Self::default();
        if let Some(value) = section.get("rpc_url").filter(|v| !v.trim().is_empty()) {
            cfg.rpc_url = value.trim_end_matches('/').to_string();
        }
        if let Some(value) = section
            .get("rpc_fallback_url")
            .filter(|v| !v.trim().is_empty())
        {
            cfg.rpc_fallback_url = Some(value.trim_end_matches('/').to_string());
        }
        if let Some(value) = section
            .get("market_base_url")
            .filter(|v| !v.trim().is_empty())
        {
            cfg.market_base_url = value.trim_end_matches('/').to_string();
        }
        if let Some(value) = section
            .get("security_base_url")
            .filter(|v| !v.trim().is_empty())
        {
            cfg.security_base_url = value.trim_end_matches('/').to_string();
        }
        cfg.require_market_data = parse_bool(
            section.get("require_market_data"),
            cfg.require_market_data,
            "require_market_data",
        )?;
        cfg.require_lp_status = parse_bool(
            section.get("require_lp_status"),
            cfg.require_lp_status,
            "require_lp_status",
        )?;
        cfg.min_liquidity_usd = parse_number(
            section.get("min_liquidity_usd"),
            cfg.min_liquidity_usd,
            0.0,
            1_000_000_000_000.0,
            "min_liquidity_usd",
        )?;
        cfg.top1_amber_pct = parse_number(
            section.get("top1_amber_pct"),
            cfg.top1_amber_pct,
            0.0,
            100.0,
            "top1_amber_pct",
        )?;
        cfg.top1_red_pct = parse_number(
            section.get("top1_red_pct"),
            cfg.top1_red_pct,
            0.0,
            100.0,
            "top1_red_pct",
        )?;
        cfg.top10_amber_pct = parse_number(
            section.get("top10_amber_pct"),
            cfg.top10_amber_pct,
            0.0,
            100.0,
            "top10_amber_pct",
        )?;
        cfg.top10_red_pct = parse_number(
            section.get("top10_red_pct"),
            cfg.top10_red_pct,
            0.0,
            100.0,
            "top10_red_pct",
        )?;

        if cfg.top1_amber_pct > cfg.top1_red_pct {
            return Err("top1_amber_pct must not exceed top1_red_pct".to_string());
        }
        if cfg.top10_amber_pct > cfg.top10_red_pct {
            return Err("top10_amber_pct must not exceed top10_red_pct".to_string());
        }
        validate_endpoint(&cfg.rpc_url, "rpc_url")?;
        if let Some(url) = &cfg.rpc_fallback_url {
            validate_endpoint(url, "rpc_fallback_url")?;
        }
        validate_endpoint(&cfg.market_base_url, "market_base_url")?;
        validate_endpoint(&cfg.security_base_url, "security_base_url")?;
        Ok(cfg)
    }
}

fn parse_bool(value: Option<&String>, default: bool, key: &str) -> Result<bool, String> {
    match value.map(|v| v.trim().to_ascii_lowercase()) {
        None => Ok(default),
        Some(v) if v == "true" => Ok(true),
        Some(v) if v == "false" => Ok(false),
        Some(_) => Err(format!("{key} must be true or false")),
    }
}

fn parse_number(
    value: Option<&String>,
    default: f64,
    min: f64,
    max: f64,
    key: &str,
) -> Result<f64, String> {
    let Some(raw) = value else {
        return Ok(default);
    };
    let parsed = raw
        .trim()
        .parse::<f64>()
        .map_err(|_| format!("{key} must be numeric"))?;
    if !parsed.is_finite() || parsed < min || parsed > max {
        return Err(format!("{key} is outside the safe range {min}..={max}"));
    }
    Ok(parsed)
}

/// Only operator configuration can choose an endpoint. HTTPS is required for
/// remote hosts; loopback HTTP remains available for a self-hosted Solana RPC.
pub fn validate_endpoint(url: &str, key: &str) -> Result<(), String> {
    if url.len() > 2_048 || url.chars().any(char::is_whitespace) || url.contains('\\') {
        return Err(format!("{key} is not a valid endpoint"));
    }
    let remote_https = url.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty()
            && !matches!(rest.as_bytes()[0], b'/' | b':' | b'?' | b'#' | b'@')
            && rest
                .split(['/', ':', '?', '#'])
                .next()
                .is_some_and(|host| host.chars().any(|ch| ch.is_ascii_alphanumeric()))
    });
    let loopback_http = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| {
            url.strip_prefix(prefix).is_some_and(|rest| {
                rest.is_empty() || matches!(rest.as_bytes()[0], b':' | b'/' | b'?' | b'#')
            })
        });
    if !remote_https && !loopback_http {
        return Err(format!(
            "{key} must use HTTPS, except for an explicit loopback RPC"
        ));
    }
    if url.contains('@') {
        return Err(format!("{key} must not contain URL user-info"));
    }
    Ok(())
}

/// Validate and decode a canonical Solana-sized base58 public key. This blocks
/// URLs, JSON, shell fragments, and prompt text before any network call occurs.
pub fn validate_mint(mint: &str) -> Result<(), String> {
    if !(32..=44).contains(&mint.len()) {
        return Err("mint must be a 32-byte Solana public key".to_string());
    }
    let mut bytes = [0u8; 32];
    for ch in mint.bytes() {
        let mut carry = base58_value(ch)
            .ok_or_else(|| "mint contains a non-base58 character".to_string())?
            as u32;
        for byte in bytes.iter_mut().rev() {
            let next = (*byte as u32) * 58 + carry;
            *byte = (next & 0xff) as u8;
            carry = next >> 8;
        }
        if carry != 0 {
            return Err("mint is larger than a 32-byte Solana public key".to_string());
        }
    }
    let leading_zero_bytes = mint.bytes().take_while(|ch| *ch == b'1').count();
    let first_nonzero = bytes.iter().position(|byte| *byte != 0).unwrap_or(32);
    let decoded_len = leading_zero_bytes + (32 - first_nonzero);
    if decoded_len != 32 {
        return Err("mint must decode to exactly 32 bytes".to_string());
    }
    Ok(())
}

fn base58_value(ch: u8) -> Option<u8> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    ALPHABET
        .iter()
        .position(|candidate| *candidate == ch)
        .map(|v| v as u8)
}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenProgram {
    Legacy,
    Token2022,
    Unknown(String),
}

impl TokenProgram {
    fn label(&self) -> &'static str {
        match self {
            Self::Legacy => "spl-token",
            Self::Token2022 => "token-2022",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MintEvidence {
    pub program: TokenProgram,
    pub supply: u128,
    pub decimals: u8,
    pub mint_authority: bool,
    pub freeze_authority: bool,
    pub extension_names: Vec<String>,
    pub transfer_fee_bps: Option<u64>,
    pub transfer_fee_authority: bool,
    pub transfer_hook: bool,
    pub permanent_delegate: bool,
    pub default_frozen: bool,
    pub non_transferable: bool,
    pub confidential_transfer: bool,
    pub pausable_authority: bool,
    pub paused: bool,
    pub permissioned_burn_authority: bool,
    pub scaled_ui_amount_authority: bool,
    pub unassessed_extensions: Vec<String>,
}

pub fn parse_mint_account(response: &Value) -> Result<MintEvidence, String> {
    reject_rpc_error(response)?;
    let value = response
        .pointer("/result/value")
        .ok_or_else(|| "mint account does not exist".to_string())?;
    if value.is_null() {
        return Err("mint account does not exist".to_string());
    }
    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| "mint account owner is missing".to_string())?;
    let program = match owner {
        LEGACY_TOKEN_PROGRAM => TokenProgram::Legacy,
        TOKEN_2022_PROGRAM => TokenProgram::Token2022,
        other => TokenProgram::Unknown(other.to_string()),
    };
    let info = value
        .pointer("/data/parsed/info")
        .ok_or_else(|| "RPC did not return jsonParsed mint data".to_string())?;
    let supply = string_or_u64(info.get("supply"), "mint supply")?;
    let decimals = info
        .get("decimals")
        .and_then(Value::as_u64)
        .and_then(|v| u8::try_from(v).ok())
        .ok_or_else(|| "mint decimals are missing or invalid".to_string())?;

    let mut evidence = MintEvidence {
        program,
        supply,
        decimals,
        mint_authority: authority_is_set(info.get("mintAuthority")),
        freeze_authority: authority_is_set(info.get("freezeAuthority")),
        extension_names: Vec::new(),
        transfer_fee_bps: None,
        transfer_fee_authority: false,
        transfer_hook: false,
        permanent_delegate: false,
        default_frozen: false,
        non_transferable: false,
        confidential_transfer: false,
        pausable_authority: false,
        paused: false,
        permissioned_burn_authority: false,
        scaled_ui_amount_authority: false,
        unassessed_extensions: Vec::new(),
    };

    match info.get("extensions") {
        Some(Value::Array(extensions)) => {
            for ext in extensions {
                parse_extension(ext, &mut evidence)?;
            }
        }
        Some(_) => return Err("mint extensions must be an array".to_string()),
        None if evidence.program == TokenProgram::Token2022 => {
            return Err("Token-2022 mint extensions are missing".to_string());
        }
        None => {}
    }
    evidence.extension_names.sort();
    evidence.extension_names.dedup();
    evidence.unassessed_extensions.sort();
    evidence.unassessed_extensions.dedup();
    Ok(evidence)
}

fn parse_extension(extension: &Value, evidence: &mut MintEvidence) -> Result<(), String> {
    let raw_name = extension
        .get("extension")
        .or_else(|| extension.get("type"))
        .or_else(|| extension.get("kind"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "mint extension name is missing or invalid".to_string())?;
    let normalized: String = raw_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    let safe_name = raw_name
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(*ch, '-' | '_'))
        .take(40)
        .collect::<String>();
    if normalized.is_empty() || safe_name.is_empty() {
        return Err("mint extension name is missing or invalid".to_string());
    }
    evidence.extension_names.push(safe_name.clone());
    let assessed = match normalized.as_str() {
        "transferfeeconfig" => {
            let state = required_extension_state(extension, "transfer fee")?;
            let config_authority = required_nullable_string(
                state,
                &["transferFeeConfigAuthority"],
                "transfer fee config authority",
            )?;
            let withdraw_authority = required_nullable_string(
                state,
                &["withdrawWithheldAuthority"],
                "withdraw-withheld authority",
            )?;
            evidence.transfer_fee_authority = config_authority || withdraw_authority;

            let mut fee_bps = Vec::new();
            for name in ["newerTransferFee", "olderTransferFee"] {
                if let Some(fee) = state.get(name) {
                    let fee = fee
                        .as_object()
                        .ok_or_else(|| format!("{name} is invalid"))?;
                    let value = fee
                        .get("transferFeeBasisPoints")
                        .and_then(value_to_u64)
                        .filter(|value| *value <= 10_000)
                        .ok_or_else(|| format!("{name} basis points are invalid"))?;
                    fee_bps.push(value);
                }
            }
            if let Some(value) = state.get("transferFeeBasisPoints") {
                fee_bps.push(
                    value_to_u64(value)
                        .filter(|value| *value <= 10_000)
                        .ok_or_else(|| "transfer fee basis points are invalid".to_string())?,
                );
            }
            evidence.transfer_fee_bps = fee_bps.into_iter().max();
            if evidence.transfer_fee_bps.is_none() {
                return Err("transfer fee schedule is missing".to_string());
            }
            true
        }
        "transferhook" => {
            let state = required_extension_state(extension, "transfer hook")?;
            evidence.transfer_hook = required_nullable_string(
                state,
                &["programId", "program_id"],
                "transfer hook program id",
            )?;
            true
        }
        "permanentdelegate" => {
            let state = required_extension_state(extension, "permanent delegate")?;
            evidence.permanent_delegate =
                required_nullable_string(state, &["delegate"], "permanent delegate")?;
            true
        }
        "defaultaccountstate" => {
            let state = required_extension_state(extension, "default account state")?;
            let account_state = state
                .get("accountState")
                .and_then(Value::as_str)
                .ok_or_else(|| "default account state is missing or invalid".to_string())?;
            evidence.default_frozen = if account_state.eq_ignore_ascii_case("frozen") {
                true
            } else if account_state.eq_ignore_ascii_case("initialized") {
                false
            } else {
                return Err("default account state is unsupported".to_string());
            };
            true
        }
        "nontransferable" | "nontransferableaccount" => {
            evidence.non_transferable = true;
            true
        }
        "confidentialtransfermint" | "confidentialtransferfeeconfig" => {
            evidence.confidential_transfer = true;
            true
        }
        "pausableconfig" | "pausable" => {
            let state = required_extension_state(extension, "pausable")?;
            evidence.pausable_authority =
                required_nullable_string(state, &["authority"], "pausable authority")?;
            evidence.paused = state
                .get("paused")
                .and_then(Value::as_bool)
                .ok_or_else(|| "pausable state is missing or invalid".to_string())?;
            true
        }
        "permissionedburnconfig" | "permissionedburn" => {
            let state = required_extension_state(extension, "permissioned burn")?;
            evidence.permissioned_burn_authority = required_nullable_string(
                state,
                &["authority", "burnAuthority"],
                "permissioned burn authority",
            )?;
            true
        }
        "scaleduiamountconfig" | "scaleduiamount" => {
            let state = required_extension_state(extension, "scaled UI amount")?;
            evidence.scaled_ui_amount_authority = required_nullable_string(
                state,
                &["authority", "updateAuthority"],
                "scaled UI amount authority",
            )?;
            true
        }
        _ => false,
    };
    if !assessed {
        evidence.unassessed_extensions.push(safe_name);
    }
    Ok(())
}

fn required_extension_state<'a>(extension: &'a Value, label: &str) -> Result<&'a Value, String> {
    extension
        .get("state")
        .filter(|state| state.is_object())
        .ok_or_else(|| format!("{label} extension state is missing or invalid"))
}

fn required_nullable_string(state: &Value, names: &[&str], label: &str) -> Result<bool, String> {
    let value = names
        .iter()
        .find_map(|name| state.get(*name))
        .ok_or_else(|| format!("{label} is missing"))?;
    match value {
        Value::Null => Ok(false),
        Value::String(value) if !value.trim().is_empty() => Ok(true),
        _ => Err(format!("{label} is invalid")),
    }
}

fn authority_is_set(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::String(v)) => !v.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
        Some(_) => true,
    }
}

fn string_or_u64(value: Option<&Value>, label: &str) -> Result<u128, String> {
    let Some(value) = value else {
        return Err(format!("{label} is missing"));
    };
    match value {
        Value::String(v) => v.parse::<u128>().map_err(|_| format!("{label} is invalid")),
        Value::Number(v) => v
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| format!("{label} is invalid")),
        _ => Err(format!("{label} is invalid")),
    }
}

fn value_to_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|v| v.parse::<u64>().ok()))
}

pub fn parse_largest_token_accounts(response: &Value) -> Result<Vec<String>, String> {
    reject_rpc_error(response)?;
    let values = response
        .pointer("/result/value")
        .and_then(Value::as_array)
        .ok_or_else(|| "largest token accounts are missing".to_string())?;
    if values.is_empty() || values.len() > 20 {
        return Err("largest token accounts are empty".to_string());
    }
    let mut seen = BTreeSet::new();
    let mut addresses = Vec::with_capacity(values.len());
    for item in values {
        let address = item
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| "largest token account address is missing".to_string())?;
        validate_mint(address)
            .map_err(|_| "largest token account address is invalid".to_string())?;
        if !seen.insert(address) {
            return Err("largest token account addresses contain a duplicate".to_string());
        }
        addresses.push(address.to_string());
    }
    Ok(addresses)
}

#[derive(Debug, Clone, PartialEq)]
pub struct HolderEvidence {
    pub owner_amounts: Vec<(String, u128)>,
    pub unresolved_accounts: usize,
}

pub fn parse_holder_accounts(
    response: &Value,
    expected_accounts: usize,
    requested_mint: &str,
) -> Result<HolderEvidence, String> {
    reject_rpc_error(response)?;
    let values = response
        .pointer("/result/value")
        .and_then(Value::as_array)
        .ok_or_else(|| "holder account data are missing".to_string())?;
    if expected_accounts == 0 || values.len() != expected_accounts {
        return Err("holder account response count does not match the request".to_string());
    }
    let mut owners = BTreeMap::<String, u128>::new();
    let mut unresolved = 0usize;
    for account in values {
        if account.is_null() {
            unresolved += 1;
            continue;
        }
        let info = match account.pointer("/data/parsed/info") {
            Some(v) => v,
            None => {
                unresolved += 1;
                continue;
            }
        };
        let account_mint = info
            .get("mint")
            .and_then(Value::as_str)
            .ok_or_else(|| "holder account mint is missing".to_string())?;
        if account_mint != requested_mint {
            return Err("holder account mint does not match the request".to_string());
        }
        let owner = match info.get("owner").and_then(Value::as_str) {
            Some(v) if !v.is_empty() => v,
            _ => {
                unresolved += 1;
                continue;
            }
        };
        let amount = match info
            .pointer("/tokenAmount/amount")
            .or_else(|| info.get("amount"))
            .map(|v| string_or_u64(Some(v), "holder amount"))
        {
            Some(Ok(v)) => v,
            _ => {
                unresolved += 1;
                continue;
            }
        };
        let entry = owners.entry(owner.to_string()).or_default();
        *entry = entry.saturating_add(amount);
    }
    let mut owner_amounts = owners.into_iter().collect::<Vec<_>>();
    owner_amounts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if owner_amounts.is_empty() {
        return Err("no holder owners could be resolved".to_string());
    }
    Ok(HolderEvidence {
        owner_amounts,
        unresolved_accounts: unresolved,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct MarketEvidence {
    pub pair_count: usize,
    pub max_liquidity_usd: f64,
    pub dex_id: Option<String>,
    pub pair_address: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LpStatus {
    Locked,
    Burned,
    PartiallyLocked,
    Unlocked,
    Concentrated,
    Unknown,
}

impl LpStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Burned => "burned",
            Self::PartiallyLocked => "partially_locked",
            Self::Unlocked => "unlocked",
            Self::Concentrated => "concentrated_position",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LpEvidence {
    pub status: LpStatus,
    pub burned_pct: Option<f64>,
    pub locked_pct: Option<f64>,
    pub pool_type: Option<String>,
    pub provider: &'static str,
}

pub fn parse_lp_security(response: &Value, requested_mint: &str) -> Result<LpEvidence, String> {
    let code_ok = response
        .get("code")
        .is_some_and(|value| value_to_u64(value) == Some(1));
    if !code_ok {
        return Err("LP-security provider returned an error".to_string());
    }
    let token = response
        .get("result")
        .and_then(|result| result.get(requested_mint))
        .ok_or_else(|| "LP-security response is not bound to the requested mint".to_string())?;
    let pools = token
        .get("dex")
        .and_then(Value::as_array)
        .ok_or_else(|| "LP-security response has no pool array".to_string())?;
    let best_pool = pools.iter().max_by(|left, right| {
        let left_tvl = left.get("tvl").and_then(value_to_f64).unwrap_or(0.0);
        let right_tvl = right.get("tvl").and_then(value_to_f64).unwrap_or(0.0);
        left_tvl.total_cmp(&right_tvl)
    });
    let Some(best_pool) = best_pool else {
        return Ok(LpEvidence {
            status: LpStatus::Unknown,
            burned_pct: None,
            locked_pct: None,
            pool_type: None,
            provider: "goplus",
        });
    };
    let raw_pool_type = best_pool
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty());
    let pool_type = raw_pool_type.map(|value| compact_label(value, 32));
    let burned_pct = parse_optional_percentage(best_pool.get("burn_percent"), "LP burn percent")?;
    let pool_kind = raw_pool_type.map(|value| value.to_ascii_lowercase());
    let locked_pct = if pool_kind.as_deref() == Some("standard") {
        parse_pool_bound_locked_percentage(token, best_pool, pools.len())?
    } else {
        None
    };
    let status = match pool_kind.as_deref() {
        Some("concentrated") => LpStatus::Concentrated,
        Some("standard") if burned_pct.is_some_and(|value| value >= 95.0) => LpStatus::Burned,
        Some("standard") if locked_pct.is_some_and(|value| value >= 95.0) => LpStatus::Locked,
        Some("standard")
            if burned_pct.is_some_and(|value| value > 0.0)
                || locked_pct.is_some_and(|value| value > 0.0) =>
        {
            LpStatus::PartiallyLocked
        }
        Some("standard") if burned_pct == Some(0.0) && locked_pct == Some(0.0) => {
            LpStatus::Unlocked
        }
        _ => LpStatus::Unknown,
    };
    Ok(LpEvidence {
        status,
        burned_pct: burned_pct.map(rounded),
        locked_pct: locked_pct.map(rounded),
        pool_type,
        provider: "goplus",
    })
}

fn parse_optional_percentage(value: Option<&Value>, label: &str) -> Result<Option<f64>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let parsed = value_to_f64(value).ok_or_else(|| format!("{label} is invalid"))?;
    if !(0.0..=100.0).contains(&parsed) {
        return Err(format!("{label} is outside 0..100"));
    }
    Ok(Some(parsed))
}

fn parse_pool_bound_locked_percentage(
    token: &Value,
    pool: &Value,
    pool_count: usize,
) -> Result<Option<f64>, String> {
    // GoPlus documents lp_holders for the largest main-token pool, but does
    // not expose a pool id on each holder. Bind the balances only when there is
    // exactly one reported pool; otherwise the association is ambiguous.
    if pool_count != 1 {
        return Ok(None);
    }
    let Some(lp_amount_value) = pool.get("lp_amount") else {
        return Ok(None);
    };
    let lp_amount = value_to_f64(lp_amount_value)
        .filter(|value| *value > 0.0)
        .ok_or_else(|| "LP total amount is invalid".to_string())?;
    let Some(holders) = token.get("lp_holders").and_then(Value::as_array) else {
        return Ok(None);
    };
    let mut locked_amount = 0.0;
    for holder in holders {
        let is_locked = holder
            .get("is_locked")
            .and_then(value_to_u64)
            .filter(|value| *value <= 1)
            .ok_or_else(|| "LP holder lock flag is invalid".to_string())?;
        if is_locked == 1 {
            let balance = holder
                .get("balance")
                .and_then(value_to_f64)
                .filter(|value| *value >= 0.0)
                .ok_or_else(|| "locked LP holder balance is invalid".to_string())?;
            locked_amount += balance;
            if !locked_amount.is_finite() {
                return Err("locked LP holder balance is invalid".to_string());
            }
        }
    }
    if locked_amount > lp_amount * 1.001 {
        return Err("locked LP balance exceeds the pool total".to_string());
    }
    Ok(Some((locked_amount / lp_amount * 100.0).clamp(0.0, 100.0)))
}

pub fn parse_market_pairs(
    response: &Value,
    requested_mint: &str,
) -> Result<MarketEvidence, String> {
    let pairs = response
        .as_array()
        .or_else(|| response.get("pairs").and_then(Value::as_array))
        .ok_or_else(|| "market-data response is not a pair array".to_string())?;
    let mut best: Option<(f64, Option<String>, Option<String>)> = None;
    let mut count = 0usize;
    for pair in pairs.iter().take(200) {
        if pair
            .get("chainId")
            .and_then(Value::as_str)
            .is_some_and(|v| !v.eq_ignore_ascii_case("solana"))
        {
            continue;
        }
        let matches_requested_mint = ["baseToken", "quoteToken"].iter().any(|side| {
            pair.pointer(&format!("/{side}/address"))
                .and_then(Value::as_str)
                .is_some_and(|address| address == requested_mint)
        });
        if !matches_requested_mint {
            continue;
        }
        count += 1;
        let liquidity = pair
            .pointer("/liquidity/usd")
            .and_then(value_to_f64)
            .unwrap_or(0.0)
            .max(0.0);
        if best
            .as_ref()
            .is_none_or(|(current, _, _)| liquidity > *current)
        {
            best = Some((
                liquidity,
                pair.get("dexId")
                    .and_then(Value::as_str)
                    .map(|value| compact_label(value, 40)),
                pair.get("pairAddress")
                    .and_then(Value::as_str)
                    .map(|value| compact_label(value, 64)),
            ));
        }
    }
    let (max_liquidity_usd, dex_id, pair_address) = best.unwrap_or((0.0, None, None));
    Ok(MarketEvidence {
        pair_count: count,
        max_liquidity_usd,
        dex_id,
        pair_address,
    })
}

fn value_to_f64(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|v| v.parse::<f64>().ok()))
        .filter(|v| v.is_finite())
}

fn reject_rpc_error(response: &Value) -> Result<(), String> {
    if let Some(error) = response.get("error") {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        return Err(format!("RPC error {code}"));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct RiskEvidence {
    pub mint: MintEvidence,
    pub holders: Option<HolderEvidence>,
    pub holders_error: Option<String>,
    pub market: Option<MarketEvidence>,
    pub market_error: Option<String>,
    pub lp_security: Option<LpEvidence>,
    pub lp_security_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Rating {
    Green,
    Amber,
    Red,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Amber,
    Red,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RiskFacts {
    pub program: &'static str,
    pub decimals: u8,
    pub mint_authority: bool,
    pub freeze_authority: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_fee_bps: Option<u64>,
    pub transfer_hook: bool,
    pub permanent_delegate: bool,
    pub pausable_authority: bool,
    pub paused: bool,
    pub permissioned_burn_authority: bool,
    pub scaled_ui_amount_authority: bool,
    pub unassessed_extensions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top1_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top10_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liquidity_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub market: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lp_status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lp_burned_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lp_locked_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lp_pool_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lp_evidence_source: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RiskReport {
    pub mint: String,
    pub rating: Rating,
    pub score: u8,
    pub complete: bool,
    pub findings: Vec<Finding>,
    pub facts: RiskFacts,
    pub note: &'static str,
}

pub fn assess(mint_address: &str, evidence: &RiskEvidence, cfg: &RiskConfig) -> RiskReport {
    let mut score: u16 = 0;
    let mut findings = Vec::new();
    let mut complete = true;

    let mut add = |severity: Severity, points: u16, code, detail: String| {
        score = score.saturating_add(points);
        findings.push(Finding {
            severity,
            code,
            detail,
        });
    };

    if let TokenProgram::Unknown(owner) = &evidence.mint.program {
        add(
            Severity::Red,
            100,
            "UNEXPECTED_PROGRAM",
            format!("mint owner is not SPL Token ({})", short(owner)),
        );
    }
    if evidence.mint.mint_authority {
        add(
            Severity::Red,
            35,
            "MINT_AUTHORITY_ACTIVE",
            "supply can still be increased".to_string(),
        );
    }
    if evidence.mint.freeze_authority {
        add(
            Severity::Amber,
            20,
            "FREEZE_AUTHORITY_ACTIVE",
            "token accounts can be frozen".to_string(),
        );
    }
    if evidence.mint.permanent_delegate {
        add(
            Severity::Red,
            45,
            "PERMANENT_DELEGATE",
            "delegate can transfer or burn holder tokens".to_string(),
        );
    }
    if evidence.mint.transfer_hook {
        add(
            Severity::Red,
            30,
            "TRANSFER_HOOK",
            "custom program runs on every transfer".to_string(),
        );
    }
    if evidence.mint.default_frozen {
        add(
            Severity::Red,
            45,
            "DEFAULT_FROZEN",
            "new token accounts default to frozen".to_string(),
        );
    }
    if evidence.mint.non_transferable {
        add(
            Severity::Red,
            50,
            "NON_TRANSFERABLE",
            "Token-2022 marks the asset non-transferable".to_string(),
        );
    }
    if evidence.mint.confidential_transfer {
        add(
            Severity::Amber,
            10,
            "CONFIDENTIAL_TRANSFER",
            "balances or transfer amounts may be opaque".to_string(),
        );
    }
    if evidence.mint.paused {
        add(
            Severity::Red,
            50,
            "TOKEN_PAUSED",
            "minting, burning, and transfers are paused".to_string(),
        );
    } else if evidence.mint.pausable_authority {
        add(
            Severity::Amber,
            15,
            "PAUSABLE_AUTHORITY",
            "an authority can pause minting, burning, and transfers".to_string(),
        );
    }
    if evidence.mint.permissioned_burn_authority {
        add(
            Severity::Amber,
            10,
            "PERMISSIONED_BURN",
            "holder burns require an additional authority".to_string(),
        );
    }
    if evidence.mint.scaled_ui_amount_authority {
        add(
            Severity::Amber,
            10,
            "SCALED_UI_AMOUNT",
            "an authority can change displayed token amounts".to_string(),
        );
    }
    if !evidence.mint.unassessed_extensions.is_empty() {
        complete = false;
        add(
            Severity::Amber,
            15,
            "UNASSESSED_TOKEN_EXTENSION",
            format!(
                "unassessed Token-2022 extensions: {}",
                evidence
                    .mint
                    .unassessed_extensions
                    .iter()
                    .take(4)
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        );
    }
    if let Some(bps) = evidence.mint.transfer_fee_bps.filter(|v| *v > 0) {
        let (severity, points) = if bps >= 1_000 {
            (Severity::Red, 35)
        } else if bps >= 500 {
            (Severity::Red, 25)
        } else {
            (Severity::Amber, 10)
        };
        add(
            severity,
            points,
            "TRANSFER_FEE",
            format!("maximum observed fee is {bps} bps"),
        );
    }
    if evidence.mint.transfer_fee_authority {
        add(
            Severity::Amber,
            10,
            "TRANSFER_FEE_AUTHORITY",
            "transfer-fee configuration remains controlled".to_string(),
        );
    }

    let (top1_pct, top10_pct) = if let Some(holders) = &evidence.holders {
        if holders.unresolved_accounts > 0 {
            complete = false;
            add(
                Severity::Red,
                25,
                "HOLDERS_PARTIAL",
                format!(
                    "{} top accounts did not resolve",
                    holders.unresolved_accounts
                ),
            );
        }
        let top1 = holders
            .owner_amounts
            .first()
            .map(|(_, amount)| percent(*amount, evidence.mint.supply));
        let top10_amount = holders
            .owner_amounts
            .iter()
            .take(10)
            .fold(0u128, |sum, (_, amount)| sum.saturating_add(*amount));
        let top10 = Some(percent(top10_amount, evidence.mint.supply));
        if let Some(value) = top1 {
            if value >= cfg.top1_red_pct {
                add(
                    Severity::Red,
                    35,
                    "TOP_HOLDER_CONCENTRATION",
                    format!("largest owner controls {}%", rounded(value)),
                );
            } else if value >= cfg.top1_amber_pct {
                add(
                    Severity::Amber,
                    15,
                    "TOP_HOLDER_CONCENTRATION",
                    format!("largest owner controls {}%", rounded(value)),
                );
            }
        }
        if let Some(value) = top10 {
            if value >= cfg.top10_red_pct {
                add(
                    Severity::Red,
                    25,
                    "TOP10_CONCENTRATION",
                    format!("top owners control {}%", rounded(value)),
                );
            } else if value >= cfg.top10_amber_pct {
                add(
                    Severity::Amber,
                    10,
                    "TOP10_CONCENTRATION",
                    format!("top owners control {}%", rounded(value)),
                );
            }
        }
        (top1.map(rounded), top10.map(rounded))
    } else {
        complete = false;
        add(
            Severity::Red,
            40,
            "HOLDER_EVIDENCE_MISSING",
            concise_error(
                evidence.holders_error.as_deref(),
                "holder evidence unavailable",
            ),
        );
        (None, None)
    };

    let (liquidity_usd, market) = if let Some(market) = &evidence.market {
        if market.pair_count == 0 || market.max_liquidity_usd <= 0.0 {
            add(
                Severity::Red,
                40,
                "NO_LIQUID_MARKET",
                "no Solana liquidity pair was found".to_string(),
            );
        } else if market.max_liquidity_usd < cfg.min_liquidity_usd * 0.1 {
            add(
                Severity::Red,
                35,
                "VERY_LOW_LIQUIDITY",
                format!("best pair has about ${}", dollars(market.max_liquidity_usd)),
            );
        } else if market.max_liquidity_usd < cfg.min_liquidity_usd {
            add(
                Severity::Amber,
                15,
                "LOW_LIQUIDITY",
                format!("best pair has about ${}", dollars(market.max_liquidity_usd)),
            );
        }
        (
            Some(market.max_liquidity_usd.round()),
            market.dex_id.clone(),
        )
    } else if cfg.require_market_data {
        complete = false;
        add(
            Severity::Red,
            35,
            "MARKET_EVIDENCE_MISSING",
            concise_error(
                evidence.market_error.as_deref(),
                "market evidence unavailable",
            ),
        );
        (None, None)
    } else {
        (None, None)
    };

    let (lp_status, lp_burned_pct, lp_locked_pct, lp_pool_type, lp_evidence_source) =
        if let Some(lp) = &evidence.lp_security {
            match lp.status {
                LpStatus::Locked | LpStatus::Burned => {}
                LpStatus::PartiallyLocked => add(
                    Severity::Amber,
                    15,
                    "LP_PARTIALLY_LOCKED",
                    "only part of the observed LP position is locked or burned".to_string(),
                ),
                LpStatus::Unlocked => add(
                    Severity::Red,
                    35,
                    "LP_UNLOCKED",
                    "the largest standard pool has no observed LP lock or burn".to_string(),
                ),
                LpStatus::Concentrated => {
                    complete = false;
                    add(
                        Severity::Amber,
                        15,
                        "LP_POSITION_CONTROL_UNVERIFIED",
                        "the largest pool uses concentrated positions; lock control is unverified"
                            .to_string(),
                    );
                }
                LpStatus::Unknown => {
                    complete = false;
                    add(
                        Severity::Red,
                        25,
                        "LP_STATUS_UNKNOWN",
                        "LP lock or burn status could not be established".to_string(),
                    );
                }
            }
            (
                Some(lp.status.label()),
                lp.burned_pct,
                lp.locked_pct,
                lp.pool_type.clone(),
                Some(lp.provider),
            )
        } else if cfg.require_lp_status {
            complete = false;
            add(
                Severity::Red,
                35,
                "LP_EVIDENCE_MISSING",
                concise_error(
                    evidence.lp_security_error.as_deref(),
                    "LP security evidence unavailable",
                ),
            );
            (None, None, None, None, None)
        } else {
            (None, None, None, None, None)
        };

    if evidence.mint.supply == 0 {
        add(
            Severity::Red,
            60,
            "ZERO_SUPPLY",
            "mint reports zero supply".to_string(),
        );
    }

    findings.sort_by_key(|finding| match finding.severity {
        Severity::Red => 0,
        Severity::Amber => 1,
    });
    findings.truncate(8);
    let rating = if findings
        .iter()
        .any(|finding| finding.severity == Severity::Red)
        || score >= 50
    {
        Rating::Red
    } else if !findings.is_empty() || score >= 20 {
        Rating::Amber
    } else {
        Rating::Green
    };

    RiskReport {
        mint: mint_address.to_string(),
        rating,
        score: score.min(100) as u8,
        complete,
        findings,
        facts: RiskFacts {
            program: evidence.mint.program.label(),
            decimals: evidence.mint.decimals,
            mint_authority: evidence.mint.mint_authority,
            freeze_authority: evidence.mint.freeze_authority,
            transfer_fee_bps: evidence.mint.transfer_fee_bps,
            transfer_hook: evidence.mint.transfer_hook,
            permanent_delegate: evidence.mint.permanent_delegate,
            pausable_authority: evidence.mint.pausable_authority,
            paused: evidence.mint.paused,
            permissioned_burn_authority: evidence.mint.permissioned_burn_authority,
            scaled_ui_amount_authority: evidence.mint.scaled_ui_amount_authority,
            unassessed_extensions: evidence
                .mint
                .unassessed_extensions
                .iter()
                .take(8)
                .map(|value| compact_label(value, 40))
                .filter(|value| !value.is_empty())
                .collect(),
            extensions: evidence
                .mint
                .extension_names
                .iter()
                .take(16)
                .map(|value| compact_label(value, 40))
                .filter(|value| !value.is_empty())
                .collect(),
            top1_pct,
            top10_pct,
            liquidity_usd,
            market,
            lp_status,
            lp_burned_pct,
            lp_locked_pct,
            lp_pool_type,
            lp_evidence_source,
        },
        note: "Read-only evidence, not financial advice.",
    }
}

pub fn render_report(report: &RiskReport) -> Result<String, String> {
    serde_json::to_string(report).map_err(|e| format!("could not render report: {e}"))
}

fn percent(amount: u128, supply: u128) -> f64 {
    if supply == 0 {
        return 100.0;
    }
    ((amount as f64 / supply as f64) * 100.0).clamp(0.0, 100.0)
}

fn rounded(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn dollars(value: f64) -> u64 {
    value.clamp(0.0, u64::MAX as f64).round() as u64
}

fn concise_error(error: Option<&str>, fallback: &str) -> String {
    let raw = error.unwrap_or(fallback);
    let mut out = raw.chars().take(120).collect::<String>();
    if raw.chars().count() > 120 {
        out.push('…');
    }
    out
}

fn compact_label(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(*ch, '-' | '_' | '.'))
        .take(max_chars)
        .collect()
}

fn short(value: &str) -> String {
    if value.len() <= 12 {
        return value.to_string();
    }
    format!("{}…{}", &value[..6], &value[value.len() - 4..])
}
