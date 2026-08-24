//! Pure Solana RPC parsing and stake-account monitoring policy.
//!
//! This module performs no I/O and has no wasm dependency. Host tests feed it
//! recorded-shaped RPC responses, including hostile and incomplete inputs.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::{json, Value};

const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const STAKE_PROGRAM_ID: &str = "Stake11111111111111111111111111111111111111";
const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
const DEACTIVATION_EPOCH_NONE: u64 = u64::MAX;

#[derive(Debug, Clone)]
pub struct StakeMonitorConfig {
    pub rpc_url: String,
    pub commitment: String,
    pub max_vote_lag_slots: u64,
    pub max_commission_pct: u8,
}

impl StakeMonitorConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let rpc_url = section
            .get("rpc_url")
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        validate_rpc_url(&rpc_url)?;

        let commitment = section
            .get("commitment")
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_else(|| "finalized".to_string());
        if !matches!(commitment.as_str(), "processed" | "confirmed" | "finalized") {
            return Err("commitment must be processed, confirmed, or finalized".to_string());
        }

        let max_vote_lag_slots = parse_bounded_u64(
            section.get("max_vote_lag_slots"),
            128,
            1,
            1_000_000,
            "max_vote_lag_slots",
        )?;
        let max_commission_pct = parse_bounded_u64(
            section.get("max_commission_pct"),
            15,
            0,
            100,
            "max_commission_pct",
        )? as u8;

        Ok(Self {
            rpc_url,
            commitment,
            max_vote_lag_slots,
            max_commission_pct,
        })
    }
}

fn parse_bounded_u64(
    value: Option<&String>,
    default: u64,
    min: u64,
    max: u64,
    name: &str,
) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    let parsed = value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an integer"))?;
    if !(min..=max).contains(&parsed) {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(parsed)
}

pub fn validate_pubkey(value: &str, field: &str) -> Result<(), String> {
    if value.len() < 32 || value.len() > 44 {
        return Err(format!("{field} must be a base58 Solana public key"));
    }
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| format!("{field} must be a base58 Solana public key"))?;
    if decoded.len() != 32 {
        return Err(format!("{field} must decode to exactly 32 bytes"));
    }
    Ok(())
}

pub fn validate_rpc_url(value: &str) -> Result<(), String> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err("rpc_url must not be empty or contain whitespace".to_string());
    }
    if value.contains('#') {
        return Err("rpc_url must not contain a fragment".to_string());
    }

    let (scheme, remainder) = value
        .split_once("://")
        .ok_or_else(|| "rpc_url must be an absolute HTTP(S) URL".to_string())?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err("rpc_url must use HTTPS, except loopback development endpoints".to_string());
    }

    let authority = remainder
        .split(['/', '?'])
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| "rpc_url must include a host".to_string())?;
    if authority.contains('@') {
        return Err("rpc_url must not contain user information".to_string());
    }

    let host = parse_host(authority)?;
    let is_loopback = matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    );
    if scheme == "http" && !is_loopback {
        return Err("rpc_url must use HTTPS, except loopback development endpoints".to_string());
    }
    Ok(())
}

fn parse_host(authority: &str) -> Result<&str, String> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or_else(|| "rpc_url contains an invalid IPv6 host".to_string())?;
        let host = &bracketed[..close];
        validate_port(&bracketed[close + 1..])?;
        if host.is_empty() {
            return Err("rpc_url must include a host".to_string());
        }
        return Ok(host);
    }

    let (host, suffix) = authority.find(':').map_or((authority, ""), |index| {
        (&authority[..index], &authority[index..])
    });
    validate_port(suffix)?;
    if host.is_empty() || host.contains(':') {
        return Err("rpc_url contains an invalid host".to_string());
    }
    Ok(host)
}

fn validate_port(suffix: &str) -> Result<(), String> {
    if suffix.is_empty() {
        return Ok(());
    }
    let port = suffix
        .strip_prefix(':')
        .ok_or_else(|| "rpc_url contains invalid text after the host".to_string())?;
    let parsed = port
        .parse::<u16>()
        .map_err(|_| "rpc_url port must be an integer from 1 to 65535".to_string())?;
    if parsed == 0 {
        return Err("rpc_url port must be an integer from 1 to 65535".to_string());
    }
    Ok(())
}

pub fn epoch_request(commitment: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getEpochInfo",
        "params": [{"commitment": commitment}]
    })
}

pub fn account_request(stake_account: &str, commitment: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "getAccountInfo",
        "params": [stake_account, {"commitment": commitment, "encoding": "jsonParsed"}]
    })
}

pub fn vote_accounts_request(vote_account: &str, commitment: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "getVoteAccounts",
        "params": [{
            "commitment": commitment,
            "votePubkey": vote_account,
            "keepUnstakedDelinquents": true
        }]
    })
}

pub fn inflation_reward_request(stake_account: &str, epoch: u64, commitment: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "getInflationReward",
        "params": [[stake_account], {"epoch": epoch, "commitment": commitment}]
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochInfo {
    pub epoch: u64,
    pub absolute_slot: u64,
    pub slot_index: u64,
    pub slots_in_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeAccount {
    pub account_lamports: u64,
    pub state: String,
    pub delegated_stake_lamports: Option<u64>,
    pub vote_account: Option<String>,
    pub activation_epoch: Option<u64>,
    pub deactivation_epoch: Option<u64>,
    pub credits_observed: Option<u64>,
    pub staker: Option<String>,
    pub withdrawer: Option<String>,
    pub lockup_epoch: Option<u64>,
    pub lockup_unix_timestamp: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidatorStatus {
    Current,
    Delinquent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorInfo {
    pub status: ValidatorStatus,
    pub activated_stake_lamports: u64,
    pub commission_pct: u8,
    pub last_vote: u64,
    pub root_slot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InflationReward {
    pub epoch: u64,
    pub amount_lamports: u64,
    pub post_balance_lamports: u64,
    pub commission_pct: Option<u8>,
}

fn rpc_result(response: &Value) -> Result<&Value, String> {
    if let Some(error) = response.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown RPC error");
        return Err(format!("Solana RPC error: {message}"));
    }
    response
        .get("result")
        .ok_or_else(|| "Solana RPC response is missing result".to_string())
}

pub fn parse_epoch_response(response: &Value) -> Result<EpochInfo, String> {
    let result = rpc_result(response)?;
    let epoch = EpochInfo {
        epoch: required_u64(result, "epoch")?,
        absolute_slot: required_u64(result, "absoluteSlot")?,
        slot_index: required_u64(result, "slotIndex")?,
        slots_in_epoch: required_u64(result, "slotsInEpoch")?,
    };
    if epoch.slots_in_epoch == 0 || epoch.slot_index > epoch.slots_in_epoch {
        return Err("getEpochInfo returned an invalid epoch slot range".to_string());
    }
    Ok(epoch)
}

pub fn parse_account_response(
    response: &Value,
    expected_stake_account: &str,
) -> Result<StakeAccount, String> {
    validate_pubkey(expected_stake_account, "stake_account")?;
    let result = rpc_result(response)?;
    let value = result
        .get("value")
        .ok_or_else(|| "getAccountInfo result is missing value".to_string())?;
    if value.is_null() {
        return Err("stake account was not found".to_string());
    }

    if required_str(value, "owner")? != STAKE_PROGRAM_ID {
        return Err("account is not owned by the Solana stake program".to_string());
    }

    let data = value
        .get("data")
        .ok_or_else(|| "stake account is missing parsed data".to_string())?;
    if required_str(data, "program")? != "stake" {
        return Err("account data is not parsed as a stake account".to_string());
    }
    let parsed = data
        .get("parsed")
        .ok_or_else(|| "stake account is missing parsed data".to_string())?;
    let state = required_str(parsed, "type")?.to_ascii_lowercase();
    let info = parsed
        .get("info")
        .and_then(Value::as_object)
        .ok_or_else(|| "stake account parsed info is missing".to_string())?;

    let meta = info.get("meta");
    let (staker, withdrawer, lockup_epoch, lockup_unix_timestamp) = match meta {
        Some(meta) => {
            let authorized = meta.get("authorized");
            let lockup = meta.get("lockup");
            (
                authorized
                    .and_then(|value| value.get("staker"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                authorized
                    .and_then(|value| value.get("withdrawer"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                lockup
                    .and_then(|value| value.get("epoch"))
                    .map(|value| u64_from_value(value, "lockup.epoch"))
                    .transpose()?,
                lockup
                    .and_then(|value| value.get("unixTimestamp"))
                    .and_then(Value::as_i64),
            )
        }
        None => (None, None, None, None),
    };

    for (field, value) in [("staker", &staker), ("withdrawer", &withdrawer)] {
        if let Some(value) = value {
            validate_pubkey(value, field)?;
        }
    }

    let stake = info.get("stake");
    let credits_observed = stake
        .and_then(|value| value.get("creditsObserved"))
        .map(|value| u64_from_value(value, "creditsObserved"))
        .transpose()?;
    let delegation = stake.and_then(|value| value.get("delegation"));

    let (delegated_stake_lamports, vote_account, activation_epoch, deactivation_epoch) =
        match delegation {
            Some(delegation) => {
                let voter = required_str(delegation, "voter")?.to_string();
                validate_pubkey(&voter, "delegated vote_account")?;
                (
                    Some(u64_from_field(delegation, "stake")?),
                    Some(voter),
                    Some(u64_from_field(delegation, "activationEpoch")?),
                    Some(u64_from_field(delegation, "deactivationEpoch")?),
                )
            }
            None => (None, None, None, None),
        };

    if state == "delegated" && delegation.is_none() {
        return Err("delegated stake account is missing delegation data".to_string());
    }
    if state != "delegated" && delegation.is_some() {
        return Err(
            "non-delegated stake account unexpectedly includes delegation data".to_string(),
        );
    }

    Ok(StakeAccount {
        account_lamports: required_u64(value, "lamports")?,
        state,
        delegated_stake_lamports,
        vote_account,
        activation_epoch,
        deactivation_epoch,
        credits_observed,
        staker,
        withdrawer,
        lockup_epoch,
        lockup_unix_timestamp,
    })
}

pub fn parse_vote_accounts_response(
    response: &Value,
    expected_vote_account: &str,
) -> Result<Option<ValidatorInfo>, String> {
    let result = rpc_result(response)?;
    let current = result
        .get("current")
        .and_then(Value::as_array)
        .ok_or_else(|| "getVoteAccounts result is missing current".to_string())?;
    let delinquent = result
        .get("delinquent")
        .and_then(Value::as_array)
        .ok_or_else(|| "getVoteAccounts result is missing delinquent".to_string())?;

    if current.len() + delinquent.len() > 1 {
        return Err("getVoteAccounts returned more than one filtered record".to_string());
    }

    let (status, value) = if let Some(value) = current.first() {
        (ValidatorStatus::Current, value)
    } else if let Some(value) = delinquent.first() {
        (ValidatorStatus::Delinquent, value)
    } else {
        return Ok(None);
    };

    if required_str(value, "votePubkey")? != expected_vote_account {
        return Err("getVoteAccounts returned a different vote account".to_string());
    }
    let commission = required_u64(value, "commission")?;
    if commission > 100 {
        return Err("validator commission exceeds 100 percent".to_string());
    }

    Ok(Some(ValidatorInfo {
        status,
        activated_stake_lamports: required_u64(value, "activatedStake")?,
        commission_pct: commission as u8,
        last_vote: required_u64(value, "lastVote")?,
        root_slot: required_u64(value, "rootSlot")?,
    }))
}

pub fn parse_reward_response(
    response: &Value,
    expected_epoch: u64,
) -> Result<Option<InflationReward>, String> {
    let result = rpc_result(response)?
        .as_array()
        .ok_or_else(|| "getInflationReward result must be an array".to_string())?;
    if result.len() != 1 {
        return Err("getInflationReward must return exactly one entry".to_string());
    }
    let value = result
        .first()
        .ok_or_else(|| "getInflationReward returned no entry".to_string())?;
    if value.is_null() {
        return Ok(None);
    }

    let epoch = required_u64(value, "epoch")?;
    if epoch != expected_epoch {
        return Err("getInflationReward returned a different epoch".to_string());
    }
    let commission = match value.get("commission") {
        Some(Value::Null) | None => None,
        Some(value) => {
            let value = u64_from_value(value, "commission")?;
            if value > 100 {
                return Err("reward commission exceeds 100 percent".to_string());
            }
            Some(value as u8)
        }
    };

    Ok(Some(InflationReward {
        epoch,
        amount_lamports: required_u64(value, "amount")?,
        post_balance_lamports: required_u64(value, "postBalance")?,
        commission_pct: commission,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertLevel {
    Green,
    Amber,
    Red,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    Active,
    Activating,
    Deactivating,
    Deactivated,
    Pending,
    Initialized,
    Uninitialized,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct StakeReport {
    pub alert: AlertLevel,
    pub summary: String,
    pub stake_account: String,
    pub lifecycle: Lifecycle,
    pub current_epoch: u64,
    pub epoch_progress_pct: u8,
    pub account_balance_sol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_stake_sol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vote_account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_status: Option<ValidatorStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_commission_pct: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_vote_lag_slots: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivation_epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_epoch_reward_sol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lockup_epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lockup_unix_timestamp: Option<i64>,
    pub alerts: Vec<String>,
}

pub fn analyze(
    stake_account: &str,
    epoch: &EpochInfo,
    account: &StakeAccount,
    validator: Option<&ValidatorInfo>,
    reward: Option<&InflationReward>,
    config: &StakeMonitorConfig,
) -> StakeReport {
    let lifecycle = lifecycle(account, epoch.epoch);
    let mut alert = AlertLevel::Green;
    let mut alerts = Vec::new();

    match lifecycle {
        Lifecycle::Active => {}
        Lifecycle::Activating => {
            alert = AlertLevel::Amber;
            alerts.push(
                "stake is activating; effective stake may be below delegated stake".to_string(),
            );
        }
        Lifecycle::Deactivating => {
            alert = AlertLevel::Amber;
            alerts.push("stake is deactivating; effective stake is cooling down".to_string());
        }
        Lifecycle::Deactivated => {
            alert = AlertLevel::Amber;
            alerts.push("stake delegation is deactivated".to_string());
        }
        Lifecycle::Pending => {
            alert = AlertLevel::Amber;
            alerts.push("stake activation epoch is in the future".to_string());
        }
        Lifecycle::Initialized | Lifecycle::Uninitialized | Lifecycle::Unknown => {
            alert = AlertLevel::Amber;
            alerts.push(format!(
                "stake account is {} and not actively delegated",
                account.state
            ));
        }
    }

    let vote_lag = validator.map(|value| {
        epoch
            .absolute_slot
            .checked_sub(value.last_vote)
            .unwrap_or(u64::MAX)
    });
    match validator {
        Some(value) if value.status == ValidatorStatus::Delinquent => {
            alert = AlertLevel::Red;
            alerts.push("delegated validator is delinquent".to_string());
        }
        Some(value) => {
            if value.commission_pct > config.max_commission_pct {
                if alert == AlertLevel::Green {
                    alert = AlertLevel::Amber;
                }
                alerts.push(format!(
                    "validator commission {}% exceeds configured limit {}%",
                    value.commission_pct, config.max_commission_pct
                ));
            }
            if vote_lag == Some(u64::MAX) {
                alert = AlertLevel::Red;
                alerts.push("validator last-vote slot is ahead of the RPC epoch slot".to_string());
            } else if vote_lag.is_some_and(|lag| lag > config.max_vote_lag_slots) {
                if alert == AlertLevel::Green {
                    alert = AlertLevel::Amber;
                }
                alerts.push(format!(
                    "validator vote lag exceeds configured limit of {} slots",
                    config.max_vote_lag_slots
                ));
            }
        }
        None if account.vote_account.is_some() => {
            alert = AlertLevel::Red;
            alerts.push("delegated vote account was not found in validator sets".to_string());
        }
        None => {}
    }

    let delegated = account.delegated_stake_lamports.map(lamports_to_sol);
    let lifecycle_label = format!("{:?}", lifecycle).to_ascii_lowercase();
    let validator_label = validator
        .map(|value| format!("{:?}", value.status).to_ascii_lowercase())
        .unwrap_or_else(|| "not available".to_string());
    let summary = match delegated.as_deref() {
        Some(stake) => format!(
            "{}: stake {lifecycle_label}; {stake} SOL delegated; validator {validator_label}",
            format!("{:?}", alert).to_ascii_uppercase()
        ),
        None => format!(
            "{}: stake account {lifecycle_label}; no active delegation",
            format!("{:?}", alert).to_ascii_uppercase()
        ),
    };

    StakeReport {
        alert,
        summary,
        stake_account: stake_account.to_string(),
        lifecycle,
        current_epoch: epoch.epoch,
        epoch_progress_pct: ((epoch.slot_index.saturating_mul(100)) / epoch.slots_in_epoch) as u8,
        account_balance_sol: lamports_to_sol(account.account_lamports),
        delegated_stake_sol: delegated,
        vote_account: account.vote_account.clone(),
        validator_status: validator.map(|value| value.status),
        validator_commission_pct: validator.map(|value| value.commission_pct),
        validator_vote_lag_slots: vote_lag.filter(|value| *value != u64::MAX),
        activation_epoch: account.activation_epoch,
        deactivation_epoch: account
            .deactivation_epoch
            .filter(|value| *value != DEACTIVATION_EPOCH_NONE),
        previous_epoch_reward_sol: reward.map(|value| lamports_to_sol(value.amount_lamports)),
        staker: account.staker.clone(),
        withdrawer: account.withdrawer.clone(),
        lockup_epoch: account.lockup_epoch,
        lockup_unix_timestamp: account.lockup_unix_timestamp,
        alerts,
    }
}

fn lifecycle(account: &StakeAccount, current_epoch: u64) -> Lifecycle {
    if account.state == "initialized" {
        return Lifecycle::Initialized;
    }
    if account.state == "uninitialized" {
        return Lifecycle::Uninitialized;
    }
    if account.state != "delegated" {
        return Lifecycle::Unknown;
    }

    let (Some(activation), Some(deactivation)) =
        (account.activation_epoch, account.deactivation_epoch)
    else {
        return Lifecycle::Unknown;
    };
    if activation > current_epoch {
        Lifecycle::Pending
    } else if activation == current_epoch && deactivation == DEACTIVATION_EPOCH_NONE {
        Lifecycle::Activating
    } else if deactivation == DEACTIVATION_EPOCH_NONE || deactivation > current_epoch {
        Lifecycle::Active
    } else if deactivation == current_epoch {
        Lifecycle::Deactivating
    } else {
        Lifecycle::Deactivated
    }
}

pub fn render_report(report: &StakeReport) -> Result<String, String> {
    let output = serde_json::to_string(report)
        .map_err(|error| format!("failed to serialize stake report: {error}"))?;
    if output.len() > 2_000 {
        return Err("stake report exceeded the 2000-byte context budget".to_string());
    }
    Ok(output)
}

pub fn lamports_to_sol(lamports: u64) -> String {
    let whole = lamports / LAMPORTS_PER_SOL;
    let fractional = lamports % LAMPORTS_PER_SOL;
    if fractional == 0 {
        return whole.to_string();
    }
    let mut fraction = format!("{fractional:09}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!("{whole}.{fraction}")
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or invalid {field}"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .ok_or_else(|| format!("missing or invalid {field}"))
        .and_then(|value| u64_from_value(value, field))
}

fn u64_from_field(value: &Value, field: &str) -> Result<u64, String> {
    required_u64(value, field)
}

fn u64_from_value(value: &Value, field: &str) -> Result<u64, String> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    value
        .as_str()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| format!("missing or invalid {field}"))
}
