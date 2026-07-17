//! Pure Solana RPC parsing and validator-health policy.
//!
//! This module performs no I/O and has no wasm dependency. Host tests feed it
//! recorded-shaped RPC responses, including hostile and incomplete inputs.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::{json, Value};

const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub rpc_url: String,
    pub commitment: String,
    pub max_vote_lag_slots: u64,
    pub max_commission_pct: u8,
}

impl ValidatorConfig {
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

pub fn validate_pubkey(value: &str) -> Result<(), String> {
    if value.len() < 32 || value.len() > 44 {
        return Err("vote_account must be a base58 Solana public key".to_string());
    }
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| "vote_account must be a base58 Solana public key".to_string())?;
    if decoded.len() != 32 {
        return Err("vote_account must decode to exactly 32 bytes".to_string());
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

pub fn vote_accounts_request(vote_account: &str, commitment: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "getVoteAccounts",
        "params": [{
            "commitment": commitment,
            "votePubkey": vote_account,
            "keepUnstakedDelinquents": true
        }]
    })
}

pub fn inflation_reward_request(vote_account: &str, epoch: u64, commitment: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "getInflationReward",
        "params": [[vote_account], {"epoch": epoch, "commitment": commitment}]
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochInfo {
    pub epoch: u64,
    pub absolute_slot: u64,
    pub slot_index: u64,
    pub slots_in_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkStatus {
    Current,
    Delinquent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteAccount {
    pub network_status: NetworkStatus,
    pub node_pubkey: String,
    pub activated_stake_lamports: u64,
    pub commission_pct: u8,
    pub last_vote: u64,
    pub root_slot: u64,
    pub credits_epoch: Option<u64>,
    pub credits_this_epoch: Option<u64>,
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

pub fn parse_vote_accounts_response(
    response: &Value,
    expected_vote_account: &str,
) -> Result<Option<VoteAccount>, String> {
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
        (NetworkStatus::Current, value)
    } else if let Some(value) = delinquent.first() {
        (NetworkStatus::Delinquent, value)
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

    let (credits_epoch, credits_this_epoch) =
        match value.get("epochCredits").and_then(Value::as_array) {
            Some(entries) if !entries.is_empty() => {
                let entry = entries
                    .last()
                    .and_then(Value::as_array)
                    .ok_or_else(|| "epochCredits contains an invalid entry".to_string())?;
                let credits = entry
                    .get(1)
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "epochCredits total is missing or invalid".to_string())?;
                let previous = entry
                    .get(2)
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "epochCredits prior total is missing or invalid".to_string())?;
                let epoch = entry
                    .first()
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "epochCredits epoch is missing or invalid".to_string())?;
                (
                    Some(epoch),
                    Some(
                        credits
                            .checked_sub(previous)
                            .ok_or_else(|| "epochCredits total moved backwards".to_string())?,
                    ),
                )
            }
            Some(_) => (None, None),
            None => return Err("getVoteAccounts result is missing epochCredits".to_string()),
        };

    Ok(Some(VoteAccount {
        network_status: status,
        node_pubkey: required_str(value, "nodePubkey")?.to_string(),
        activated_stake_lamports: required_u64(value, "activatedStake")?,
        commission_pct: commission as u8,
        last_vote: required_u64(value, "lastVote")?,
        root_slot: required_u64(value, "rootSlot")?,
        credits_epoch,
        credits_this_epoch,
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
    let Some(value) = result.first() else {
        return Err("getInflationReward returned no entry".to_string());
    };
    if value.is_null() {
        return Ok(None);
    }
    let commission = match value.get("commission").and_then(Value::as_u64) {
        Some(value) if value <= 100 => Some(value as u8),
        Some(_) => return Err("inflation reward commission exceeds 100 percent".to_string()),
        None => None,
    };
    let epoch = required_u64(value, "epoch")?;
    if epoch != expected_epoch {
        return Err("getInflationReward returned a different epoch".to_string());
    }
    Ok(Some(InflationReward {
        epoch,
        amount_lamports: required_u64(value, "amount")?,
        post_balance_lamports: required_u64(value, "postBalance")?,
        commission_pct: commission,
    }))
}

fn required_u64(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("RPC response field {field} is missing or invalid"))
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("RPC response field {field} is missing or invalid"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertLevel {
    Green,
    Amber,
    Red,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidatorReport {
    pub alert: AlertLevel,
    pub summary: String,
    pub vote_account: String,
    pub node_pubkey: Option<String>,
    pub network_status: Option<NetworkStatus>,
    pub current_epoch: u64,
    pub epoch_progress_pct: u8,
    pub activated_stake_sol: Option<String>,
    pub commission_pct: Option<u8>,
    pub vote_lag_slots: Option<u64>,
    pub root_lag_slots: Option<u64>,
    pub credits_epoch: Option<u64>,
    pub credits_this_epoch: Option<u64>,
    pub previous_epoch_reward_sol: Option<String>,
    pub alerts: Vec<String>,
}

pub fn analyze(
    vote_account: &str,
    epoch: &EpochInfo,
    vote: Option<&VoteAccount>,
    reward: Option<&InflationReward>,
    config: &ValidatorConfig,
) -> ValidatorReport {
    let progress = epoch
        .slot_index
        .saturating_mul(100)
        .checked_div(epoch.slots_in_epoch)
        .unwrap_or(0)
        .min(100) as u8;

    let Some(vote) = vote else {
        return ValidatorReport {
            alert: AlertLevel::Red,
            summary: "RED: vote account was not found in current or delinquent validator sets"
                .to_string(),
            vote_account: vote_account.to_string(),
            node_pubkey: None,
            network_status: None,
            current_epoch: epoch.epoch,
            epoch_progress_pct: progress,
            activated_stake_sol: None,
            commission_pct: None,
            vote_lag_slots: None,
            root_lag_slots: None,
            credits_epoch: None,
            credits_this_epoch: None,
            previous_epoch_reward_sol: reward.map(|item| lamports_to_sol(item.amount_lamports)),
            alerts: vec!["vote account not visible to the configured RPC".to_string()],
        };
    };

    let vote_lag = epoch.absolute_slot.saturating_sub(vote.last_vote);
    let root_lag = epoch.absolute_slot.saturating_sub(vote.root_slot);
    let mut level = AlertLevel::Green;
    let mut alerts = Vec::new();

    if vote.network_status == NetworkStatus::Delinquent {
        level = AlertLevel::Red;
        alerts.push("validator is in the delinquent set".to_string());
    }
    if vote.activated_stake_lamports == 0 {
        level = max_level(level, AlertLevel::Amber);
        alerts.push("validator has zero activated stake".to_string());
    }
    if vote_lag > config.max_vote_lag_slots {
        level = max_level(level, AlertLevel::Amber);
        alerts.push(format!(
            "vote lag {vote_lag} exceeds configured limit {}",
            config.max_vote_lag_slots
        ));
    }
    if vote.commission_pct > config.max_commission_pct {
        level = max_level(level, AlertLevel::Amber);
        alerts.push(format!(
            "commission {}% exceeds configured limit {}%",
            vote.commission_pct, config.max_commission_pct
        ));
    }
    let credits_this_epoch = if vote.credits_epoch == Some(epoch.epoch) {
        vote.credits_this_epoch
    } else {
        level = max_level(level, AlertLevel::Amber);
        alerts.push("validator has no credits row for the current epoch".to_string());
        None
    };

    let status = match vote.network_status {
        NetworkStatus::Current => "current",
        NetworkStatus::Delinquent => "delinquent",
    };
    let summary = format!(
        "{}: validator {status}; {} SOL activated, {}% commission, vote lag {vote_lag} slots",
        alert_name(level),
        lamports_to_sol(vote.activated_stake_lamports),
        vote.commission_pct
    );

    ValidatorReport {
        alert: level,
        summary,
        vote_account: vote_account.to_string(),
        node_pubkey: Some(vote.node_pubkey.clone()),
        network_status: Some(vote.network_status),
        current_epoch: epoch.epoch,
        epoch_progress_pct: progress,
        activated_stake_sol: Some(lamports_to_sol(vote.activated_stake_lamports)),
        commission_pct: Some(vote.commission_pct),
        vote_lag_slots: Some(vote_lag),
        root_lag_slots: Some(root_lag),
        credits_epoch: vote.credits_epoch,
        credits_this_epoch,
        previous_epoch_reward_sol: reward.map(|item| lamports_to_sol(item.amount_lamports)),
        alerts,
    }
}

fn max_level(left: AlertLevel, right: AlertLevel) -> AlertLevel {
    use AlertLevel::{Amber, Green, Red};
    match (left, right) {
        (Red, _) | (_, Red) => Red,
        (Amber, _) | (_, Amber) => Amber,
        _ => Green,
    }
}

fn alert_name(level: AlertLevel) -> &'static str {
    match level {
        AlertLevel::Green => "GREEN",
        AlertLevel::Amber => "AMBER",
        AlertLevel::Red => "RED",
    }
}

pub fn lamports_to_sol(lamports: u64) -> String {
    let whole = lamports / LAMPORTS_PER_SOL;
    let fractional = lamports % LAMPORTS_PER_SOL;
    if fractional == 0 {
        return whole.to_string();
    }
    let trimmed = format!("{fractional:09}").trim_end_matches('0').to_string();
    format!("{whole}.{trimmed}")
}

pub fn render_report(report: &ValidatorReport) -> Result<String, String> {
    serde_json::to_string(report).map_err(|error| format!("failed to render report: {error}"))
}
