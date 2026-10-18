//! Pure parsing, validation, and reporting core for `stake-account-brief`.
//!
//! This module intentionally contains no WASM or networking dependency. Host
//! tests exercise all public-input validation and JSON-RPC response handling.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
pub const STAKE_PROGRAM_ID: &str = "Stake11111111111111111111111111111111111111";
const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
const NEVER_DEACTIVATES: u64 = u64::MAX;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolArgs {
    pub stake_account: String,
    #[serde(rename = "__config", default)]
    pub config: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeConfig {
    pub rpc_url: String,
    pub commitment: String,
}

impl StakeConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let rpc_url = section
            .get("rpc_url")
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_RPC_URL)
            .to_string();
        validate_rpc_url(&rpc_url)?;

        let commitment = section
            .get("commitment")
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .unwrap_or("finalized")
            .to_string();
        if !matches!(commitment.as_str(), "processed" | "confirmed" | "finalized") {
            return Err("commitment must be processed, confirmed, or finalized".to_string());
        }

        Ok(Self {
            rpc_url,
            commitment,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakeKind {
    Delegated,
    Initialized,
    Uninitialized,
    RewardsPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeAccountSnapshot {
    pub kind: StakeKind,
    pub balance_lamports: u64,
    pub delegated_lamports: Option<u64>,
    pub vote_account: Option<String>,
    pub activation_epoch: Option<u64>,
    pub deactivation_epoch: Option<u64>,
    pub credits_observed: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochSnapshot {
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardSnapshot {
    pub epoch: u64,
    pub amount_lamports: u64,
    pub post_balance_lamports: u64,
    pub effective_slot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorSnapshot {
    Current {
        activated_stake_lamports: u64,
        commission_pct: u8,
    },
    Delinquent {
        activated_stake_lamports: u64,
        commission_pct: u8,
    },
    NotFound,
}

impl ValidatorSnapshot {
    fn status(&self) -> &'static str {
        match self {
            Self::Current { .. } => "current",
            Self::Delinquent { .. } => "delinquent",
            Self::NotFound => "not-found",
        }
    }

    fn activated_stake_lamports(&self) -> Option<u64> {
        match self {
            Self::Current {
                activated_stake_lamports,
                ..
            }
            | Self::Delinquent {
                activated_stake_lamports,
                ..
            } => Some(*activated_stake_lamports),
            Self::NotFound => None,
        }
    }

    fn commission_pct(&self) -> Option<u8> {
        match self {
            Self::Current { commission_pct, .. } | Self::Delinquent { commission_pct, .. } => {
                Some(*commission_pct)
            }
            Self::NotFound => None,
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct StakeBrief {
    custody_tier: &'static str,
    stake_account: String,
    schedule_phase: &'static str,
    current_epoch: u64,
    balance_sol: String,
    delegated_sol: Option<String>,
    vote_account: Option<String>,
    validator_status: Option<&'static str>,
    validator_commission_pct: Option<u8>,
    validator_activated_stake_sol: Option<String>,
    activation_epoch: Option<u64>,
    deactivation_epoch: Option<u64>,
    previous_epoch_reward_sol: Option<String>,
    reward_epoch: Option<u64>,
    note: &'static str,
}

pub fn parse_tool_args(input: &str) -> Result<ToolArgs, String> {
    let parsed: ToolArgs =
        serde_json::from_str(input).map_err(|error| format!("invalid arguments: {error}"))?;
    validate_pubkey(&parsed.stake_account)?;
    Ok(parsed)
}

pub fn validate_pubkey(value: &str) -> Result<(), String> {
    if !(32..=44).contains(&value.len()) {
        return Err("stake_account must be a 32-byte base58 public key".to_string());
    }
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| "stake_account must be valid base58".to_string())?;
    if decoded.len() != 32 {
        return Err("stake_account must decode to exactly 32 bytes".to_string());
    }
    Ok(())
}

pub fn account_info_request(stake_account: &str, commitment: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            stake_account,
            {"commitment": commitment, "encoding": "jsonParsed"}
        ]
    })
}

pub fn epoch_info_request(commitment: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "getEpochInfo",
        "params": [{"commitment": commitment}]
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
        "params": [
            [stake_account],
            {"epoch": epoch, "commitment": commitment}
        ]
    })
}

pub fn parse_account_response(
    response: &Value,
    expected_account: &str,
) -> Result<StakeAccountSnapshot, String> {
    validate_pubkey(expected_account)?;
    let result = rpc_result(response, "getAccountInfo")?;
    let value = result
        .get("value")
        .ok_or_else(|| "getAccountInfo result is missing value".to_string())?;
    if value.is_null() {
        return Err("stake account was not found".to_string());
    }

    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| "stake account response is missing owner".to_string())?;
    if owner != STAKE_PROGRAM_ID {
        return Err("account is not owned by the Solana stake program".to_string());
    }

    let balance_lamports = parse_u64(
        value
            .get("lamports")
            .ok_or_else(|| "stake account response is missing lamports".to_string())?,
        "lamports",
    )?;
    let data = value
        .get("data")
        .ok_or_else(|| "stake account response is missing data".to_string())?;
    let program = data
        .get("program")
        .and_then(Value::as_str)
        .ok_or_else(|| "stake account response is missing parsed program".to_string())?;
    if program != "stake" {
        return Err("account data was not parsed by the Solana stake program".to_string());
    }
    let parsed = data
        .get("parsed")
        .ok_or_else(|| "stake account data is not JSON parsed".to_string())?;
    let account_type = parsed
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "parsed stake account is missing type".to_string())?;

    match account_type {
        "delegated" => parse_delegated(parsed, balance_lamports),
        "initialized" => Ok(empty_snapshot(StakeKind::Initialized, balance_lamports)),
        "uninitialized" => Ok(empty_snapshot(StakeKind::Uninitialized, balance_lamports)),
        "rewardsPool" => Ok(empty_snapshot(StakeKind::RewardsPool, balance_lamports)),
        _ => Err("unsupported parsed stake account type".to_string()),
    }
}

pub fn parse_epoch_response(response: &Value) -> Result<EpochSnapshot, String> {
    let result = rpc_result(response, "getEpochInfo")?;
    let epoch = parse_u64(
        result
            .get("epoch")
            .ok_or_else(|| "getEpochInfo result is missing epoch".to_string())?,
        "epoch",
    )?;
    Ok(EpochSnapshot { epoch })
}

pub fn parse_vote_accounts_response(
    response: &Value,
    expected_vote_account: &str,
) -> Result<ValidatorSnapshot, String> {
    validate_pubkey(expected_vote_account)?;
    let result = rpc_result(response, "getVoteAccounts")?;
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

    let (is_delinquent, value) = if let Some(value) = current.first() {
        (false, value)
    } else if let Some(value) = delinquent.first() {
        (true, value)
    } else {
        return Ok(ValidatorSnapshot::NotFound);
    };

    let returned_vote_account = value
        .get("votePubkey")
        .and_then(Value::as_str)
        .ok_or_else(|| "getVoteAccounts record is missing votePubkey".to_string())?;
    if returned_vote_account != expected_vote_account {
        return Err("getVoteAccounts returned a different vote account".to_string());
    }

    let activated_stake_lamports = parse_required_u64(value, "activatedStake")?;
    let commission = parse_required_u64(value, "commission")?;
    if commission > 100 {
        return Err("validator commission exceeds 100 percent".to_string());
    }

    if is_delinquent {
        Ok(ValidatorSnapshot::Delinquent {
            activated_stake_lamports,
            commission_pct: commission as u8,
        })
    } else {
        Ok(ValidatorSnapshot::Current {
            activated_stake_lamports,
            commission_pct: commission as u8,
        })
    }
}

pub fn parse_reward_response(
    response: &Value,
    expected_epoch: u64,
) -> Result<Option<RewardSnapshot>, String> {
    let result = rpc_result(response, "getInflationReward")?;
    let entries = result
        .as_array()
        .ok_or_else(|| "getInflationReward result must be an array".to_string())?;
    if entries.len() != 1 {
        return Err("getInflationReward must return exactly one entry".to_string());
    }
    let first = &entries[0];
    if first.is_null() {
        return Ok(None);
    }

    let epoch = parse_required_u64(first, "epoch")?;
    if epoch != expected_epoch {
        return Err("getInflationReward returned an unexpected epoch".to_string());
    }

    Ok(Some(RewardSnapshot {
        epoch,
        amount_lamports: parse_required_u64(first, "amount")?,
        post_balance_lamports: parse_required_u64(first, "postBalance")?,
        effective_slot: parse_required_u64(first, "effectiveSlot")?,
    }))
}

pub fn build_brief(
    stake_account: &str,
    account: &StakeAccountSnapshot,
    epoch: &EpochSnapshot,
    validator: Option<&ValidatorSnapshot>,
    reward: Option<&RewardSnapshot>,
) -> StakeBrief {
    StakeBrief {
        custody_tier: "T0-read-only",
        stake_account: stake_account.to_string(),
        schedule_phase: schedule_phase(account, epoch.epoch),
        current_epoch: epoch.epoch,
        balance_sol: format_sol(account.balance_lamports),
        delegated_sol: account.delegated_lamports.map(format_sol),
        vote_account: account.vote_account.clone(),
        validator_status: validator.map(ValidatorSnapshot::status),
        validator_commission_pct: validator.and_then(ValidatorSnapshot::commission_pct),
        validator_activated_stake_sol: validator
            .and_then(ValidatorSnapshot::activated_stake_lamports)
            .map(format_sol),
        activation_epoch: account.activation_epoch,
        deactivation_epoch: account
            .deactivation_epoch
            .filter(|value| *value != NEVER_DEACTIVATES),
        previous_epoch_reward_sol: reward.map(|value| format_sol(value.amount_lamports)),
        reward_epoch: reward.map(|value| value.epoch),
        note: "Schedule phase is epoch-based, not exact effective stake during warmup/cooldown.",
    }
}

pub fn render_brief(brief: &StakeBrief) -> Result<String, String> {
    serde_json::to_string(brief).map_err(|_| "failed to serialize stake brief".to_string())
}

fn parse_delegated(parsed: &Value, balance_lamports: u64) -> Result<StakeAccountSnapshot, String> {
    let delegation = parsed
        .pointer("/info/stake/delegation")
        .ok_or_else(|| "delegated stake account is missing delegation".to_string())?;
    let vote_account = delegation
        .get("voter")
        .and_then(Value::as_str)
        .ok_or_else(|| "delegation is missing voter".to_string())?;
    validate_pubkey(vote_account)
        .map_err(|_| "delegation voter is not a valid public key".to_string())?;

    let delegated_lamports = parse_required_u64(delegation, "stake")?;
    if delegated_lamports > balance_lamports {
        return Err("delegated stake exceeds the stake-account balance".to_string());
    }
    let activation_epoch = parse_required_u64(delegation, "activationEpoch")?;
    let deactivation_epoch = parse_required_u64(delegation, "deactivationEpoch")?;
    if deactivation_epoch != NEVER_DEACTIVATES && deactivation_epoch < activation_epoch {
        return Err("deactivation epoch precedes activation epoch".to_string());
    }

    Ok(StakeAccountSnapshot {
        kind: StakeKind::Delegated,
        balance_lamports,
        delegated_lamports: Some(delegated_lamports),
        vote_account: Some(vote_account.to_string()),
        activation_epoch: Some(activation_epoch),
        deactivation_epoch: Some(deactivation_epoch),
        credits_observed: parsed
            .pointer("/info/stake/creditsObserved")
            .map(|value| parse_u64(value, "creditsObserved"))
            .transpose()?,
    })
}

fn empty_snapshot(kind: StakeKind, balance_lamports: u64) -> StakeAccountSnapshot {
    StakeAccountSnapshot {
        kind,
        balance_lamports,
        delegated_lamports: None,
        vote_account: None,
        activation_epoch: None,
        deactivation_epoch: None,
        credits_observed: None,
    }
}

fn schedule_phase(account: &StakeAccountSnapshot, current_epoch: u64) -> &'static str {
    match account.kind {
        StakeKind::Initialized => "initialized-not-delegated",
        StakeKind::Uninitialized => "uninitialized",
        StakeKind::RewardsPool => "rewards-pool",
        StakeKind::Delegated => {
            let activation = account.activation_epoch.unwrap_or(current_epoch);
            let deactivation = account.deactivation_epoch.unwrap_or(NEVER_DEACTIVATES);
            if activation == deactivation {
                "never-activated"
            } else if current_epoch < activation {
                "scheduled-activation"
            } else if current_epoch == activation {
                "activation-epoch"
            } else if deactivation == NEVER_DEACTIVATES {
                "delegated"
            } else if current_epoch < deactivation {
                "scheduled-deactivation"
            } else if current_epoch == deactivation {
                "deactivation-epoch"
            } else {
                "post-deactivation-epoch"
            }
        }
    }
}

fn validate_rpc_url(url: &str) -> Result<(), String> {
    if url.len() > 2_048 || url.chars().any(char::is_whitespace) {
        return Err("rpc_url must be a valid HTTPS URL".to_string());
    }
    let remainder = url
        .strip_prefix("https://")
        .ok_or_else(|| "rpc_url must use HTTPS".to_string())?;
    let authority = remainder.split(['/', '?']).next().unwrap_or_default();
    if authority.is_empty()
        || authority.starts_with(':')
        || remainder.contains('@')
        || remainder.contains('#')
    {
        return Err(
            "rpc_url must be a valid HTTPS URL without credentials or fragments".to_string(),
        );
    }
    Ok(())
}

fn rpc_result<'a>(response: &'a Value, method: &str) -> Result<&'a Value, String> {
    if response.get("error").is_some() {
        return Err(format!("{method} returned an RPC error"));
    }
    response
        .get("result")
        .ok_or_else(|| format!("{method} response is missing result"))
}

fn parse_required_u64(object: &Value, field: &str) -> Result<u64, String> {
    parse_u64(
        object
            .get(field)
            .ok_or_else(|| format!("response is missing {field}"))?,
        field,
    )
}

fn parse_u64(value: &Value, field: &str) -> Result<u64, String> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    value
        .as_str()
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or_else(|| format!("{field} must be an unsigned integer"))
}

fn format_sol(lamports: u64) -> String {
    let whole = lamports / LAMPORTS_PER_SOL;
    let fractional = lamports % LAMPORTS_PER_SOL;
    format!("{whole}.{fractional:09}")
}
