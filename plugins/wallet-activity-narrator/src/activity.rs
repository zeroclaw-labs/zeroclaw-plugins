//! Pure parsing and deterministic narration for Solana JSON-RPC responses.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityRequest {
    pub address: String,
    pub limit: Option<u8>,
}

impl ActivityRequest {
    pub fn validate(&self) -> Result<(), String> {
        let decoded = bs58::decode(&self.address)
            .into_vec()
            .map_err(|_| "address must be valid base58".to_string())?;
        if decoded.len() != 32 {
            return Err("address must decode to a 32-byte Solana address".to_string());
        }
        if let Some(limit) = self.limit {
            if !(1..=5).contains(&limit) {
                return Err("limit must be between 1 and 5".to_string());
            }
        }
        Ok(())
    }

    pub fn effective_limit(&self) -> u8 {
        self.limit.unwrap_or(3)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignatureMeta {
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TokenChange {
    pub mint: String,
    pub amount: f64,
    pub decimals: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ActivityItem {
    pub signature: String,
    pub explorer_url: String,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub status: String,
    pub activity_type: String,
    pub summary: String,
    pub sol_change: f64,
    pub fee_sol: f64,
    pub token_changes: Vec<TokenChange>,
    pub programs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ActivityReport {
    pub address: String,
    pub transaction_count: usize,
    pub unavailable: u8,
    pub transactions: Vec<ActivityItem>,
    pub note: String,
}

pub fn parse_signatures(response: &str, limit: u8) -> Result<Vec<SignatureMeta>, String> {
    let root: Value = serde_json::from_str(response)
        .map_err(|error| format!("invalid getSignaturesForAddress JSON: {error}"))?;
    if let Some(error) = root.get("error") {
        return Err(format!("getSignaturesForAddress RPC error: {error}"));
    }
    let entries = root
        .get("result")
        .and_then(Value::as_array)
        .ok_or_else(|| "signature list missing".to_string())?;
    entries
        .iter()
        .take(limit as usize)
        .map(|entry| {
            let signature = entry
                .get("signature")
                .and_then(Value::as_str)
                .ok_or_else(|| "signature entry missing signature".to_string())?;
            if signature.len() < 64 || signature.len() > 100 {
                return Err("signature has invalid length".to_string());
            }
            Ok(SignatureMeta {
                signature: signature.to_string(),
            })
        })
        .collect()
}

pub fn summarize_transaction(
    wallet: &str,
    signature: &str,
    response: &str,
) -> Result<Option<ActivityItem>, String> {
    let root: Value = serde_json::from_str(response)
        .map_err(|error| format!("invalid getTransaction JSON: {error}"))?;
    if let Some(error) = root.get("error") {
        return Err(format!("getTransaction RPC error: {error}"));
    }
    let Some(result) = root.get("result") else {
        return Err("transaction result missing".to_string());
    };
    if result.is_null() {
        return Ok(None);
    }

    let account_keys = result
        .pointer("/transaction/message/accountKeys")
        .and_then(Value::as_array)
        .ok_or_else(|| "transaction account keys missing".to_string())?;
    let wallet_index = account_keys
        .iter()
        .position(|key| account_key(key) == Some(wallet))
        .ok_or_else(|| "wallet not found in transaction accounts".to_string())?;

    let meta = result
        .get("meta")
        .ok_or_else(|| "transaction metadata missing".to_string())?;
    let pre_balance = array_u64(meta, "preBalances", wallet_index)?;
    let post_balance = array_u64(meta, "postBalances", wallet_index)?;
    let sol_change = (post_balance as f64 - pre_balance as f64) / 1_000_000_000.0;
    let fee_sol = meta.get("fee").and_then(Value::as_u64).unwrap_or(0) as f64 / 1_000_000_000.0;
    let failed = meta.get("err").is_some_and(|value| !value.is_null());

    let pre_tokens = token_balances(meta.get("preTokenBalances"), wallet)?;
    let post_tokens = token_balances(meta.get("postTokenBalances"), wallet)?;
    let mut mints = BTreeSet::new();
    mints.extend(pre_tokens.keys().cloned());
    mints.extend(post_tokens.keys().cloned());
    let mut token_changes = Vec::new();
    for mint in mints {
        let (pre_amount, pre_decimals) = pre_tokens.get(&mint).copied().unwrap_or((0, 0));
        let (post_amount, post_decimals) = post_tokens.get(&mint).copied().unwrap_or((0, 0));
        let decimals = post_tokens
            .get(&mint)
            .map(|(_, value)| *value)
            .unwrap_or(pre_decimals.max(post_decimals));
        let raw_delta = post_amount - pre_amount;
        if raw_delta != 0 {
            token_changes.push(TokenChange {
                mint,
                amount: round6(raw_delta as f64 / 10f64.powi(decimals as i32)),
                decimals,
            });
        }
    }

    let mut programs = BTreeSet::new();
    if let Some(instructions) = result
        .pointer("/transaction/message/instructions")
        .and_then(Value::as_array)
    {
        for instruction in instructions {
            if let Some(program) = instruction.get("program").and_then(Value::as_str) {
                programs.insert(program.to_string());
            } else if let Some(program_id) = instruction.get("programId").and_then(Value::as_str) {
                programs.insert(short(program_id));
            }
        }
    }

    let activity_type = classify(failed, sol_change, fee_sol, &token_changes);
    let status = if failed { "failed" } else { "confirmed" };
    let summary = narrate(&activity_type, sol_change, fee_sol, &token_changes);

    Ok(Some(ActivityItem {
        signature: signature.to_string(),
        explorer_url: format!("https://solscan.io/tx/{signature}"),
        slot: result.get("slot").and_then(Value::as_u64).unwrap_or(0),
        block_time: result.get("blockTime").and_then(Value::as_i64),
        status: status.to_string(),
        activity_type,
        summary,
        sol_change: round6(sol_change),
        fee_sol: round6(fee_sol),
        token_changes,
        programs: programs.into_iter().collect(),
    }))
}

fn account_key(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("pubkey").and_then(Value::as_str))
}

fn array_u64(meta: &Value, name: &str, index: usize) -> Result<u64, String> {
    meta.get(name)
        .and_then(Value::as_array)
        .and_then(|values| values.get(index))
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{name} missing wallet balance"))
}

fn token_balances(
    value: Option<&Value>,
    wallet: &str,
) -> Result<BTreeMap<String, (i128, u8)>, String> {
    let mut balances = BTreeMap::new();
    let Some(entries) = value.and_then(Value::as_array) else {
        return Ok(balances);
    };
    for entry in entries {
        if entry.get("owner").and_then(Value::as_str) != Some(wallet) {
            continue;
        }
        let mint = entry
            .get("mint")
            .and_then(Value::as_str)
            .ok_or_else(|| "token balance mint missing".to_string())?;
        let amount = entry
            .pointer("/uiTokenAmount/amount")
            .and_then(Value::as_str)
            .ok_or_else(|| "raw token amount missing".to_string())?
            .parse::<i128>()
            .map_err(|_| "raw token amount is invalid".to_string())?;
        let decimals = entry
            .pointer("/uiTokenAmount/decimals")
            .and_then(Value::as_u64)
            .ok_or_else(|| "token decimals missing".to_string())? as u8;
        let existing = balances.entry(mint.to_string()).or_insert((0, decimals));
        if existing.1 != decimals {
            return Err("inconsistent token decimals".to_string());
        }
        existing.0 += amount;
    }
    Ok(balances)
}

fn classify(failed: bool, sol_change: f64, fee_sol: f64, tokens: &[TokenChange]) -> String {
    if failed {
        return "failed".to_string();
    }
    let positive_token = tokens.iter().any(|change| change.amount > 0.0);
    let negative_token = tokens.iter().any(|change| change.amount < 0.0);
    let meaningful_sol = sol_change.abs() > fee_sol + 0.000_001;
    if (positive_token && negative_token)
        || (positive_token && sol_change < -(fee_sol + 0.000_001))
        || (negative_token && sol_change > 0.000_001)
    {
        "swap".to_string()
    } else if positive_token || (meaningful_sol && sol_change > 0.0) {
        "received".to_string()
    } else if negative_token || (meaningful_sol && sol_change < 0.0) {
        "sent".to_string()
    } else {
        "interaction".to_string()
    }
}

fn narrate(kind: &str, sol_change: f64, fee_sol: f64, tokens: &[TokenChange]) -> String {
    if kind == "failed" {
        return format!("Failed transaction; fee impact {} SOL.", signed(sol_change));
    }
    let mut changes = Vec::new();
    if sol_change.abs() > 0.000_001 {
        changes.push(format!("{} SOL", signed(sol_change)));
    }
    changes.extend(
        tokens
            .iter()
            .map(|change| format!("{} {}", signed(change.amount), token_label(&change.mint))),
    );
    let detail = if changes.is_empty() {
        format!("no material balance change; fee {fee_sol:.6} SOL")
    } else {
        changes.join(", ")
    };
    format!("{}: {detail}.", capitalize(kind))
}

fn signed(value: f64) -> String {
    if value >= 0.0 {
        format!("+{value:.6}")
    } else {
        format!("{value:.6}")
    }
}

fn short(value: &str) -> String {
    if value.len() <= 12 {
        value.to_string()
    } else {
        format!("{}...{}", &value[..6], &value[value.len() - 4..])
    }
}

fn token_label(mint: &str) -> String {
    match mint {
        "So11111111111111111111111111111111111111112" => "SOL".to_string(),
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" => "USDC".to_string(),
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" => "USDT".to_string(),
        _ => short(mint),
    }
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn round6(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}
