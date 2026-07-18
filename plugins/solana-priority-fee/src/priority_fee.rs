//! Pure validation, JSON-RPC request construction, and percentile analysis.
//! No wasm or network dependency is used here, so host tests cover the exact
//! policy and response-shaping logic used by the component.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const DEFAULT_MAX_ACCOUNTS: usize = 32;
const PROTOCOL_MAX_ACCOUNTS: usize = 128;
const DEFAULT_PERCENTILE: u8 = 75;
const DEFAULT_MAX_MICRO_LAMPORTS_PER_CU: u64 = 2_000_000;
const MAX_SAMPLES: usize = 512;
pub const MAX_RPC_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolArgs {
    #[serde(default)]
    pub writable_accounts: Vec<String>,
    #[serde(default)]
    pub percentile: Option<u8>,
    #[serde(rename = "__config", default)]
    pub config: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PriorityFeeConfig {
    pub rpc_url: String,
    pub max_accounts: usize,
    pub default_percentile: u8,
    pub max_micro_lamports_per_cu: u64,
}

#[derive(Debug, Clone)]
pub struct PreparedQuery {
    pub config: PriorityFeeConfig,
    pub percentile: u8,
    pub request: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FeeSummary {
    pub unit: &'static str,
    pub scope: &'static str,
    pub sample_count: usize,
    pub oldest_slot: u64,
    pub newest_slot: u64,
    pub minimum: u64,
    pub p50: u64,
    pub p75: u64,
    pub p90: u64,
    pub p95: u64,
    pub maximum: u64,
    pub selected_percentile: u8,
    pub raw_recommendation: u64,
    pub recommended: u64,
    pub recommendation_capped: bool,
    pub all_zero_samples: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
struct FeeSample {
    slot: u64,
    fee: u64,
}

impl PriorityFeeConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let rpc_url = section
            .get("rpc_url")
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        validate_rpc_url(&rpc_url)?;

        let max_accounts = parse_or_default::<usize>(
            section.get("max_accounts"),
            DEFAULT_MAX_ACCOUNTS,
            "max_accounts",
        )?;
        if !(1..=PROTOCOL_MAX_ACCOUNTS).contains(&max_accounts) {
            return Err(format!(
                "max_accounts must be between 1 and {PROTOCOL_MAX_ACCOUNTS}"
            ));
        }

        let default_percentile = parse_or_default::<u8>(
            section.get("default_percentile"),
            DEFAULT_PERCENTILE,
            "default_percentile",
        )?;
        validate_percentile(default_percentile)?;

        let max_micro_lamports_per_cu = parse_or_default::<u64>(
            section.get("max_micro_lamports_per_cu"),
            DEFAULT_MAX_MICRO_LAMPORTS_PER_CU,
            "max_micro_lamports_per_cu",
        )?;

        Ok(Self {
            rpc_url,
            max_accounts,
            default_percentile,
            max_micro_lamports_per_cu,
        })
    }
}

pub fn prepare_query(args: &ToolArgs) -> Result<PreparedQuery, String> {
    let config = PriorityFeeConfig::from_section(&args.config)?;
    let percentile = args.percentile.unwrap_or(config.default_percentile);
    validate_percentile(percentile)?;
    validate_accounts(&args.writable_accounts, config.max_accounts)?;

    let params = if args.writable_accounts.is_empty() {
        json!([])
    } else {
        json!([args.writable_accounts])
    };

    Ok(PreparedQuery {
        config,
        percentile,
        request: json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getRecentPrioritizationFees",
            "params": params
        }),
    })
}

pub fn append_bounded_rpc_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), String> {
    if body.len().saturating_add(chunk.len()) > MAX_RPC_BODY_BYTES {
        return Err(format!(
            "Solana RPC response exceeds the {MAX_RPC_BODY_BYTES}-byte limit"
        ));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

pub fn analyze_rpc_response(
    response: &Value,
    selected_percentile: u8,
    max_micro_lamports_per_cu: u64,
    writable_account_count: usize,
) -> Result<FeeSummary, String> {
    validate_percentile(selected_percentile)?;

    if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || response.get("id").and_then(Value::as_u64) != Some(1)
    {
        return Err("Solana RPC response has an unexpected JSON-RPC envelope".to_string());
    }

    if let Some(error) = response.get("error") {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        return Err(format!("Solana RPC returned error code {code}"));
    }

    let values = response
        .get("result")
        .and_then(Value::as_array)
        .ok_or_else(|| "Solana RPC response is missing a result array".to_string())?;
    if values.is_empty() {
        return Err("Solana RPC returned no recent priority-fee samples".to_string());
    }
    if values.len() > MAX_SAMPLES {
        return Err(format!(
            "Solana RPC returned more than {MAX_SAMPLES} samples"
        ));
    }

    let mut samples = Vec::with_capacity(values.len());
    let mut seen_slots = HashSet::with_capacity(values.len());
    for value in values {
        let slot = value
            .get("slot")
            .and_then(Value::as_u64)
            .ok_or_else(|| "priority-fee sample is missing an unsigned slot".to_string())?;
        let fee = value
            .get("prioritizationFee")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                "priority-fee sample is missing an unsigned prioritizationFee".to_string()
            })?;
        if !seen_slots.insert(slot) {
            return Err("Solana RPC returned a duplicate slot".to_string());
        }
        samples.push(FeeSample { slot, fee });
    }

    let oldest_slot = samples
        .iter()
        .map(|sample| sample.slot)
        .min()
        .unwrap_or_default();
    let newest_slot = samples
        .iter()
        .map(|sample| sample.slot)
        .max()
        .unwrap_or_default();
    let mut fees: Vec<u64> = samples.iter().map(|sample| sample.fee).collect();
    fees.sort_unstable();

    let raw_recommendation = nearest_rank(&fees, selected_percentile);
    let recommended = raw_recommendation.min(max_micro_lamports_per_cu);
    let all_zero_samples = fees.iter().all(|fee| *fee == 0);

    Ok(FeeSummary {
        unit: "micro-lamports-per-compute-unit",
        scope: if writable_account_count == 0 {
            "global"
        } else {
            "writable-account-set"
        },
        sample_count: fees.len(),
        oldest_slot,
        newest_slot,
        minimum: fees[0],
        p50: nearest_rank(&fees, 50),
        p75: nearest_rank(&fees, 75),
        p90: nearest_rank(&fees, 90),
        p95: nearest_rank(&fees, 95),
        maximum: *fees.last().unwrap_or(&0),
        selected_percentile,
        raw_recommendation,
        recommended,
        recommendation_capped: recommended != raw_recommendation,
        all_zero_samples,
        warning: all_zero_samples.then_some(
            "all recent samples are zero; use the transaction's complete writable-account set for a local-market estimate",
        ),
    })
}

fn validate_accounts(accounts: &[String], max_accounts: usize) -> Result<(), String> {
    if accounts.len() > max_accounts {
        return Err(format!(
            "writable_accounts exceeds the operator limit of {max_accounts}"
        ));
    }

    let mut seen = HashSet::with_capacity(accounts.len());
    for account in accounts {
        if !(32..=44).contains(&account.len()) || !account.is_ascii() {
            return Err("writable_accounts contains an invalid public-key length".to_string());
        }
        if !seen.insert(account) {
            return Err("writable_accounts contains a duplicate".to_string());
        }
        let decoded = bs58::decode(account)
            .into_vec()
            .map_err(|_| "writable_accounts contains invalid base58".to_string())?;
        if decoded.len() != 32 {
            return Err("writable_accounts contains a non-32-byte public key".to_string());
        }
    }
    Ok(())
}

fn validate_percentile(percentile: u8) -> Result<(), String> {
    if !(1..=99).contains(&percentile) {
        return Err("percentile must be between 1 and 99".to_string());
    }
    Ok(())
}

fn validate_rpc_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("rpc_url must use https://".to_string());
    }
    let authority_and_path = &url[8..];
    let authority = authority_and_path.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') || authority.contains('#') {
        return Err("rpc_url must contain an HTTPS host and no embedded credentials".to_string());
    }
    Ok(())
}

fn nearest_rank(sorted: &[u64], percentile: u8) -> u64 {
    let rank = (percentile as usize * sorted.len()).div_ceil(100);
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn parse_or_default<T>(raw: Option<&String>, default: T, key: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    match raw {
        Some(value) => value
            .parse::<T>()
            .map_err(|_| format!("{key} has an invalid value")),
        None => Ok(default),
    }
}
