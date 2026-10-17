use std::collections::HashMap;

use crate::keys::Pubkey;
use crate::rpc::{HttpClient, ParsedMemoTx, Rpc, SignatureInfo};
use crate::shape::{assert_budget, short_id, truncate};
use serde_json::Value;

const DEFAULT_MAX_AGE_SECS: u64 = 3600;
const DEFAULT_MEMO_PREFIX: &str = "ZCDEPIN";
const DEFAULT_SCAN_LIMIT: usize = 25;
const MAX_SCAN_LIMIT: usize = 50;
const DEFAULT_MAX_PAGES: usize = 4;
const MAX_PAGES_CAP: usize = 8;
const SUMMARY_MAX_CHARS: usize = 800;
const CLOCK_SKEW_SECS: u64 = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchConfig {
    pub rpc_url: String,
    pub payer: String,
    pub max_age_secs: u64,
    pub memo_prefix: String,
    pub scan_limit: usize,
    pub max_pages: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchArgs {
    pub device_id: String,
    pub max_age_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Stale,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchOutput {
    pub summary: String,
    pub verdict: Verdict,
    pub age_secs: Option<u64>,
}

#[derive(Debug, Clone)]
struct MemoMatch {
    signature: String,
    block_time: Option<u64>,
    memo: String,
}

fn memo_match(signature: &SignatureInfo, tx: ParsedMemoTx) -> MemoMatch {
    MemoMatch {
        signature: tx.signature,
        block_time: tx
            .block_time
            .or(signature.block_time)
            .and_then(|block_time| u64::try_from(block_time).ok()),
        memo: tx.memo,
    }
}

impl WatchConfig {
    pub fn from_section(map: &HashMap<String, String>) -> Result<WatchConfig, String> {
        let rpc_url = required_config(map, "rpc_url")?.to_string();
        let payer = required_config(map, "payer")?.to_string();
        let max_age_secs = optional_u64(map, "max_age_secs", DEFAULT_MAX_AGE_SECS)?;
        let memo_prefix = map
            .get("memo_prefix")
            .map(String::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(DEFAULT_MEMO_PREFIX)
            .to_string();
        validate_memo_field("memo_prefix", &memo_prefix)?;
        let scan_limit = optional_usize(map, "scan_limit", DEFAULT_SCAN_LIMIT)?;
        let max_pages = optional_usize(map, "max_pages", DEFAULT_MAX_PAGES)?;

        if scan_limit > MAX_SCAN_LIMIT {
            return Err("scan_limit must be <= 50".to_string());
        }
        if max_pages == 0 || max_pages > MAX_PAGES_CAP {
            return Err("max_pages must be 1..=8".to_string());
        }

        Ok(WatchConfig {
            rpc_url,
            payer,
            max_age_secs,
            memo_prefix,
            scan_limit,
            max_pages,
        })
    }
}

pub fn parse_args_strict(json: &str) -> Result<WatchArgs, String> {
    let value: Value = serde_json::from_str(json).map_err(|e| format!("invalid arguments: {e}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;

    for config_only in ["payer", "private_key"] {
        if object.contains_key(config_only) {
            return Err(format!("{config_only} must come from config"));
        }
    }

    for key in object.keys() {
        if !matches!(key.as_str(), "device_id" | "max_age_secs") {
            return Err(format!("unknown field `{key}`"));
        }
    }

    let device_id = required_string(object, "device_id")?;
    if device_id.trim().is_empty() {
        return Err("device_id must not be empty".to_string());
    }
    if device_id.contains('|') || device_id.chars().any(char::is_control) {
        return Err("device_id must not contain `|` or control characters".to_string());
    }

    let max_age_secs = match object.get("max_age_secs") {
        Some(value) => Some(
            value
                .as_u64()
                .ok_or_else(|| "max_age_secs must be a non-negative integer".to_string())?,
        ),
        None => None,
    };

    Ok(WatchArgs {
        device_id,
        max_age_secs,
    })
}

pub fn execute<H: HttpClient>(
    args_json: &str,
    config: &HashMap<String, String>,
    http: &H,
    now_unix: u64,
) -> Result<WatchOutput, String> {
    let args = parse_args_strict(args_json)?;
    let cfg = WatchConfig::from_section(config)?;
    let payer = Pubkey::from_base58(&cfg.payer).map_err(|e| format!("payer: {e}"))?;
    let max_age_secs = args.max_age_secs.unwrap_or(cfg.max_age_secs);
    let rpc = Rpc {
        url: &cfg.rpc_url,
        http,
    };

    let mut before: Option<String> = None;
    let mut scanned = 0usize;

    for _page in 0..cfg.max_pages {
        let signatures = rpc
            .get_signatures_for_address(&payer, cfg.scan_limit, before.as_deref())
            .map_err(|e| format!("🔌 get signatures failed: {e}"))?;
        if signatures.is_empty() {
            break;
        }

        scanned += signatures.len();
        for signature in &signatures {
            if signature.err.is_some() {
                continue;
            }
            let tx = match rpc.get_transaction_memo(&signature.signature) {
                Ok(tx) => tx,
                Err(_) => {
                    // Skip flaky per-tx RPC failures; keep scanning.
                    continue;
                }
            };
            let Some(tx) = tx else {
                continue;
            };
            if !memo_matches(&tx.memo, &cfg.memo_prefix, &args.device_id) {
                continue;
            }

            // Signatures are newest-first; first match is the latest attestation.
            let found = memo_match(signature, tx);
            return output_for_match(&args.device_id, max_age_secs, now_unix, found);
        }

        before = signatures.last().map(|sig| sig.signature.clone());
        if signatures.len() < cfg.scan_limit {
            break;
        }
    }

    missing_output(&args.device_id, scanned)
}

fn memo_matches(memo: &str, prefix: &str, device_id: &str) -> bool {
    // Exact pipe fields only. Never use substring contains() — a short
    // prompt-injected device_id like "7" must not match "prod-greenhouse-7".
    let mut parts = memo.split('|');
    match (parts.next(), parts.next()) {
        (Some(found_prefix), Some(found_device_id)) => {
            found_prefix == prefix && found_device_id == device_id
        }
        _ => false,
    }
}

fn output_for_match(
    device_id: &str,
    max_age_secs: u64,
    now_unix: u64,
    found: MemoMatch,
) -> Result<WatchOutput, String> {
    let (age_secs, clock_skew) = match found.block_time {
        Some(block_time) if block_time > now_unix.saturating_add(CLOCK_SKEW_SECS) => {
            (Some(0), true)
        }
        Some(block_time) if block_time > now_unix => (Some(0), false),
        Some(block_time) => (Some(now_unix.saturating_sub(block_time)), false),
        None => (None, false),
    };
    let verdict = match age_secs {
        Some(age) if age <= max_age_secs => Verdict::Ok,
        Some(_) => Verdict::Stale,
        None => Verdict::Stale,
    };
    let age = age_secs
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let skew_note = if clock_skew {
        "\n⚠️ Note    blockTime ahead of host clock (treated as age 0)"
    } else {
        ""
    };
    let icon = match verdict {
        Verdict::Ok => "🟢",
        Verdict::Stale => "🟡",
        Verdict::Missing => "🔴",
    };
    let label = verdict_label(&verdict);
    let summary = fit_summary(format!(
        "{icon} Uptime {label} · {device_id}\n\
⏱ Age     {age}s (max {max_age_secs}s)\n\
🔗 Sig     {}\n\
📝 Memo    {}{skew_note}",
        short_id(&found.signature),
        truncate(&found.memo, 120),
    ));

    assert_budget(&summary, SUMMARY_MAX_CHARS).map_err(|e| e.to_string())?;
    Ok(WatchOutput {
        summary,
        verdict,
        age_secs,
    })
}

fn missing_output(device_id: &str, scanned: usize) -> Result<WatchOutput, String> {
    let summary = fit_summary(format!(
        "🔴 Uptime MISSING · {device_id}\n\
🔎 Scanned {scanned} recent signatures\n\
ℹ️ Reason  no successful matching memo found"
    ));

    assert_budget(&summary, SUMMARY_MAX_CHARS).map_err(|e| e.to_string())?;
    Ok(WatchOutput {
        summary,
        verdict: Verdict::Missing,
        age_secs: None,
    })
}

fn fit_summary(summary: String) -> String {
    truncate(&summary, SUMMARY_MAX_CHARS)
}

fn verdict_label(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Ok => "OK",
        Verdict::Stale => "STALE",
        Verdict::Missing => "MISSING",
    }
}

fn validate_memo_field(label: &str, value: &str) -> Result<(), String> {
    if value.contains('|') || value.chars().any(char::is_control) {
        return Err(format!(
            "{label} must not contain `|` or control characters"
        ));
    }
    Ok(())
}

fn required_string(object: &serde_json::Map<String, Value>, key: &str) -> Result<String, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{key} must be a string"))
}

fn required_config<'a>(config: &'a HashMap<String, String>, key: &str) -> Result<&'a str, String> {
    config
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{key} must come from config"))
}

fn optional_u64(config: &HashMap<String, String>, key: &str, default: u64) -> Result<u64, String> {
    match config.get(key) {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| format!("{key} must be a non-negative integer")),
        None => Ok(default),
    }
}

fn optional_usize(
    config: &HashMap<String, String>,
    key: &str,
    default: usize,
) -> Result<usize, String> {
    match config.get(key) {
        Some(raw) => raw
            .parse::<usize>()
            .map_err(|_| format!("{key} must be a non-negative integer")),
        None => Ok(default),
    }
}
