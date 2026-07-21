use std::collections::HashMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

const DEFAULT_MEMO_PREFIX: &str = "ZCDEPIN";
const DEFAULT_MAX_ABS_READING: f64 = 1_000_000.0;
const MEMO_MAX_BYTES: usize = 566;
const DEFAULT_ALLOWED_METRICS: [&str; 5] = [
    "temperature",
    "humidity",
    "uptime",
    "pressure",
    "air_quality",
];

#[derive(Debug, Clone, PartialEq)]
pub struct AttestConfig {
    pub allowed_metrics: Vec<String>,
    pub max_abs_reading: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttestArgs {
    pub device_id: String,
    pub reading: f64,
    pub unit: String,
    pub metric: String,
    pub memo_prefix: Option<String>,
}

impl AttestConfig {
    pub fn from_section(map: &HashMap<String, String>) -> Result<AttestConfig, String> {
        let allowed_metrics = match map.get("allowed_metrics") {
            Some(csv) => parse_allowed_metrics(csv)?,
            None => DEFAULT_ALLOWED_METRICS
                .iter()
                .map(|metric| (*metric).to_string())
                .collect(),
        };

        let max_abs_reading = match map.get("max_abs_reading") {
            Some(raw) => raw
                .parse::<f64>()
                .map_err(|_| "max_abs_reading must be a number".to_string())?,
            None => DEFAULT_MAX_ABS_READING,
        };

        if !max_abs_reading.is_finite() || max_abs_reading < 0.0 {
            return Err("max_abs_reading must be a finite non-negative number".to_string());
        }

        Ok(AttestConfig {
            allowed_metrics,
            max_abs_reading,
        })
    }
}

pub fn parse_args_strict(json: &str) -> Result<AttestArgs, String> {
    let value: Value = serde_json::from_str(json).map_err(|e| format!("invalid arguments: {e}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;

    for config_only in ["payer", "nonce_account", "private_key"] {
        if object.contains_key(config_only) {
            return Err(format!("{config_only} must come from config"));
        }
    }

    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "device_id" | "reading" | "unit" | "metric" | "memo_prefix"
        ) {
            return Err(format!("unknown field `{key}`"));
        }
    }

    let device_id = required_string(object, "device_id")?;
    let reading = object
        .get("reading")
        .and_then(Value::as_f64)
        .ok_or_else(|| "reading must be a number".to_string())?;
    let unit = required_string(object, "unit")?;
    let metric = required_string(object, "metric")?;
    let memo_prefix = match object.get("memo_prefix") {
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| "memo_prefix must be a string".to_string())?
                .to_string(),
        ),
        None => None,
    };

    Ok(AttestArgs {
        device_id,
        reading,
        unit,
        metric,
        memo_prefix,
    })
}

pub fn format_reading(v: f64) -> String {
    let rounded = if v == 0.0 { 0.0 } else { v };
    let mut rendered = format!("{rounded:.6}");
    while rendered.contains('.') && rendered.ends_with('0') {
        rendered.pop();
    }
    if rendered.ends_with('.') {
        rendered.pop();
    }
    rendered
}

pub fn period_bucket(unix_secs: u64) -> u64 {
    unix_secs / 300
}

pub fn attestation_hash(
    device_id: &str,
    metric: &str,
    reading_str: &str,
    unit: &str,
    period: u64,
) -> String {
    let canonical = format!("{device_id}|{metric}|{reading_str}|{unit}|{period}");
    let digest = Sha256::digest(canonical.as_bytes());
    hex_lower(&digest)
}

pub fn build_memo(
    prefix: &str,
    device_id: &str,
    metric: &str,
    reading_str: &str,
    unit: &str,
    period: u64,
    hash12: &str,
) -> Result<String, String> {
    let memo = format!("{prefix}|{device_id}|{metric}|{reading_str}|{unit}|{period}|{hash12}");
    if memo.len() > MEMO_MAX_BYTES {
        return Err("memo exceeds 566 bytes".to_string());
    }
    Ok(memo)
}

pub fn validate_policy(cfg: &AttestConfig, args: &AttestArgs) -> Result<(), String> {
    if !args.reading.is_finite() {
        return Err("reading must be finite".to_string());
    }
    if args.reading.abs() > cfg.max_abs_reading {
        return Err("reading exceeds max_abs_reading".to_string());
    }
    if !cfg
        .allowed_metrics
        .iter()
        .any(|metric| metric == &args.metric)
    {
        return Err("metric is not allowlisted".to_string());
    }
    Ok(())
}

pub fn memo_prefix(args: &AttestArgs) -> &str {
    args.memo_prefix.as_deref().unwrap_or(DEFAULT_MEMO_PREFIX)
}

fn parse_allowed_metrics(csv: &str) -> Result<Vec<String>, String> {
    let metrics = csv
        .split(',')
        .map(str::trim)
        .filter(|metric| !metric.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    if metrics.is_empty() {
        return Err("allowed_metrics is empty".to_string());
    }

    Ok(metrics)
}

fn required_string(object: &serde_json::Map<String, Value>, key: &str) -> Result<String, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| format!("{key} must be a string"))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
