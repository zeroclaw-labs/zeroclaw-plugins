//! Pure lending-health parsing and policy. No wasm, no HTTP, no I/O.
//! Host tests exercise this module directly with `cargo test`.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::{json, Value};

const DEFAULT_API_BASE_URL: &str = "https://api.kamino.finance";
const DEFAULT_ENV: &str = "mainnet-beta";
const DEFAULT_HEALTH_AMBER_BPS: u32 = 12_000;
const DEFAULT_HEALTH_RED_BPS: u32 = 10_500;
const BPS_MIN: u32 = 10_001;
const BPS_MAX: u32 = 30_000;

pub const ALLOWED_ENVS: &[&str] = &["mainnet-beta", "devnet"];

/// Operator-configurable policy resolved from the plugin's own config section.
#[derive(Debug, Clone)]
pub struct LendingConfig {
    pub api_base_url: String,
    pub env: String,
    pub health_amber_bps: u32,
    pub health_red_bps: u32,
}

impl LendingConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let api_base_url = section
            .get("api_base_url")
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string());
        validate_api_url(&api_base_url)?;

        let env = section
            .get("env")
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_else(|| DEFAULT_ENV.to_string());
        validate_env(&env)?;

        let health_amber_bps = parse_bounded_u32(
            section.get("health_amber_bps"),
            DEFAULT_HEALTH_AMBER_BPS,
            BPS_MIN,
            BPS_MAX,
            "health_amber_bps",
        )?;

        let health_red_bps = parse_bounded_u32(
            section.get("health_red_bps"),
            DEFAULT_HEALTH_RED_BPS,
            BPS_MIN,
            BPS_MAX,
            "health_red_bps",
        )?;

        if health_red_bps >= health_amber_bps {
            return Err(format!(
                "health_red_bps ({health_red_bps}) must be strictly less than health_amber_bps ({health_amber_bps})"
            ));
        }

        Ok(Self {
            api_base_url,
            env,
            health_amber_bps,
            health_red_bps,
        })
    }
}

fn parse_bounded_u32(
    value: Option<&String>,
    default: u32,
    min: u32,
    max: u32,
    name: &str,
) -> Result<u32, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    let parsed = value
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("{name} must be a non-negative integer"))?;
    if !(min..=max).contains(&parsed) {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(parsed)
}

pub fn validate_api_url(value: &str) -> Result<(), String> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err("api_base_url must not be empty or contain whitespace".to_string());
    }
    if value.contains('#') {
        return Err("api_base_url must not contain a fragment".to_string());
    }

    let (scheme, remainder) = value
        .split_once("://")
        .ok_or_else(|| "api_base_url must be an absolute HTTP(S) URL".to_string())?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err("api_base_url must use HTTPS, except loopback development endpoints".to_string());
    }

    let authority = remainder
        .split(['/', '?'])
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| "api_base_url must include a host".to_string())?;
    if authority.contains('@') {
        return Err("api_base_url must not contain user information".to_string());
    }

    let host = parse_host(authority)?;
    let is_loopback = matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    );
    if scheme == "http" && !is_loopback {
        return Err("api_base_url must use HTTPS, except loopback development endpoints".to_string());
    }
    Ok(())
}

fn parse_host(authority: &str) -> Result<&str, String> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or_else(|| "api_base_url contains an invalid IPv6 host".to_string())?;
        let host = &bracketed[..close];
        validate_port(&bracketed[close + 1..])?;
        if host.is_empty() {
            return Err("api_base_url must include a host".to_string());
        }
        return Ok(host);
    }

    let (host, suffix) = authority.find(':').map_or((authority, ""), |index| {
        (&authority[..index], &authority[index..])
    });
    validate_port(suffix)?;
    if host.is_empty() || host.contains(':') {
        return Err("api_base_url contains an invalid host".to_string());
    }
    Ok(host)
}

fn validate_port(suffix: &str) -> Result<(), String> {
    if suffix.is_empty() {
        return Ok(());
    }
    let port = suffix
        .strip_prefix(':')
        .ok_or_else(|| "api_base_url contains invalid text after the host".to_string())?;
    let parsed = port
        .parse::<u16>()
        .map_err(|_| "api_base_url port must be an integer from 1 to 65535".to_string())?;
    if parsed == 0 {
        return Err("api_base_url port must be an integer from 1 to 65535".to_string());
    }
    Ok(())
}

pub fn validate_env(value: &str) -> Result<(), String> {
    if ALLOWED_ENVS.contains(&value) {
        Ok(())
    } else {
        Err(format!("env must be one of: {}", ALLOWED_ENVS.join(", ")))
    }
}

/// Validate that a string is a Solana public key: base58, decoding to exactly
/// 32 bytes. Rejects prompt-injection-shaped garbage before any HTTP happens.
pub fn validate_obligation_pubkey(value: &str) -> Result<(), String> {
    if value.len() < 32 || value.len() > 44 {
        return Err("obligation must be a base58 Solana public key".to_string());
    }
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| "obligation must be a base58 Solana public key".to_string())?;
    if decoded.len() != 32 {
        return Err("obligation must decode to exactly 32 bytes".to_string());
    }
    Ok(())
}

/// Build the URL for the Kamino obligation metrics history endpoint.
/// The path template and query key set are hard-coded here so the LLM cannot
/// redirect requests by injecting a URL through tool arguments.
pub fn metrics_history_url(base_url: &str, obligation: &str, env: &str) -> String {
    let trimmed = base_url.trim_end_matches('/');
    format!("{trimmed}/kamino-obligation/{obligation}/metrics/history?env={env}")
}

/// The subset of an `ObligationMetrics` snapshot we actually use. Everything
/// else in Kamino's response is ignored to keep the parse surface minimal.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ObligationSnapshot {
    pub timestamp: String,
    pub tag: u8,
    pub loan_to_value: f64,
    pub liquidation_ltv: f64,
    pub net_account_value: f64,
    pub user_total_deposit: f64,
    pub user_total_borrow: f64,
}

/// Parse the latest snapshot out of a Kamino metrics history response.
/// Verifies the response echoes the obligation we asked for, and that the
/// history contains at least one snapshot. Fails closed on any mismatch.
pub fn parse_metrics_history_response(
    response: &Value,
    expected_obligation: &str,
) -> Result<ObligationSnapshot, String> {
    if let Some(error) = response.get("error").and_then(Value::as_str) {
        return Err(format!("Kamino API returned error: {error}"));
    }

    let obligation = response
        .get("obligation")
        .and_then(Value::as_str)
        .ok_or_else(|| "response is missing obligation field".to_string())?;
    if obligation != expected_obligation {
        return Err("response returned a different obligation than requested".to_string());
    }

    let history = response
        .get("history")
        .and_then(Value::as_array)
        .ok_or_else(|| "response is missing history array".to_string())?;

    let latest = history
        .last()
        .ok_or_else(|| "history is empty; obligation may not exist or has no snapshots".to_string())?;

    parse_snapshot(latest)
}

fn parse_snapshot(value: &Value) -> Result<ObligationSnapshot, String> {
    let timestamp = value
        .get("timestamp")
        .and_then(Value::as_str)
        .ok_or_else(|| "snapshot is missing timestamp".to_string())?
        .to_string();

    let stats = value
        .get("refreshedStats")
        .ok_or_else(|| "snapshot is missing refreshedStats".to_string())?;

    let loan_to_value = field_as_decimal(stats, "loanToValue")?;
    let liquidation_ltv = field_as_decimal(stats, "liquidationLtv")?;
    let net_account_value = field_as_decimal(stats, "netAccountValue")?;
    let user_total_deposit = field_as_decimal(stats, "userTotalDeposit")?;
    let user_total_borrow = field_as_decimal(stats, "userTotalBorrow")?;

    let tag_u64 = value
        .get("tag")
        .and_then(Value::as_u64)
        .ok_or_else(|| "snapshot is missing tag".to_string())?;
    if tag_u64 > 3 {
        return Err(format!(
            "obligation tag {tag_u64} is outside the documented range 0..=3"
        ));
    }

    Ok(ObligationSnapshot {
        timestamp,
        tag: tag_u64 as u8,
        loan_to_value,
        liquidation_ltv,
        net_account_value,
        user_total_deposit,
        user_total_borrow,
    })
}

/// Read a Kamino `Decimal` field. Accepts a JSON string ("0.75") or a JSON
/// number (0.75). Rejects NaN, infinity, negatives, and non-decimal text.
fn field_as_decimal(value: &Value, name: &str) -> Result<f64, String> {
    let field = value
        .get(name)
        .ok_or_else(|| format!("field {name} is missing"))?;
    let parsed = if let Some(s) = field.as_str() {
        s.parse::<f64>()
            .map_err(|_| format!("field {name} is not a valid decimal"))?
    } else if let Some(f) = field.as_f64() {
        f
    } else {
        return Err(format!("field {name} must be a decimal string or number"));
    };
    if !parsed.is_finite() {
        return Err(format!("field {name} is not a finite number"));
    }
    if parsed < 0.0 {
        return Err(format!("field {name} is negative"));
    }
    Ok(parsed)
}

/// Convenience for tests and future analyzer wiring: emit the request body
/// shape a Kamino call would carry (currently just the URL; kept as a Value
/// stub so downstream code can migrate to any future POST endpoint without a
/// signature change).
pub fn metrics_history_request(base_url: &str, obligation: &str, env: &str) -> Value {
    json!({
        "url": metrics_history_url(base_url, obligation, env),
        "method": "GET",
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertLevel {
    Green,
    Amber,
    Red,
}

/// Compact report emitted by [`analyze`] and rendered via [`render_report`].
/// Derived fields (`health_bps`, `buffer_pct`) are `None` when there is no
/// active borrow, which serializes to JSON `null`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LendingReport {
    pub alert: AlertLevel,
    pub summary: String,
    pub obligation: String,
    pub timestamp: String,
    pub obligation_type: &'static str,
    pub loan_to_value: f64,
    pub liquidation_ltv: f64,
    pub health_bps: Option<u32>,
    pub buffer_pct: Option<u32>,
    pub net_account_value: f64,
    pub user_total_deposit: f64,
    pub user_total_borrow: f64,
    pub alerts: Vec<String>,
}

/// Turn a validated snapshot plus operator policy into a green/amber/red
/// report. Pure computation on already-validated data; never fails.
pub fn analyze(
    obligation: &str,
    snapshot: &ObligationSnapshot,
    config: &LendingConfig,
) -> LendingReport {
    let obligation_type = obligation_type_name(snapshot.tag);
    let mut alerts = Vec::new();

    let (health_bps_opt, buffer_pct_opt, level) = if snapshot.loan_to_value <= 0.0 {
        alerts.push("no active borrow".to_string());
        (None, None, AlertLevel::Green)
    } else if snapshot.liquidation_ltv <= 0.0 {
        alerts.push(
            "liquidation LTV is zero with an active borrow; obligation state is suspicious"
                .to_string(),
        );
        (Some(0), Some(0), AlertLevel::Red)
    } else {
        let health_ratio = snapshot.liquidation_ltv / snapshot.loan_to_value;
        let health_bps_raw = (health_ratio * 10_000.0).round();
        let health_bps = health_bps_raw.clamp(0.0, u32::MAX as f64) as u32;

        let buffer_pct = if snapshot.liquidation_ltv > snapshot.loan_to_value {
            let raw = (snapshot.liquidation_ltv - snapshot.loan_to_value)
                / snapshot.liquidation_ltv;
            (raw * 100.0).round().clamp(0.0, 100.0) as u32
        } else {
            0
        };

        let level = if health_bps <= config.health_red_bps {
            alerts.push(format!(
                "health {health_bps} bps at or below red threshold {}",
                config.health_red_bps
            ));
            AlertLevel::Red
        } else if health_bps < config.health_amber_bps {
            alerts.push(format!(
                "health {health_bps} bps below amber threshold {}",
                config.health_amber_bps
            ));
            AlertLevel::Amber
        } else {
            AlertLevel::Green
        };

        (Some(health_bps), Some(buffer_pct), level)
    };

    let summary = build_summary(level, health_bps_opt, buffer_pct_opt);

    LendingReport {
        alert: level,
        summary,
        obligation: obligation.to_string(),
        timestamp: snapshot.timestamp.clone(),
        obligation_type,
        loan_to_value: snapshot.loan_to_value,
        liquidation_ltv: snapshot.liquidation_ltv,
        health_bps: health_bps_opt,
        buffer_pct: buffer_pct_opt,
        net_account_value: snapshot.net_account_value,
        user_total_deposit: snapshot.user_total_deposit,
        user_total_borrow: snapshot.user_total_borrow,
        alerts,
    }
}

pub fn render_report(report: &LendingReport) -> Result<String, String> {
    serde_json::to_string(report).map_err(|error| format!("failed to render report: {error}"))
}

fn obligation_type_name(tag: u8) -> &'static str {
    match tag {
        0 => "Vanilla",
        1 => "Multiply",
        2 => "Lending",
        3 => "Leverage",
        _ => "Unknown",
    }
}

fn alert_name(level: AlertLevel) -> &'static str {
    match level {
        AlertLevel::Green => "GREEN",
        AlertLevel::Amber => "AMBER",
        AlertLevel::Red => "RED",
    }
}

fn build_summary(level: AlertLevel, health_bps: Option<u32>, buffer_pct: Option<u32>) -> String {
    let name = alert_name(level);
    match (health_bps, buffer_pct) {
        (None, _) => format!("{name}: no active borrow"),
        (Some(bps), Some(buffer)) => format!(
            "{name}: health {} ({buffer}% buffer to liquidation)",
            format_health(bps)
        ),
        _ => format!("{name}: invalid state"),
    }
}

fn format_health(bps: u32) -> String {
    let whole = bps / 10_000;
    let frac = bps % 10_000;
    if frac == 0 {
        return whole.to_string();
    }
    let trimmed = format!("{frac:04}").trim_end_matches('0').to_string();
    format!("{whole}.{trimmed}")
}
