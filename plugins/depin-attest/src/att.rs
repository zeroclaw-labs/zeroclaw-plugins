//! The attestation core: fail-closed argument validation, on-chain sequence
//! recovery, canonical payload construction, and output shaping.
//!
//! Trust boundaries, explicitly:
//! - `metric` / `value` / `unit` come from the LLM — hostile until validated.
//! - `device_pubkey`, `rpc_url`, and the metric allowlist come from the
//!   operator's config section, which the host injects under `__config` and
//!   strips from caller args first — the model cannot spoof or override it.
//! - The previous-attestation lookup trusts confirmed chain history only.

use std::collections::HashMap;

use serde_json::Value;

use crate::rpc::{self, PriorTx};
use solana_wasip2_core::{b64, hash, pubkey, tx};

/// Public, keyless default. Operators running real devices set their own
/// endpoint (their key stays in config, never in code or arguments).
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// How many recent transactions to scan for the previous attestation.
const PRIOR_SCAN_LIMIT: u16 = 25;

// ── Config ────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub struct MetricSpec {
    pub name: String,
    pub min: f64,
    pub max: f64,
    pub unit: String,
}

#[derive(Debug)]
pub struct Config {
    pub device_pubkey: String,
    pub rpc_url: String,
    pub metrics: Vec<MetricSpec>,
}

/// Charset for metric names and units inside the canonical JSON payload —
/// tight enough that no validated value can break out of a JSON string.
fn spec_token_ok(s: &str, max_len: usize) -> bool {
    !s.is_empty()
        && s.len() <= max_len
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '%' | '/' | '.' | '-'))
}

/// The host injects plugin config as a flat string map, so metric specs use a
/// compact encoding: `"name:min:max:unit"` entries, comma-separated, e.g.
/// `metrics = "temp_c:-40:85:C, humidity_pct:0:100:%"`.
pub fn parse_config(cfg: &HashMap<String, String>) -> Result<Config, String> {
    let device_pubkey = cfg
        .get("device_pubkey")
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("config is missing device_pubkey — refusing to attest for an unconfigured device")?;
    pubkey::decode(device_pubkey)
        .map_err(|e| format!("config device_pubkey is invalid: {e}"))?;

    let rpc_url = cfg
        .get("rpc_url")
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_RPC_URL)
        .to_string();

    let raw = cfg
        .get("metrics")
        .map(String::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or("config is missing the metrics allowlist — refusing to attest unlisted metrics")?;
    let mut metrics = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        let parts: Vec<&str> = entry.split(':').collect();
        let [name, min, max, unit] = parts[..] else {
            return Err(format!(
                "metric spec '{entry}' is malformed (want name:min:max:unit)"
            ));
        };
        if !spec_token_ok(name, 32) || !spec_token_ok(unit, 8) {
            return Err(format!("metric spec '{entry}' has an invalid name or unit"));
        }
        let min: f64 = min.parse().map_err(|_| format!("bad min in '{entry}'"))?;
        let max: f64 = max.parse().map_err(|_| format!("bad max in '{entry}'"))?;
        if !min.is_finite() || !max.is_finite() || min >= max {
            return Err(format!("bounds in '{entry}' are not a valid range"));
        }
        metrics.push(MetricSpec {
            name: name.to_string(),
            min,
            max,
            unit: unit.to_string(),
        });
    }
    Ok(Config {
        device_pubkey: device_pubkey.to_string(),
        rpc_url,
        metrics,
    })
}

// ── Arguments ─────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteArgs {
    pub metric: String,
    pub value: Value,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(rename = "__config", default)]
    pub config: HashMap<String, String>,
}

/// A validated reading: metric matched the allowlist, value is finite, within
/// operator bounds, and canonically formatted.
#[derive(Debug)]
pub struct Reading {
    pub metric: String,
    pub value_str: String,
    pub unit: String,
}

pub fn validate_reading(args: &ExecuteArgs, cfg: &Config) -> Result<Reading, String> {
    let spec = cfg
        .metrics
        .iter()
        .find(|m| m.name == args.metric)
        .ok_or_else(|| {
            format!(
                "metric '{}' is not in the operator's allowlist ({})",
                sanitize(&args.metric),
                cfg.metrics
                    .iter()
                    .map(|m| m.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    let value = match &args.value {
        Value::Number(n) => n
            .as_f64()
            .ok_or_else(|| "value is not a representable number".to_string())?,
        Value::String(s) => {
            if s.len() > 32 {
                return Err("value string is too long to be a sensor reading".into());
            }
            s.trim()
                .parse::<f64>()
                .map_err(|_| format!("value '{}' is not numeric", sanitize(s)))?
        }
        _ => return Err("value must be a number".into()),
    };
    if !value.is_finite() {
        return Err("value must be finite".into());
    }
    if value < spec.min || value > spec.max {
        return Err(format!(
            "value {value} is outside the operator's bounds for {} [{}, {}] — refusing to attest",
            spec.name, spec.min, spec.max
        ));
    }
    if let Some(unit) = &args.unit {
        if unit != &spec.unit {
            return Err(format!(
                "unit '{}' does not match the configured unit '{}' for {}",
                sanitize(unit),
                spec.unit,
                spec.name
            ));
        }
    }

    // Canonical value: shortest round-trip formatting of the parsed number,
    // so the payload never carries attacker-shaped digits.
    let value_str = format_value(value);
    Ok(Reading {
        metric: spec.name.clone(),
        value_str,
        unit: spec.unit.clone(),
    })
}

fn format_value(v: f64) -> String {
    if v == v.trunc() && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        let s = format!("{v}");
        s.chars().take(32).collect()
    }
}

/// Echo untrusted input safely: strip to a short printable prefix.
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '%' | '/' | '.' | '-'))
        .take(24)
        .collect()
}

// ── Chain recovery ────────────────────────────────────────────────────────

pub struct Prior {
    pub seq: u64,
    pub signature: String,
}

/// Newest confirmed transaction whose memo is one of OUR attestations for
/// THIS device. Anything else on the address (transfers, other memos,
/// attacker-crafted lookalikes for a different `dev`) is ignored.
pub fn find_prior(priors: &[PriorTx], device: &str) -> Option<Prior> {
    for p in priors {
        let Some(memo) = &p.memo else { continue };
        let Ok(v) = serde_json::from_str::<Value>(memo) else {
            continue;
        };
        if v.get("v").and_then(Value::as_u64) != Some(1) {
            continue;
        }
        if v.get("dev").and_then(Value::as_str) != Some(device) {
            continue;
        }
        let Some(seq) = v.get("seq").and_then(Value::as_u64) else {
            continue;
        };
        return Some(Prior {
            seq,
            signature: p.signature.clone(),
        });
    }
    None
}

// ── Payload + output ──────────────────────────────────────────────────────

/// Canonical attestation JSON. Built by hand so byte layout is deterministic:
/// fixed key order, no whitespace. Every interpolated value is validated
/// upstream (charset-restricted or numeric), so the result is always valid
/// JSON with exactly these eight keys.
pub fn build_payload(
    device: &str,
    seq: u64,
    ts: u64,
    reading: &Reading,
    prev: &str,
) -> String {
    format!(
        r#"{{"v":1,"dev":"{device}","seq":{seq},"ts":{ts},"metric":"{metric}","val":"{val}","unit":"{unit}","prev":"{prev}"}}"#,
        metric = reading.metric,
        val = reading.value_str,
        unit = reading.unit,
    )
}

/// The full flow, transport-injected so host tests exercise every branch with
/// canned RPC responses: recover the chain, build the payload, build the
/// unsigned transaction, shape the output.
pub fn run<F>(args_json: &str, post: &mut F, now_unix: u64) -> Result<String, String>
where
    F: FnMut(&str, &Value) -> Result<String, String>,
{
    let args: ExecuteArgs = serde_json::from_str(args_json)
        .map_err(|e| format!("arguments rejected: {e}"))?;
    let cfg = parse_config(&args.config)?;
    let reading = validate_reading(&args, &cfg)?;

    let sigs_resp = post(&cfg.rpc_url, &rpc::build_get_signatures(&cfg.device_pubkey, PRIOR_SCAN_LIMIT))?;
    let priors = rpc::parse_signatures(&sigs_resp)?;
    let (seq, prev) = match find_prior(&priors, &cfg.device_pubkey) {
        Some(prior) => (prior.seq + 1, hash::short_hash_hex(&prior.signature)),
        None => (1, "genesis".to_string()),
    };

    let bh_resp = post(&cfg.rpc_url, &rpc::build_get_latest_blockhash())?;
    let (blockhash_b58, last_valid_height) = rpc::parse_latest_blockhash(&bh_resp)?;
    let blockhash = pubkey::decode(&blockhash_b58)
        .map_err(|e| format!("RPC returned an invalid blockhash: {e}"))?;

    let payload = build_payload(&cfg.device_pubkey, seq, now_unix, &reading, &prev);
    let fee_payer = pubkey::decode(&cfg.device_pubkey)?;
    let tx_bytes = tx::build_unsigned_memo_tx(&fee_payer, &blockhash, payload.as_bytes())?;

    let dev_short: String = cfg.device_pubkey.chars().take(8).collect();
    Ok(format!(
        "ATTESTATION #{seq} ready to sign — {metric} {val} {unit} from device {dev_short}…\n\
         chain: prev {prev}, ts {ts}\n\
         memo: {payload}\n\
         unsigned_tx_base64: {tx_b64}\n\
         Approving signs a fee-only memo (no transfer possible). Blockhash valid \
         to height {lvbh}; if approval waits past ~60s, call again to rebuild — \
         the sequence stays consistent until one lands.",
        metric = reading.metric,
        val = reading.value_str,
        unit = reading.unit,
        ts = now_unix,
        tx_b64 = b64::encode(&tx_bytes),
        lvbh = last_valid_height,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_map() -> HashMap<String, String> {
        HashMap::from([
            (
                "device_pubkey".to_string(),
                // The system program id — a convenient valid 32-byte key.
                "11111111111111111111111111111111".to_string(),
            ),
            (
                "metrics".to_string(),
                "temp_c:-40:85:C, humidity_pct:0:100:%".to_string(),
            ),
        ])
    }

    #[test]
    fn config_parses_and_defaults_rpc() {
        let cfg = parse_config(&cfg_map()).unwrap();
        assert_eq!(cfg.rpc_url, DEFAULT_RPC_URL);
        assert_eq!(cfg.metrics.len(), 2);
        assert_eq!(cfg.metrics[1].unit, "%");
    }

    #[test]
    fn missing_device_or_metrics_fails_closed() {
        let mut m = cfg_map();
        m.remove("device_pubkey");
        assert!(parse_config(&m).unwrap_err().contains("device_pubkey"));
        let mut m = cfg_map();
        m.remove("metrics");
        assert!(parse_config(&m).unwrap_err().contains("allowlist"));
    }

    #[test]
    fn malformed_metric_specs_fail_closed() {
        for bad in [
            "temp_c:-40:85",           // missing unit
            "temp_c:cold:85:C",        // non-numeric bound
            "temp_c:85:-40:C",         // inverted range
            "temp\"c:-40:85:C",        // name would break JSON
            ":-40:85:C",               // empty name
        ] {
            let mut m = cfg_map();
            m.insert("metrics".to_string(), bad.to_string());
            assert!(parse_config(&m).is_err(), "should reject {bad}");
        }
    }

    fn args(metric: &str, value: Value) -> ExecuteArgs {
        ExecuteArgs {
            metric: metric.to_string(),
            value,
            unit: None,
            config: cfg_map(),
        }
    }

    #[test]
    fn readings_validate_and_canonicalize() {
        let cfg = parse_config(&cfg_map()).unwrap();
        let r = validate_reading(&args("temp_c", Value::from(23.5)), &cfg).unwrap();
        assert_eq!(r.value_str, "23.5");
        assert_eq!(r.unit, "C");
        let r = validate_reading(&args("temp_c", Value::from("21")), &cfg).unwrap();
        assert_eq!(r.value_str, "21");
    }

    #[test]
    fn out_of_bounds_and_unlisted_fail_closed() {
        let cfg = parse_config(&cfg_map()).unwrap();
        assert!(validate_reading(&args("temp_c", Value::from(200)), &cfg)
            .unwrap_err()
            .contains("outside"));
        assert!(validate_reading(&args("balance_sol", Value::from(1)), &cfg)
            .unwrap_err()
            .contains("allowlist"));
        assert!(validate_reading(&args("temp_c", Value::from("NaN")), &cfg).is_err());
        assert!(validate_reading(&args("temp_c", Value::from(f64::NAN)), &cfg).is_err());
    }

    #[test]
    fn prior_recovery_ignores_foreign_and_malformed_memos() {
        let device = "11111111111111111111111111111111";
        let priors = vec![
            PriorTx { signature: "s1".into(), memo: None },
            PriorTx { signature: "s2".into(), memo: Some("gm".into()) },
            PriorTx {
                signature: "s3".into(),
                memo: Some(format!(
                    r#"{{"v":1,"dev":"SomeOtherDevice1111111111111111","seq":99}}"#
                )),
            },
            PriorTx {
                signature: "s4".into(),
                memo: Some(format!(r#"{{"v":1,"dev":"{device}","seq":7,"prev":"x"}}"#)),
            },
        ];
        let prior = find_prior(&priors, device).unwrap();
        assert_eq!(prior.seq, 7);
        assert_eq!(prior.signature, "s4");
    }

    #[test]
    fn payload_is_canonical_json() {
        let reading = Reading {
            metric: "temp_c".into(),
            value_str: "23.5".into(),
            unit: "C".into(),
        };
        let p = build_payload("Dev111", 8, 1789000000, &reading, "aabbccdd00112233");
        assert_eq!(
            p,
            r#"{"v":1,"dev":"Dev111","seq":8,"ts":1789000000,"metric":"temp_c","val":"23.5","unit":"C","prev":"aabbccdd00112233"}"#
        );
        let parsed: Value = serde_json::from_str(&p).unwrap();
        assert_eq!(parsed["seq"], 8);
    }
}
