//! Pure constructor from the host-injected `__config` string map
//! (`HashMap<String, String>`, exactly as `redact-text` receives it) to a typed
//! [`Config`]. No I/O, no wasm dependency: compiles and tests on the host.
//!
//! Fail-closed by construction: the canonical key set is closed, any key
//! outside it (including a misspelling) is a hard `Err` naming the offending
//! key, and there is no silent default for anything present-but-wrong.

use std::collections::HashMap;

/// Default Kamino Lend market when `markets` is absent from config.
pub const DEFAULT_MARKET: &str = "7u3HeHxYDLhnCoErrtycNokbQYbWGzLs6JSDqGAv5PfF";
/// Default RPC endpoint when `rpc_url` is absent from config.
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
pub const DEFAULT_WATCH_PCT: f64 = 25.0;
pub const DEFAULT_WARN_PCT: f64 = 15.0;
pub const DEFAULT_CRITICAL_PCT: f64 = 7.0;

/// The only keys `Config::from_map` accepts. Anything else is a hard error.
const CANONICAL_KEYS: [&str; 10] = [
    "wallet",
    "markets",
    "watch_pct",
    "warn_pct",
    "critical_pct",
    "rpc_url",
    "max_repay_ui",
    "max_deposit_ui",
    "priority_fee_microlamports",
    "nonce_account",
];

/// Resolved plugin configuration.
#[derive(Debug)]
pub struct Config {
    /// Base58 pubkey, 32 bytes when decoded.
    pub wallet: Option<String>,
    /// Kamino Lend markets to scope lookups to; defaults to the main market.
    pub markets: Vec<String>,
    pub watch_pct: f64,
    pub warn_pct: f64,
    pub critical_pct: f64,
    /// https-only RPC endpoint; never overridable by model-supplied args.
    pub rpc_url: String,
    /// Absent means the rescue action is disabled.
    pub max_repay_ui: Option<f64>,
    /// Absent means the deposit action is disabled (same fail-closed
    /// semantics as `max_repay_ui`).
    pub max_deposit_ui: Option<f64>,
    /// Absent means the built rescue tx carries no compute-budget
    /// instructions (feature OFF, byte-identical to pre-v1.1 output).
    pub priority_fee_microlamports: Option<u64>,
    /// Base58 pubkey, 32 bytes when decoded. Absent means the built rescue
    /// tx uses a fetched `getLatestBlockhash` value (feature OFF,
    /// byte-identical to pre-v1.1 output); present switches `run_rescue`
    /// to reading and advancing this durable-nonce account instead, and
    /// any problem with it (missing, wrong owner/state/authority) is a
    /// hard error — never a silent fallback to a fetched blockhash.
    pub nonce_account: Option<String>,
}

impl Config {
    /// Build from the flat `string -> string` section the host injects under
    /// `__config`. Fails closed: an unknown/misspelled key, a wrong-type
    /// value, an `http://` `rpc_url`, or a threshold-ordering violation is a
    /// hard `Err` naming the offending key.
    pub fn from_map(m: &HashMap<String, String>) -> Result<Config, String> {
        let mut unknown: Vec<&str> = m
            .keys()
            .map(String::as_str)
            .filter(|k| !CANONICAL_KEYS.contains(k))
            .collect();
        unknown.sort_unstable();
        if let Some(key) = unknown.first() {
            return Err(format!("unknown config key '{key}'"));
        }

        let wallet = match m.get("wallet") {
            Some(v) => {
                validate_base58_32(v).map_err(|()| {
                    "invalid config key 'wallet': not a valid base58 32-byte pubkey".to_string()
                })?;
                Some(v.clone())
            }
            None => None,
        };

        let markets = match m.get("markets") {
            Some(v) => {
                let parts: Vec<String> = v
                    .split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect();
                if parts.is_empty() {
                    return Err("invalid config key 'markets': empty list".to_string());
                }
                for p in &parts {
                    validate_base58_32(p).map_err(|()| {
                        "invalid config key 'markets': not a valid base58 32-byte pubkey"
                            .to_string()
                    })?;
                }
                parts
            }
            None => vec![DEFAULT_MARKET.to_string()],
        };

        let watch_pct = parse_pct(m, "watch_pct", DEFAULT_WATCH_PCT)?;
        let warn_pct = parse_pct(m, "warn_pct", DEFAULT_WARN_PCT)?;
        let critical_pct = parse_pct(m, "critical_pct", DEFAULT_CRITICAL_PCT)?;
        if !(critical_pct < warn_pct && warn_pct < watch_pct) {
            return Err(
                "invalid config thresholds: require critical_pct < warn_pct < watch_pct"
                    .to_string(),
            );
        }

        let rpc_url = match m.get("rpc_url") {
            Some(v) => {
                if !v.starts_with("https://") {
                    return Err("invalid config key 'rpc_url': must use https://".to_string());
                }
                v.clone()
            }
            None => DEFAULT_RPC_URL.to_string(),
        };

        let max_repay_ui = parse_positive_f64(m, "max_repay_ui")?;
        let max_deposit_ui = parse_positive_f64(m, "max_deposit_ui")?;

        let priority_fee_microlamports = match m.get("priority_fee_microlamports") {
            Some(v) => {
                let n: f64 = v.parse().map_err(|_| {
                    "invalid config key 'priority_fee_microlamports': not a number".to_string()
                })?;
                // `>= 2^64` and not `> u64::MAX`: `u64::MAX as f64` rounds up
                // to exactly 2^64. Without the bound, `n as u64` saturates
                // rather than wrapping, so a fat-fingered exponent would buy a
                // `u64::MAX` microlamports/CU fee instead of being rejected.
                if !n.is_finite() || n <= 0.0 || n.fract() != 0.0 || n >= u64::MAX as f64 {
                    return Err(
                        "invalid config key 'priority_fee_microlamports': must be a positive integer"
                            .to_string(),
                    );
                }
                Some(n as u64)
            }
            None => None,
        };

        let nonce_account = match m.get("nonce_account") {
            Some(v) => {
                validate_base58_32(v).map_err(|()| {
                    "invalid config key 'nonce_account': not a valid base58 32-byte pubkey"
                        .to_string()
                })?;
                Some(v.clone())
            }
            None => None,
        };

        Ok(Config {
            wallet,
            markets,
            watch_pct,
            warn_pct,
            critical_pct,
            rpc_url,
            max_repay_ui,
            max_deposit_ui,
            priority_fee_microlamports,
            nonce_account,
        })
    }
}

fn parse_pct(m: &HashMap<String, String>, key: &str, default: f64) -> Result<f64, String> {
    match m.get(key) {
        Some(v) => {
            let n: f64 = v
                .parse()
                .map_err(|_| format!("invalid config key '{key}': not a number"))?;
            if !(n.is_finite() && n > 0.0 && n < 100.0) {
                return Err(format!("invalid config key '{key}': must be in (0, 100)"));
            }
            Ok(n)
        }
        None => Ok(default),
    }
}

/// Shared validation for `max_repay_ui`/`max_deposit_ui`: absent -> `None`
/// (action disabled), else must parse as a finite positive number.
fn parse_positive_f64(m: &HashMap<String, String>, key: &str) -> Result<Option<f64>, String> {
    match m.get(key) {
        Some(v) => {
            let n: f64 = v
                .parse()
                .map_err(|_| format!("invalid config key '{key}': not a number"))?;
            if !n.is_finite() || n <= 0.0 {
                return Err(format!(
                    "invalid config key '{key}': must be finite and > 0"
                ));
            }
            Ok(Some(n))
        }
        None => Ok(None),
    }
}

/// Decode `s` as base58 and require exactly 32 bytes (a Solana pubkey).
pub(crate) fn validate_base58_32(s: &str) -> Result<(), ()> {
    match bs58::decode(s).into_vec() {
        Ok(bytes) if bytes.len() == 32 => Ok(()),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_market_is_valid_base58_32() {
        validate_base58_32(DEFAULT_MARKET).expect("bundled default market must be a valid pubkey");
    }
}
