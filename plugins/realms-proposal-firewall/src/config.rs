use std::{collections::HashMap, error::Error, fmt};

use crate::pubkey::Pubkey;

pub const DEFAULT_MAX_TRANSACTIONS: usize = 32;
pub const HARD_MAX_TRANSACTIONS: usize = 64;
pub const DEFAULT_MAX_INSTRUCTIONS: usize = 64;
pub const HARD_MAX_INSTRUCTIONS: usize = 128;
pub const DEFAULT_LARGE_OUTFLOW_BPS: u16 = 2_500;
pub const DEFAULT_CRITICAL_OUTFLOW_BPS: u16 = 9_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub rpc_url: String,
    pub expected_genesis_hash: Pubkey,
    pub governance_program_ids: Vec<Pubkey>,
    pub allowed_destination_owners: Vec<Pubkey>,
    pub allowed_mints: Vec<Pubkey>,
    pub max_transactions: usize,
    pub max_instructions: usize,
    pub large_outflow_bps: u16,
    pub critical_outflow_bps: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    message: String,
}

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ConfigError {}

impl Config {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, ConfigError> {
        const KEYS: [&str; 9] = [
            "rpc_url",
            "expected_genesis_hash",
            "governance_program_ids",
            "allowed_destination_owners",
            "allowed_mints",
            "max_transactions",
            "max_instructions",
            "large_outflow_bps",
            "critical_outflow_bps",
        ];
        if let Some(key) = section.keys().find(|key| !KEYS.contains(&key.as_str())) {
            return Err(ConfigError::new(format!(
                "unknown configuration key: {key}"
            )));
        }

        let rpc_url = required(section, "rpc_url")?;
        validate_https_url(rpc_url)?;

        let expected_genesis_hash = required(section, "expected_genesis_hash")?
            .parse()
            .map_err(|e| ConfigError::new(format!("invalid expected_genesis_hash: {e}")))?;

        let governance_program_ids = match section.get("governance_program_ids") {
            None => vec![crate::pubkey::spl_governance_program_id()],
            Some(value) => parse_pubkey_csv("governance_program_ids", value, false)?,
        };
        let allowed_destination_owners = section
            .get("allowed_destination_owners")
            .map(|value| parse_pubkey_csv("allowed_destination_owners", value, true))
            .transpose()?
            .unwrap_or_default();
        let allowed_mints = section
            .get("allowed_mints")
            .map(|value| parse_pubkey_csv("allowed_mints", value, true))
            .transpose()?
            .unwrap_or_default();

        let max_transactions = parse_bounded(
            section,
            "max_transactions",
            DEFAULT_MAX_TRANSACTIONS,
            1,
            HARD_MAX_TRANSACTIONS,
        )?;
        let max_instructions = parse_bounded(
            section,
            "max_instructions",
            DEFAULT_MAX_INSTRUCTIONS,
            1,
            HARD_MAX_INSTRUCTIONS,
        )?;
        let large_outflow_bps = parse_bounded(
            section,
            "large_outflow_bps",
            DEFAULT_LARGE_OUTFLOW_BPS as usize,
            0,
            10_000,
        )? as u16;
        let critical_outflow_bps = parse_bounded(
            section,
            "critical_outflow_bps",
            DEFAULT_CRITICAL_OUTFLOW_BPS as usize,
            0,
            10_000,
        )? as u16;

        if large_outflow_bps > critical_outflow_bps {
            return Err(ConfigError::new(
                "large_outflow_bps must be less than or equal to critical_outflow_bps",
            ));
        }

        Ok(Self {
            rpc_url: rpc_url.to_owned(),
            expected_genesis_hash,
            governance_program_ids,
            allowed_destination_owners,
            allowed_mints,
            max_transactions,
            max_instructions,
            large_outflow_bps,
            critical_outflow_bps,
        })
    }
}

fn required<'a>(section: &'a HashMap<String, String>, key: &str) -> Result<&'a str, ConfigError> {
    section
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ConfigError::new(format!("missing required configuration: {key}")))
}

fn validate_https_url(value: &str) -> Result<(), ConfigError> {
    if value != value.trim()
        || value
            .chars()
            .any(|c| c.is_ascii_control() || c.is_whitespace())
        || value.contains('#')
    {
        return Err(ConfigError::new("rpc_url must be a valid HTTPS URL"));
    }

    let rest = value
        .strip_prefix("https://")
        .ok_or_else(|| ConfigError::new("rpc_url must use HTTPS"))?;
    let authority = rest
        .split(['/', '?'])
        .next()
        .filter(|authority| !authority.is_empty())
        .ok_or_else(|| ConfigError::new("rpc_url must include a host"))?;

    if authority.contains('@') || authority.starts_with('.') || authority.ends_with('.') {
        return Err(ConfigError::new("rpc_url contains an invalid authority"));
    }
    if authority.starts_with('[') {
        let end = authority
            .find(']')
            .ok_or_else(|| ConfigError::new("rpc_url contains an invalid IPv6 host"))?;
        authority[1..end]
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| ConfigError::new("rpc_url contains an invalid IPv6 host"))?;
        validate_port(&authority[end + 1..])?;
    } else {
        let mut parts = authority.split(':');
        let host = parts.next().unwrap_or_default();
        let port = parts.next();
        if host.is_empty() || parts.next().is_some() {
            return Err(ConfigError::new("rpc_url contains an invalid host"));
        }
        if host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }) {
            return Err(ConfigError::new("rpc_url contains an invalid host"));
        }
        if let Some(port) = port {
            validate_port(&format!(":{port}"))?;
        }
    }

    Ok(())
}

fn validate_port(suffix: &str) -> Result<(), ConfigError> {
    if suffix.is_empty() {
        return Ok(());
    }
    let port = suffix
        .strip_prefix(':')
        .filter(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| ConfigError::new("rpc_url contains an invalid port"))?;
    let _ = port;
    Ok(())
}

fn parse_pubkey_csv(key: &str, value: &str, allow_empty: bool) -> Result<Vec<Pubkey>, ConfigError> {
    if value.trim().is_empty() {
        return if allow_empty {
            Ok(Vec::new())
        } else {
            Err(ConfigError::new(format!("{key} must not be empty")))
        };
    }

    let mut parsed = Vec::new();
    for item in value.split(',') {
        let item = item.trim();
        if item.is_empty() {
            return Err(ConfigError::new(format!("{key} contains an empty entry")));
        }
        let pubkey = item
            .parse()
            .map_err(|e| ConfigError::new(format!("invalid {key} entry: {e}")))?;
        if parsed.contains(&pubkey) {
            return Err(ConfigError::new(format!(
                "{key} contains a duplicate entry"
            )));
        }
        parsed.push(pubkey);
    }
    Ok(parsed)
}

fn parse_bounded(
    section: &HashMap<String, String>,
    key: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, ConfigError> {
    let Some(raw) = section.get(key) else {
        return Ok(default);
    };
    if raw != raw.trim() || raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ConfigError::new(format!("{key} must be an integer")));
    }
    let value = raw
        .parse::<usize>()
        .map_err(|_| ConfigError::new(format!("{key} is out of range")))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(ConfigError::new(format!(
            "{key} must be between {minimum} and {maximum}"
        )));
    }
    Ok(value)
}
