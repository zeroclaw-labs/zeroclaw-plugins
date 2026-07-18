//! Pure lending-health parsing and policy. No wasm, no HTTP, no I/O.
//! Host tests exercise this module directly with `cargo test`.

use std::collections::HashMap;

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
