//! Pure parsing and policy for Solana account rent inspection.

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Serialize;
use serde_json::{json, Value};

const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const MAX_ACCOUNT_DATA_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AccountRentConfig {
    pub rpc_url: String,
    pub commitment: String,
}

impl AccountRentConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let rpc_url = section
            .get("rpc_url")
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        validate_rpc_url(&rpc_url)?;

        let commitment = section
            .get("commitment")
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_else(|| "finalized".to_string());
        if !matches!(commitment.as_str(), "processed" | "confirmed" | "finalized") {
            return Err("commitment must be processed, confirmed, or finalized".to_string());
        }

        Ok(Self {
            rpc_url,
            commitment,
        })
    }
}

pub fn validate_pubkey(value: &str, field: &str) -> Result<(), String> {
    if value.len() < 32 || value.len() > 44 {
        return Err(format!("{field} must be a base58 Solana public key"));
    }
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| format!("{field} must be a base58 Solana public key"))?;
    if decoded.len() != 32 {
        return Err(format!("{field} must decode to exactly 32 bytes"));
    }
    Ok(())
}

pub fn validate_rpc_url(value: &str) -> Result<(), String> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err("rpc_url must not be empty or contain whitespace".to_string());
    }
    if value.contains('#') || value.contains('@') {
        return Err("rpc_url must not contain a fragment or user information".to_string());
    }
    let (scheme, remainder) = value
        .split_once("://")
        .ok_or_else(|| "rpc_url must be an absolute HTTP(S) URL".to_string())?;
    let authority = remainder
        .split(['/', '?'])
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| "rpc_url must include a host".to_string())?;
    let host = parse_host(authority)?;
    let loopback = matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    );
    if scheme.eq_ignore_ascii_case("https") || (scheme.eq_ignore_ascii_case("http") && loopback) {
        Ok(())
    } else {
        Err("rpc_url must use HTTPS, except loopback development endpoints".to_string())
    }
}

fn parse_host(authority: &str) -> Result<&str, String> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or_else(|| "rpc_url contains an invalid IPv6 host".to_string())?;
        let host = &bracketed[..close];
        validate_port(&bracketed[close + 1..])?;
        if host.is_empty() {
            return Err("rpc_url must include a host".to_string());
        }
        return Ok(host);
    }

    let (host, suffix) = authority.find(':').map_or((authority, ""), |index| {
        (&authority[..index], &authority[index..])
    });
    validate_port(suffix)?;
    if host.is_empty() || host.contains(':') {
        return Err("rpc_url contains an invalid host".to_string());
    }
    Ok(host)
}

fn validate_port(suffix: &str) -> Result<(), String> {
    if suffix.is_empty() {
        return Ok(());
    }
    let port = suffix
        .strip_prefix(':')
        .ok_or_else(|| "rpc_url contains invalid text after the host".to_string())?;
    let parsed = port
        .parse::<u16>()
        .map_err(|_| "rpc_url port must be an integer from 1 to 65535".to_string())?;
    if parsed == 0 {
        return Err("rpc_url port must be an integer from 1 to 65535".to_string());
    }
    Ok(())
}

pub fn account_request(address: &str, id: u8, commitment: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "getAccountInfo",
        "params": [address, {"commitment": commitment, "encoding": "base64"}]
    })
}

pub fn rent_request(data_len: usize, id: u8, commitment: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "getMinimumBalanceForRentExemption",
        "params": [data_len, {"commitment": commitment}]
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcAccount {
    pub owner: String,
    pub executable: bool,
    pub lamports: u64,
    pub data_len: usize,
}

pub fn parse_account_response(response: &Value, address: &str) -> Result<RpcAccount, String> {
    if let Some(error) = response.get("error") {
        return Err(format!("Solana RPC rejected account query: {error}"));
    }
    let value = response
        .pointer("/result/value")
        .ok_or_else(|| format!("account {address} was not found"))?;
    if value.is_null() {
        return Err(format!("account {address} was not found"));
    }
    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| "RPC account owner is missing".to_string())?
        .to_string();
    validate_pubkey(&owner, "RPC account owner")?;
    let executable = value
        .get("executable")
        .and_then(Value::as_bool)
        .ok_or_else(|| "RPC account executable flag is missing".to_string())?;
    let lamports = value
        .get("lamports")
        .and_then(Value::as_u64)
        .ok_or_else(|| "RPC account lamports are missing".to_string())?;
    let encoded = value
        .pointer("/data/0")
        .and_then(Value::as_str)
        .ok_or_else(|| "RPC account data must be base64 tuple form".to_string())?;
    let encoding = value
        .pointer("/data/1")
        .and_then(Value::as_str)
        .ok_or_else(|| "RPC account data encoding is missing".to_string())?;
    if encoding != "base64" {
        return Err("RPC account data encoding must be base64".to_string());
    }
    let data = BASE64
        .decode(encoded)
        .map_err(|_| "RPC account data is invalid base64".to_string())?;
    if data.len() > MAX_ACCOUNT_DATA_BYTES {
        return Err("RPC account data exceeds the 16 MiB safety limit".to_string());
    }
    Ok(RpcAccount {
        owner,
        executable,
        lamports,
        data_len: data.len(),
    })
}

pub fn parse_rent_response(response: &Value) -> Result<u64, String> {
    if let Some(error) = response.get("error") {
        return Err(format!("Solana RPC rejected rent query: {error}"));
    }
    response
        .get("result")
        .and_then(Value::as_u64)
        .ok_or_else(|| "RPC rent result must be a non-negative integer".to_string())
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct AccountRentReport {
    pub account_address: String,
    pub owner: String,
    pub executable: bool,
    pub data_len: usize,
    pub lamports: u64,
    pub minimum_rent_exempt_lamports: u64,
    pub rent_exempt: bool,
    pub surplus_lamports: u64,
    pub deficit_lamports: u64,
    pub risk_flags: Vec<String>,
}

pub fn build_report(address: &str, account: &RpcAccount, minimum: u64) -> AccountRentReport {
    let rent_exempt = account.lamports >= minimum;
    AccountRentReport {
        account_address: address.to_string(),
        owner: account.owner.clone(),
        executable: account.executable,
        data_len: account.data_len,
        lamports: account.lamports,
        minimum_rent_exempt_lamports: minimum,
        rent_exempt,
        surplus_lamports: account.lamports.saturating_sub(minimum),
        deficit_lamports: minimum.saturating_sub(account.lamports),
        risk_flags: if rent_exempt {
            Vec::new()
        } else {
            vec!["below_rent_exempt_minimum".to_string()]
        },
    }
}

pub fn render_report(report: &AccountRentReport) -> Result<String, String> {
    let output = serde_json::to_string_pretty(report)
        .map_err(|error| format!("failed to serialize account rent report: {error}"))?;
    if output.len() > 2_000 {
        return Err("account rent report exceeded the 2,000-byte limit".to_string());
    }
    Ok(output)
}
