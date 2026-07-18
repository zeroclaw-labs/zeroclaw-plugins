//! Pure parsing and policy for Solana program authority inspection.

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Serialize;
use serde_json::{json, Value};

pub const UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
pub const LEGACY_LOADER_V1: &str = "BPFLoader1111111111111111111111111111111111";
pub const LEGACY_LOADER_V2: &str = "BPFLoader2111111111111111111111111111111111";
const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const PROGRAM_TAG: u32 = 2;
const PROGRAMDATA_TAG: u32 = 3;

#[derive(Debug, Clone)]
pub struct ProgramAuthorityConfig {
    pub rpc_url: String,
    pub commitment: String,
}

impl ProgramAuthorityConfig {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcAccount {
    pub owner: String,
    pub executable: bool,
    pub lamports: u64,
    pub data: Vec<u8>,
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
    if data.len() > 16 * 1024 * 1024 {
        return Err("RPC account data exceeds the 16 MiB safety limit".to_string());
    }
    Ok(RpcAccount {
        owner,
        executable,
        lamports,
        data,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramLoader {
    Upgradeable { programdata_address: String },
    Legacy,
    Unsupported,
}

pub fn inspect_program_account(account: &RpcAccount) -> Result<ProgramLoader, String> {
    if !account.executable {
        return Err("the supplied account is not executable".to_string());
    }
    match account.owner.as_str() {
        UPGRADEABLE_LOADER => {
            if account.data.len() != 36 || read_u32(&account.data, 0)? != PROGRAM_TAG {
                return Err("upgradeable program account has malformed loader state".to_string());
            }
            Ok(ProgramLoader::Upgradeable {
                programdata_address: bs58::encode(&account.data[4..36]).into_string(),
            })
        }
        LEGACY_LOADER_V1 | LEGACY_LOADER_V2 => Ok(ProgramLoader::Legacy),
        _ => Ok(ProgramLoader::Unsupported),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramDataState {
    pub deployment_slot: u64,
    pub upgrade_authority: Option<String>,
}

pub fn parse_programdata(account: &RpcAccount) -> Result<ProgramDataState, String> {
    if account.owner != UPGRADEABLE_LOADER {
        return Err("ProgramData owner does not match the upgradeable loader".to_string());
    }
    if account.executable {
        return Err("ProgramData account must not be executable".to_string());
    }
    if account.data.len() < 13 || read_u32(&account.data, 0)? != PROGRAMDATA_TAG {
        return Err("ProgramData account has malformed loader state".to_string());
    }
    let deployment_slot = read_u64(&account.data, 4)?;
    let upgrade_authority = match account.data[12] {
        0 => None,
        1 => {
            let bytes = account
                .data
                .get(13..45)
                .ok_or_else(|| "ProgramData authority bytes are truncated".to_string())?;
            Some(bs58::encode(bytes).into_string())
        }
        _ => return Err("ProgramData authority option tag is invalid".to_string()),
    };
    Ok(ProgramDataState {
        deployment_slot,
        upgrade_authority,
    })
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or_else(|| "loader state is truncated".to_string())?
        .try_into()
        .map_err(|_| "loader state is truncated".to_string())?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, String> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .ok_or_else(|| "loader state is truncated".to_string())?
        .try_into()
        .map_err(|_| "loader state is truncated".to_string())?;
    Ok(u64::from_le_bytes(bytes))
}

#[derive(Debug, Serialize)]
pub struct ProgramAuthorityReport {
    pub program_id: String,
    pub loader: String,
    pub executable: bool,
    pub upgradeable: Option<bool>,
    pub immutable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programdata_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_authority: Option<String>,
    pub risk_flags: Vec<String>,
}

pub fn build_report(
    program_id: &str,
    account: &RpcAccount,
    loader: &ProgramLoader,
    programdata: Option<&ProgramDataState>,
) -> Result<ProgramAuthorityReport, String> {
    match loader {
        ProgramLoader::Upgradeable {
            programdata_address,
        } => {
            let state = programdata.ok_or_else(|| "ProgramData state is required".to_string())?;
            let mutable = state.upgrade_authority.is_some();
            Ok(ProgramAuthorityReport {
                program_id: program_id.to_string(),
                loader: "bpf-upgradeable".to_string(),
                executable: account.executable,
                upgradeable: Some(mutable),
                immutable: Some(!mutable),
                programdata_address: Some(programdata_address.clone()),
                deployment_slot: Some(state.deployment_slot),
                upgrade_authority: state.upgrade_authority.clone(),
                risk_flags: if mutable {
                    vec!["upgrade_authority_present".to_string()]
                } else {
                    Vec::new()
                },
            })
        }
        ProgramLoader::Legacy => Ok(ProgramAuthorityReport {
            program_id: program_id.to_string(),
            loader: "bpf-legacy".to_string(),
            executable: account.executable,
            upgradeable: Some(false),
            immutable: Some(true),
            programdata_address: None,
            deployment_slot: None,
            upgrade_authority: None,
            risk_flags: Vec::new(),
        }),
        ProgramLoader::Unsupported => Ok(ProgramAuthorityReport {
            program_id: program_id.to_string(),
            loader: account.owner.clone(),
            executable: account.executable,
            upgradeable: None,
            immutable: None,
            programdata_address: None,
            deployment_slot: None,
            upgrade_authority: None,
            risk_flags: vec!["unsupported_loader_state".to_string()],
        }),
    }
}

pub fn render_report(report: &ProgramAuthorityReport) -> Result<String, String> {
    let output = serde_json::to_string_pretty(report)
        .map_err(|error| format!("failed to serialize program authority report: {error}"))?;
    if output.len() > 2_000 {
        return Err("program authority report exceeded the 2,000-byte limit".to_string());
    }
    Ok(output)
}
