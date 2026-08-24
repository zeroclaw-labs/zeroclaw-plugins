//! Pure request validation and response policy for slot-leaders.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::{json, Value};

const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const MAX_OUTPUT_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub rpc_url: String,
    pub commitment: String,
}

impl RpcConfig {
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

pub fn validate_identifier(value: &str, field: &str, decoded_len: usize) -> Result<(), String> {
    if value.len() < 32 || value.len() > 88 {
        return Err(format!("{field} must be a base58 Solana identifier"));
    }
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| format!("{field} must be a base58 Solana identifier"))?;
    if decoded.len() != decoded_len {
        return Err(format!(
            "{field} must decode to exactly {decoded_len} bytes"
        ));
    }
    Ok(())
}

pub const fn expected_decoded_len() -> usize {
    32
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
    let host = authority
        .trim_start_matches('[')
        .split([']', ':'])
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| "rpc_url must include a valid host".to_string())?;
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

pub fn rpc_request(slot: u64, id: u8, commitment: &str) -> Value {
    let argument = slot.to_string();
    let _ = commitment;
    let params = json!([
        argument.parse::<u64>().expect("slot is generated from u64"),
        10
    ]);
    json!({"jsonrpc":"2.0", "id":id, "method":"getSlotLeaders", "params":params})
}

pub fn parse_rpc_response(response: &Value) -> Result<Value, String> {
    if let Some(error) = response.get("error") {
        return Err(format!("Solana RPC rejected getSlotLeaders: {error}"));
    }
    let result = response
        .get("result")
        .filter(|value| !value.is_null())
        .ok_or_else(|| "RPC response is missing a non-null result".to_string())?;
    Ok(result.clone())
}

#[derive(Debug, Serialize, PartialEq)]
pub struct RpcReport {
    pub tool: &'static str,
    pub rpc_method: &'static str,
    pub query: String,
    pub result: Value,
}

pub fn build_report(query: String, result: Value) -> RpcReport {
    RpcReport {
        tool: "slot-leaders",
        rpc_method: "getSlotLeaders",
        query,
        result,
    }
}

pub fn render_report(report: &RpcReport) -> Result<String, String> {
    let output = serde_json::to_string(report)
        .map_err(|error| format!("failed to serialize RPC report: {error}"))?;
    if output.len() > MAX_OUTPUT_BYTES {
        return Err("RPC report exceeds the 8 KiB output safety limit".to_string());
    }
    Ok(output)
}
