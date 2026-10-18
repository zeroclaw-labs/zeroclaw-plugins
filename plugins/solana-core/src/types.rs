//! Solana JSON-RPC types — hand-rolled serde structs matching the
//! Solana JSON-RPC wire format. No solana-sdk dependency.

use serde::{Deserialize, Serialize};

/// A Solana public key as base58 string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pubkey(pub String);

impl Pubkey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for Pubkey {
    fn from(s: String) -> Self {
        Pubkey(s)
    }
}

impl std::fmt::Display for Pubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// JSON-RPC request envelope.
#[derive(Debug, Serialize)]
pub struct JsonRpcRequest<T: Serialize> {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: Vec<T>,
}

impl<T: Serialize> JsonRpcRequest<T> {
    pub fn new(method: &str, params: Vec<T>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: 1,
            method: method.into(),
            params,
        }
    }
}

/// JSON-RPC response envelope.
#[derive(Debug, Deserialize)]
pub struct JsonRpcResponse<R> {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Option<R>,
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC error.
#[derive(Debug, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

/// getAccountInfo response.
#[derive(Debug, Deserialize)]
pub struct AccountInfo {
    pub lamports: u64,
    pub owner: String,
    pub data: Vec<String>,       // base64-encoded
    pub executable: bool,
    pub rent_epoch: u64,
}

/// getTokenSupply response.
#[derive(Debug, Deserialize)]
pub struct TokenSupply {
    pub amount: String,           // raw amount as decimal string
    pub decimals: u8,
    pub supply: String,           // same as amount
}

/// getTokenLargestAccounts entry.
#[derive(Debug, Deserialize)]
pub struct LargestAccount {
    pub address: String,
    pub amount: String,           // raw decimal string
    pub decimals: u8,
}

/// getProgramAccounts response item.
#[derive(Debug, Deserialize)]
pub struct ProgramAccount {
    pub pubkey: String,
    pub account: AccountInfo,
}

/// Simplified token account (SPL Token / Token-2022).
#[derive(Debug, Clone)]
pub struct MintAccount {
    pub address: String,
    pub decimals: u8,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    pub supply: u64,
    pub is_initialized: bool,
}

/// Holder concentration analysis.
#[derive(Debug, Clone, Serialize)]
pub struct HolderConcentration {
    pub total_holders: usize,
    pub top1_pct: f64,
    pub top5_pct: f64,
    pub top10_pct: f64,
}

/// Token-2022 extensions summary (relevant fields only).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Token2022Extensions {
    pub has_transfer_hook: bool,
    pub has_transfer_fee: bool,
    pub has_permanent_delegate: bool,
    pub has_non_transferable: bool,
    pub has_interest_bearing: bool,
}

/// Overall risk assessment for a token mint.
#[derive(Debug, Clone, Serialize)]
pub struct TokenRiskReport {
    pub mint: String,
    pub risk_level: RiskLevel,
    pub reasons: Vec<String>,
    pub score: u32,               // 0-100: 0=lowest risk
    pub supply: u64,
    pub decimals: u8,
    pub concentration: Option<HolderConcentration>,
    pub extensions: Token2022Extensions,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Green,
    Amber,
    Red,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Green => write!(f, "GREEN"),
            RiskLevel::Amber => write!(f, "AMBER"),
            RiskLevel::Red => write!(f, "RED"),
        }
    }
}

/// Result shaped to ~200 tokens for LLM consumption.
#[derive(Debug, Serialize)]
pub struct ShapedOutput {
    pub summary: String,
    pub structured: serde_json::Value,
}

impl ShapedOutput {
    pub fn text(summary: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            structured: serde_json::Value::Null,
        }
    }

    pub fn json(summary: impl Into<String>, value: serde_json::Value) -> Self {
        Self {
            summary: summary.into(),
            structured: value,
        }
    }
}