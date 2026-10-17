//! Pure Token-2022 risk assessment core.
//! No wasm dependencies — testable on host with `cargo test`.

use serde::{Deserialize, Serialize};

/// Risk level output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub tier: String,       // "green" | "amber" | "red"
    pub score: u8,          // 0-100
    pub flags: Vec<String>,
    pub summary: String,
}

/// Token extensions that indicate elevated risk
#[derive(Debug, Default, Clone)]
struct TokenExtensions {
    mintable: bool,
    freeze_authority: bool,
    permanent_delegate: Option<String>,
    transfer_hook: Option<String>,
    transfer_fee: Option<u16>,
    transfer_fee_config: Option<String>,
}

/// Holder concentration snapshot
#[derive(Debug, Default)]
struct HolderProfile {
    total_holders: usize,
    top_10_pct: f64,
    has_suspicious_concentration: bool,
}

/// DAS API response for token supply
#[derive(Debug, Deserialize)]
pub struct TokenSupply {
    #[serde(rename = "supply")]
    pub supply: Option<String>,
    #[serde(rename = "decimals")]
    pub decimals: Option<u8>,
}

/// DAS API getTokenAccounts response
#[derive(Debug, Deserialize)]
pub struct TokenAccountsResponse {
    #[serde(rename = "value")]
    pub value: Option<Vec<TokenAccount>>,
    #[serde(rename = "errors")]
    pub errors: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct TokenAccount {
    #[serde(rename = "account")]
    pub account: TokenAccountData,
}

#[derive(Debug, Deserialize)]
pub struct TokenAccountData {
    #[serde(rename = "data")]
    pub data: Option<TokenAccountParsedData>,
    #[serde(rename = "pubkey")]
    pub pubkey: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenAccountParsedData {
    #[serde(rename = "parsed")]
    pub parsed: Option<TokenAccountInfo>,
}

#[derive(Debug, Deserialize)]
pub struct TokenAccountInfo {
    #[serde(rename = "info")]
    pub info: Option<TokenInfo>,
}

#[derive(Debug, Deserialize)]
pub struct TokenInfo {
    #[serde(rename = "tokenAmount")]
    pub token_amount: Option<TokenAmount>,
}

#[derive(Debug, Deserialize)]
pub struct TokenAmount {
    #[serde(rename = "amount")]
    pub amount: Option<String>,
    #[serde(rename = "uiAmount")]
    pub ui_amount: Option<f64>,
}

/// Token metadata from DAS
#[derive(Debug, Deserialize)]
pub struct TokenMetadata {
    #[serde(rename = "items")]
    pub items: Option<Vec<TokenMetadataItem>>,
}

#[derive(Debug, Deserialize)]
pub struct TokenMetadataItem {
    #[serde(rename = "mint")]
    pub mint: Option<String>,
    #[serde(rename = "name")]
    pub name: Option<String>,
    #[serde(rename = "symbol")]
    pub symbol: Option<String>,
}

/// RPC response: getAccountInfo for mint
#[derive(Debug, Deserialize)]
pub struct MintAccountInfo {
    #[serde(rename = "result")]
    pub result: Option<AccountResult>,
}

#[derive(Debug, Deserialize)]
pub struct AccountResult {
    #[serde(rename = "value")]
    pub value: Option<AccountValue>,
}

#[derive(Debug, Deserialize)]
pub struct AccountValue {
    #[serde(rename = "data")]
    pub data: Option<serde_json::Value>,
    #[serde(rename = "owner")]
    pub owner: Option<String>,
    #[serde(rename = "lamports")]
    pub lamports: Option<u64>,
}

/// High-level risk assessment for a mint address.
/// Uses the DAS API (digital-assets-schema) to check:
/// - Mint/freeze authority (Token-2022 extensions)
/// - Holder concentration
/// - Transfer hooks, transfer fees, permanent delegate
/// - Supply and decimals
pub fn assess_risk(mint: &str, rpc_url: &str) -> RiskAssessment {
    let mut flags = Vec::new();
    let mut score: i32 = 100;

    // Step 1: Get mint account info via getAccountInfo
    let mint_info = fetch_mint_info(mint, rpc_url);
    if let Some(ref info) = mint_info {
        check_mint_authority(info, &mut flags, &mut score);
        check_freeze_authority(info, &mut flags, &mut score);
        check_token_extensions(info, &mut flags, &mut score);
    } else {
        flags.push("Could not fetch mint account — may be invalid or deleted".to_string());
        score -= 40;
    }

    // Step 2: Get holder profile via DAS getTokenAccounts
    let holders = fetch_holders(mint, rpc_url);
    check_holder_concentration(&holders, &mut flags, &mut score);

    // Step 3: Check if supply is 0 (dead token)
    if let Some(ref info) = mint_info {
        if let Some(supply) = &info.supply {
            if supply == "0" || supply == "\\"0\\"" {
                flags.push("Supply is 0 — token may be deactivated or a honeypot".to_string());
                score -= 30;
            }
        }
    }

    // Clamp score
    score = score.max(0).min(100) as u8;

    let tier = if score >= 75 {
        "green".to_string()
    } else if score >= 40 {
        "amber".to_string()
    } else {
        "red".to_string()
    };

    let summary = build_summary(mint, &flags, score, &tier);

    RiskAssessment { tier, score, flags, summary }
}

fn check_mint_authority(info: &MintInfo, flags: &mut Vec<String>, score: &mut i32) {
    if info.mint_authority.is_some() {
        flags.push("Mint authority is set — tokens can be minted infinitely".to_string());
        *score -= 15;
    }
}

fn check_freeze_authority(info: &MintInfo, flags: &mut Vec<String>, score: &mut i32) {
    if info.freeze_authority.is_some() {
        flags.push("Freeze authority is set — tokens can be frozen".to_string());
        *score -= 10;
    }
}

fn check_token_extensions(info: &MintInfo, flags: &mut Vec<String>, score: &mut i32) {
    if let Some(ref delegate) = info.permanent_delegate {
        flags.push(format!("Permanent delegate set for: {} — can burn or transfer any tokens", &delegate[..8.min(delegate.len())]));
        *score -= 40;
    }
    if info.transfer_hook.is_some() {
        flags.push("Transfer hook detected — custom logic executes on every transfer".to_string());
        *score -= 20;
    }
    if let Some(fee) = info.transfer_fee {
        if fee > 0 {
            flags.push(format!("Transfer fee of {} bps ({}%) — tokens have a tax on every trade", fee, fee as f64 / 100.0));
            *score -= 15;
        }
    }
    if info.mintable {
        flags.push("Token is mintable — new supply can be created at any time".to_string());
        *score -= 20;
    }
}

fn check_holder_concentration(holders: &[Holder], flags: &mut Vec<String>, score: &mut i32) {
    if holders.is_empty() {
        flags.push("No holders found — may be pre-launch or airdropped dust".to_string());
        *score -= 10;
        return;
    }
    let total: u64 = holders.iter().map(|h| h.amount).sum();
    if total == 0 { return; }

    let top10: u64 = holders.iter().take(1).map(|h| h.amount).sum::<u64>();
    let concentration = top10 as f64 / total as f64;
    if concentration > 0.90 {
        flags.push(format!("Top holder controls {:.0}% of supply — extreme concentration risk", concentration * 100.0));
        *score -= 25;
    } else if concentration > 0.70 {
        flags.push(format!("Top holder controls {:.0}% of supply — high concentration", concentration * 100.0));
        *score -= 15;
    }
    if holders.len() < 10 {
        flags.push(format!("Only {} holders — low distribution, may be easily manipulated", holders.len()));
        *score -= 10;
    }
}

fn build_summary(mint: &str, flags: &[String], score: u8, tier: &str) -> String {
    let short = &mint[..8.min(mint.len())];
    let emoji = match tier {
        "green" => "🟢",
        "amber" => "🟡",
        _ => "🔴",
    };
    let flag_list: Vec<&str> = flags.iter().map(|s| s.as_str()).collect();
    let flag_str = if flag_list.is_empty() {
        "No risk flags detected.".to_string()
    } else {
        flag_list.join("; ")
    };
    format!(
        "{} Risk profile for {}...: {}/100 ({})
{}",
        emoji, short, score, tier.to_uppercase(), flag_str
    )
}

// --- RPC calls ---

#[derive(Debug, Clone)]
pub struct MintInfo {
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    pub permanent_delegate: Option<String>,
    pub transfer_hook: Option<String>,
    pub transfer_fee: Option<u16>,
    pub supply: Option<String>,
    pub decimals: Option<u8>,
    pub mintable: bool,
}

pub fn fetch_mint_info(mint: &str, rpc_url: &str) -> Option<MintInfo> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            mint,
            { "encoding": "jsonParsed" }
        ]
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().ok()?;

    let resp = client.post(rpc_url)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send().ok()?;

    let text = resp.text().ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&text).ok()?;

    let value = parsed.pointer("/result/value")?;
    let data = value.get("data")?;
    let parsed_data = data.get("parsed")?;
    let info = parsed_data.get("info")?;

    let mint_authority = info.get("mintAuthority").and_then(|v| v.as_str().map(String::from));
    let freeze_authority = info.get("freezeAuthority").and_then(|v| v.as_str().map(String::from));
    let supply = info.get("supply").and_then(|v| v.as_str().map(String::from));
    let decimals = info.get("decimals").and_then(|v| v.as_u64()).map(|d| d as u8);
    let is_initialized = info.get("isInitialized").and_then(|v| v.as_bool()).unwrap_or(false);
    let mintable = info.get("mintable").and_then(|v| v.as_bool()).unwrap_or(false);

    // Check Token-2022 extensions
    let extensions = info.get("extensions").and_then(|v| v.as_array());
    let mut permanent_delegate = None;
    let mut transfer_hook = None;
    let mut transfer_fee = None;

    if let Some(exts) = extensions {
        for ext in exts {
            if let Some(ext_obj) = ext.as_object() {
                let extension_type = ext_obj.get("extension")?.as_str()?;
                match extension_type {
                    "PermanentDelegate" => {
                        permanent_delegate = ext_obj.get("state")
                            .and_then(|s| s.get("delegate"))
                            .and_then(|d| d.as_str())
                            .map(String::from);
                    }
                    "TransferHook" => {
                        transfer_hook = ext_obj.get("state")
                            .and_then(|s| s.get("authority"))
                            .and_then(|a| a.as_str())
                            .map(String::from);
                    }
                    "TransferFeeConfig" => {
                        transfer_fee = ext_obj.get("state")
                            .and_then(|s| s.get("transferFeeBasisPoints"))
                            .and_then(|f| f.as_u64())
                            .map(|f| f as u16);
                    }
                    _ => {}
                }
            }
        }
    }

    Some(MintInfo {
        mint_authority,
        freeze_authority,
        permanent_delegate,
        transfer_hook,
        transfer_fee,
        supply,
        decimals,
        mintable,
    })
}

#[derive(Debug, Clone)]
pub struct Holder {
    pub address: String,
    pub amount: u64,
}

pub fn fetch_holders(mint: &str, rpc_url: &str) -> Vec<Holder> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccounts",
        "params": [
            mint,
            { "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" },
            { "encoding": "jsonParsed", "commitment": "confirmed" }
        ]
    });

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let resp = match client.post(rpc_url)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
    {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let text = match resp.text() {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    let parsed: serde_json::Value = match serde_json::from_str(&text) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let accounts = parsed.pointer("/result/value")?.as_array().cloned().unwrap_or_default();

    let mut holders: Vec<Holder> = Vec::new();
    for account in accounts {
        let address = account.get("pubkey")?.as_str()?.to_string();
        let amount_opt = account
            .pointer("/account/data/parsed/info/tokenAmount/uiAmount")
            .and_then(|v| v.as_f64())
            .map(|f| (f * 1000.0) as u64);

        if let Some(amount) = amount_opt {
            if amount > 0 {
                holders.push(Holder { address, amount });
            }
        }
    }

    holders.sort_by(|a, b| b.amount.cmp(&a.amount));
    holders
}
