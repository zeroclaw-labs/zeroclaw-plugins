//! Pure Solana token-risk analysis. This module has no WIT or WASM dependency;
//! host tests feed it mocked RPC/API payloads through the same path used by the
//! component shim.

use serde::Serialize;
use serde_json::{json, Value};

pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Green,
    Amber,
    Red,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskMetrics {
    pub token_program: String,
    pub top_holder_pct: Option<f64>,
    pub top_five_pct: Option<f64>,
    pub max_liquidity_usd: Option<f64>,
    pub markets: usize,
    pub token_2022_extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskReport {
    pub mint: String,
    pub level: RiskLevel,
    pub score: u16,
    pub reasons: Vec<String>,
    pub metrics: RiskMetrics,
    pub disclaimer: &'static str,
}

impl RiskReport {
    /// A deliberately compact response for an agent context window. Detailed
    /// raw provider responses are never echoed back.
    pub fn compact_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"level":"red","reasons":["report serialization failed"]}"#.to_string()
        })
    }
}

pub fn validate_mint(mint: &str) -> Result<(), String> {
    if mint.len() < 32 || mint.len() > 44 {
        return Err("mint must be a base58-encoded 32-byte Solana public key".to_string());
    }
    let decoded = bs58::decode(mint)
        .into_vec()
        .map_err(|_| "mint must be valid base58".to_string())?;
    if decoded.len() != 32 {
        return Err("mint must decode to exactly 32 bytes".to_string());
    }
    Ok(())
}

pub fn rpc_request(method: &str, params: Value, id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
}

pub fn analyze_responses(
    mint: &str,
    mint_account: &Value,
    token_supply: &Value,
    largest_accounts: &Value,
    dex_pairs: Option<&Value>,
) -> Result<RiskReport, String> {
    validate_mint(mint)?;

    let account = mint_account
        .pointer("/result/value")
        .ok_or_else(|| rpc_error("getAccountInfo", mint_account))?;
    if account.is_null() {
        return Err("mint account was not found".to_string());
    }
    let info = account
        .pointer("/data/parsed/info")
        .ok_or_else(|| "RPC did not return a parsed token mint account".to_string())?;
    let owner = account
        .get("owner")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let supply = parse_u128(
        token_supply
            .pointer("/result/value/amount")
            .and_then(Value::as_str)
            .ok_or_else(|| rpc_error("getTokenSupply", token_supply))?,
        "token supply",
    )?;
    if supply == 0 {
        return Err("token supply is zero".to_string());
    }

    let balances = largest_accounts
        .pointer("/result/value")
        .and_then(Value::as_array)
        .ok_or_else(|| rpc_error("getTokenLargestAccounts", largest_accounts))?;
    let mut largest = Vec::with_capacity(balances.len());
    for item in balances {
        if let Some(amount) = item.get("amount").and_then(Value::as_str) {
            largest.push(parse_u128(amount, "largest account balance")?);
        }
    }
    largest.sort_unstable_by(|a, b| b.cmp(a));
    let top_holder_pct = largest.first().map(|v| percent(*v, supply));
    let top_five_sum = largest.iter().take(5).copied().sum::<u128>();
    let top_five_pct = (!largest.is_empty()).then(|| percent(top_five_sum, supply));

    let mint_authority = info.get("mintAuthority").filter(|v| !v.is_null());
    let freeze_authority = info.get("freezeAuthority").filter(|v| !v.is_null());
    let extensions = collect_extensions(account, info);
    let (markets, max_liquidity_usd) = liquidity_summary(dex_pairs);

    let mut score = 0u16;
    let mut reasons = Vec::new();

    match owner {
        TOKEN_PROGRAM => {}
        TOKEN_2022_PROGRAM => reasons.push("Token-2022 mint; extension review applied".to_string()),
        _ => {
            score += 60;
            reasons.push("account is not owned by a recognized Solana token program".to_string());
        }
    }

    if mint_authority.is_some() {
        score += 25;
        reasons.push("mint authority is still active".to_string());
    }
    if freeze_authority.is_some() {
        score += 30;
        reasons.push("freeze authority is still active".to_string());
    }

    for ext in &extensions {
        let normalized = ext.to_ascii_lowercase();
        if normalized.contains("permanentdelegate") || normalized.contains("permanent_delegate") {
            score += 35;
            reasons.push("permanent delegate can transfer or burn holder tokens".to_string());
        } else if normalized.contains("transferhook") || normalized.contains("transfer_hook") {
            score += 20;
            reasons.push("transfer hook can add external transfer rules".to_string());
        } else if normalized.contains("defaultaccountstate")
            || normalized.contains("default_account_state")
        {
            score += 15;
            reasons.push("default account state extension needs manual review".to_string());
        } else if normalized.contains("transferfee") || normalized.contains("transfer_fee") {
            score += 10;
            reasons.push("transfer fee extension is enabled".to_string());
        }
    }

    if let Some(pct) = top_holder_pct {
        if pct >= 50.0 {
            score += 35;
            reasons.push(format!("largest token account holds {pct:.1}% of supply"));
        } else if pct >= 20.0 {
            score += 15;
            reasons.push(format!("largest token account holds {pct:.1}% of supply"));
        }
    }
    if let Some(pct) = top_five_pct {
        if pct >= 80.0 {
            score += 25;
            reasons.push(format!("top five token accounts hold {pct:.1}% of supply"));
        } else if pct >= 50.0 {
            score += 12;
            reasons.push(format!("top five token accounts hold {pct:.1}% of supply"));
        }
    }

    match max_liquidity_usd {
        None => {
            // Missing liquidity is not a clean bill of health. Keep the result
            // at least amber so an upstream outage cannot turn an uncertain
            // token green.
            score += 25;
            reasons.push("no verifiable Solana DEX liquidity data".to_string());
        }
        Some(v) if v < 10_000.0 => {
            score += 25;
            reasons.push(format!("maximum observed DEX liquidity is only ${v:.0}"));
        }
        Some(v) if v < 100_000.0 => {
            score += 10;
            reasons.push(format!("maximum observed DEX liquidity is ${v:.0}"));
        }
        Some(_) => {}
    }

    if reasons.is_empty() {
        reasons.push("no configured high-risk signals were detected".to_string());
    }
    score = score.min(100);
    let level = if score >= 60 {
        RiskLevel::Red
    } else if score >= 25 {
        RiskLevel::Amber
    } else {
        RiskLevel::Green
    };

    Ok(RiskReport {
        mint: mint.to_string(),
        level,
        score,
        reasons,
        metrics: RiskMetrics {
            token_program: if owner == TOKEN_2022_PROGRAM {
                "token-2022".to_string()
            } else if owner == TOKEN_PROGRAM {
                "spl-token".to_string()
            } else {
                "unknown".to_string()
            },
            top_holder_pct,
            top_five_pct,
            max_liquidity_usd,
            markets,
            token_2022_extensions: extensions,
        },
        disclaimer:
            "Heuristic screening only; token accounts may share an owner and liquidity can change.",
    })
}

fn rpc_error(method: &str, payload: &Value) -> String {
    let detail = payload
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("missing result");
    format!("{method} RPC failed: {detail}")
}

fn parse_u128(value: &str, label: &str) -> Result<u128, String> {
    value
        .parse::<u128>()
        .map_err(|_| format!("invalid {label}"))
}

fn percent(value: u128, total: u128) -> f64 {
    (value as f64 / total as f64) * 100.0
}

fn collect_extensions(account: &Value, info: &Value) -> Vec<String> {
    let arrays = [
        account.pointer("/data/parsed/info/extensions"),
        account.pointer("/data/parsed/extensions"),
        info.get("extensions"),
    ];
    let mut out = Vec::new();
    for array in arrays.into_iter().flatten().filter_map(Value::as_array) {
        for ext in array {
            let name = ext
                .get("extension")
                .or_else(|| ext.get("extensionType"))
                .or_else(|| ext.get("type"))
                .and_then(Value::as_str)
                .or_else(|| ext.as_str());
            if let Some(name) = name {
                if !out.iter().any(|v| v == name) {
                    out.push(name.to_string());
                }
            }
        }
    }
    out.sort();
    out
}

fn liquidity_summary(payload: Option<&Value>) -> (usize, Option<f64>) {
    let Some(pairs) = payload
        .and_then(|v| v.get("pairs"))
        .and_then(Value::as_array)
    else {
        return (0, None);
    };
    let liquidities: Vec<f64> = pairs
        .iter()
        .filter(|pair| pair.get("chainId").and_then(Value::as_str) == Some("solana"))
        .filter_map(|pair| pair.pointer("/liquidity/usd").and_then(Value::as_f64))
        .filter(|v| v.is_finite() && *v >= 0.0)
        .collect();
    let max = liquidities.iter().copied().reduce(f64::max);
    (liquidities.len(), max)
}
