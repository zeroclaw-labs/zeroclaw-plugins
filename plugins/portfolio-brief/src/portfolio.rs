//! Pure portfolio parsing and rendering core.
//!
//! This module has no WASM or network dependency. Host tests supply captured
//! JSON responses and exercise the exact validation and formatting logic used
//! by the component shim.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

use serde_json::{json, Value};

pub const SOL_MINT: &str = "So11111111111111111111111111111111111111112";
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;
const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const DEFAULT_PRICE_API_URL: &str = "https://api.jup.ag/price/v3";
const DEFAULT_MAX_POSITIONS: usize = 8;
const DEFAULT_MAX_PRICE_IDS: usize = 50;
const MAX_PRICE_IDS: usize = 50;
const MAX_TOKEN_ACCOUNTS: usize = 500;

#[derive(Debug, Clone, PartialEq)]
pub struct Holding {
    pub mint: String,
    pub amount: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Price {
    pub usd_price: f64,
    pub change_24h: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PortfolioConfig {
    pub rpc_url: String,
    pub price_api_url: String,
    pub jupiter_api_key: String,
    pub max_positions: usize,
    pub max_price_ids: usize,
    pub labels: HashMap<String, String>,
}

impl PortfolioConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let rpc_url = secure_endpoint(section.get("rpc_url"), DEFAULT_RPC_URL, "rpc_url")?;
        let price_api_url = secure_endpoint(
            section.get("price_api_url"),
            DEFAULT_PRICE_API_URL,
            "price_api_url",
        )?;
        let jupiter_api_key = section
            .get("jupiter_api_key")
            .map(|v| v.trim())
            .unwrap_or_default()
            .to_string();
        if jupiter_api_key.len() > 256
            || jupiter_api_key
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(
                "jupiter_api_key must not contain whitespace or control characters".to_string(),
            );
        }
        let max_positions = bounded_usize(
            section.get("max_positions"),
            DEFAULT_MAX_POSITIONS,
            1,
            15,
            "max_positions",
        )?;
        let max_price_ids = bounded_usize(
            section.get("max_price_ids"),
            DEFAULT_MAX_PRICE_IDS,
            1,
            MAX_PRICE_IDS,
            "max_price_ids",
        )?;
        let labels = parse_labels(section.get("token_labels"))?;

        Ok(Self {
            rpc_url,
            price_api_url,
            jupiter_api_key,
            max_positions,
            max_price_ids,
            labels,
        })
    }
}

pub fn validate_pubkey(pubkey: &str) -> Result<(), String> {
    if pubkey.len() < 32 || pubkey.len() > 44 {
        return Err("wallet must be a 32-byte base58 Solana public key".to_string());
    }
    let bytes = bs58::decode(pubkey)
        .into_vec()
        .map_err(|_| "wallet must be a 32-byte base58 Solana public key".to_string())?;
    if bytes.len() != 32 {
        return Err("wallet must be a 32-byte base58 Solana public key".to_string());
    }
    Ok(())
}

pub fn balance_request(wallet: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [wallet, {"commitment": "confirmed"}]
    })
}

pub fn token_accounts_request(wallet: &str, program_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountsByOwner",
        "params": [
            wallet,
            {"programId": program_id},
            {"commitment": "confirmed", "encoding": "jsonParsed"}
        ]
    })
}

pub fn parse_balance_response(response: &Value) -> Result<u64, String> {
    reject_rpc_error(response)?;
    response
        .pointer("/result/value")
        .and_then(Value::as_u64)
        .ok_or_else(|| "getBalance response is missing result.value".to_string())
}

pub fn parse_token_accounts_response(response: &Value) -> Result<Vec<Holding>, String> {
    reject_rpc_error(response)?;
    let accounts = response
        .pointer("/result/value")
        .and_then(Value::as_array)
        .ok_or_else(|| "token account response is missing result.value".to_string())?;
    if accounts.len() > MAX_TOKEN_ACCOUNTS {
        return Err(format!(
            "token account response exceeds the safety limit of {MAX_TOKEN_ACCOUNTS} accounts"
        ));
    }

    let mut holdings = Vec::new();
    for account in accounts {
        let Some(mint) = account
            .pointer("/account/data/parsed/info/mint")
            .and_then(Value::as_str)
        else {
            continue;
        };
        if validate_pubkey(mint).is_err() {
            continue;
        }
        let Some(amount) = account
            .pointer("/account/data/parsed/info/tokenAmount/uiAmountString")
            .and_then(Value::as_str)
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v > 0.0)
        else {
            continue;
        };
        holdings.push(Holding {
            mint: mint.to_string(),
            amount,
        });
    }
    Ok(holdings)
}

pub fn merge_holdings(lamports: u64, tokens: impl IntoIterator<Item = Holding>) -> Vec<Holding> {
    let mut totals = BTreeMap::<String, f64>::new();
    if lamports > 0 {
        totals.insert(SOL_MINT.to_string(), lamports as f64 / LAMPORTS_PER_SOL);
    }
    for holding in tokens {
        if holding.amount.is_finite() && holding.amount > 0.0 {
            *totals.entry(holding.mint).or_default() += holding.amount;
        }
    }
    totals
        .into_iter()
        .map(|(mint, amount)| Holding { mint, amount })
        .collect()
}

pub fn select_price_mints(holdings: &[Holding], max_price_ids: usize) -> Vec<String> {
    let mut selected = holdings.to_vec();
    selected.sort_by(|a, b| {
        if a.mint == SOL_MINT {
            Ordering::Less
        } else if b.mint == SOL_MINT {
            Ordering::Greater
        } else {
            b.amount.partial_cmp(&a.amount).unwrap_or(Ordering::Equal)
        }
    });
    selected
        .into_iter()
        .take(max_price_ids.min(MAX_PRICE_IDS))
        .map(|holding| holding.mint)
        .collect()
}

pub fn price_url(base: &str, mints: &[String]) -> Result<String, String> {
    if mints.is_empty() {
        return Err("at least one mint is required for a price request".to_string());
    }
    if mints.len() > MAX_PRICE_IDS {
        return Err(format!(
            "price request supports at most {MAX_PRICE_IDS} mints"
        ));
    }
    for mint in mints {
        validate_pubkey(mint)?;
    }
    let separator = if base.contains('?') { '&' } else { '?' };
    Ok(format!("{base}{separator}ids={}", mints.join(",")))
}

pub fn parse_price_response(response: &Value) -> Result<HashMap<String, Price>, String> {
    if let Some(message) = response.get("error").and_then(error_message) {
        return Err(format!("price API error: {message}"));
    }
    let object = response
        .as_object()
        .ok_or_else(|| "price API response must be an object".to_string())?;
    if object.contains_key("code") {
        if let Some(message) = object.get("message").and_then(Value::as_str) {
            return Err(format!("price API error: {message}"));
        }
    }
    let mut prices = HashMap::new();
    for (mint, item) in object {
        if validate_pubkey(mint).is_err() {
            continue;
        }
        let Some(usd_price) = item
            .get("usdPrice")
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite() && *v >= 0.0)
        else {
            continue;
        };
        let change_24h = item
            .get("priceChange24h")
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite());
        prices.insert(
            mint.clone(),
            Price {
                usd_price,
                change_24h,
            },
        );
    }
    Ok(prices)
}

pub fn render_brief(
    wallet: &str,
    holdings: &[Holding],
    prices: &HashMap<String, Price>,
    labels: &HashMap<String, String>,
    max_positions: usize,
) -> String {
    struct Row<'a> {
        holding: &'a Holding,
        price: Option<Price>,
        value: Option<f64>,
    }

    let mut rows: Vec<Row<'_>> = holdings
        .iter()
        .map(|holding| {
            let price = prices.get(&holding.mint).copied();
            let value = price.map(|p| p.usd_price * holding.amount);
            Row {
                holding,
                price,
                value,
            }
        })
        .collect();
    rows.sort_by(|a, b| match (a.value, b.value) {
        (Some(a), Some(b)) => b.partial_cmp(&a).unwrap_or(Ordering::Equal),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => b
            .holding
            .amount
            .partial_cmp(&a.holding.amount)
            .unwrap_or(Ordering::Equal),
    });

    let total: f64 = rows.iter().filter_map(|row| row.value).sum();
    let priced_count = rows.iter().filter(|row| row.value.is_some()).count();
    let shown = rows.len().min(max_positions.clamp(1, 15));
    let mut lines = vec![format!(
        "Solana portfolio {} · ${} priced across {}/{} assets",
        short_key(wallet),
        format_usd(total),
        priced_count,
        rows.len()
    )];

    for row in rows.iter().take(shown) {
        let label = asset_label(&row.holding.mint, labels);
        let amount = format_amount(row.holding.amount);
        match (row.price, row.value) {
            (Some(price), Some(value)) => {
                let change = price
                    .change_24h
                    .map(|v| format!("{v:+.2}%"))
                    .unwrap_or_else(|| "24h n/a".to_string());
                lines.push(format!(
                    "• {label}: {amount} · ${} · {change}",
                    format_usd(value)
                ));
            }
            _ => lines.push(format!("• {label}: {amount} · price unavailable")),
        }
    }
    if rows.len() > shown {
        lines.push(format!("• +{} more assets hidden", rows.len() - shown));
    }
    lines.push("Read-only snapshot; no transaction was built or signed.".to_string());
    lines.join("\n")
}

fn reject_rpc_error(response: &Value) -> Result<(), String> {
    if let Some(error) = response.get("error") {
        let message = error_message(error).unwrap_or_else(|| error.to_string());
        return Err(format!("Solana RPC error: {message}"));
    }
    Ok(())
}

fn error_message(value: &Value) -> Option<String> {
    value
        .get("message")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| value.as_str().map(str::to_string))
}

fn secure_endpoint(
    configured: Option<&String>,
    default: &str,
    name: &str,
) -> Result<String, String> {
    let value = configured
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .unwrap_or(default);
    if !value.starts_with("https://")
        || value[8..].is_empty()
        || value[8..].contains('@')
        || value.contains('#')
        || value.chars().any(char::is_whitespace)
    {
        return Err(format!(
            "{name} must be an HTTPS URL without credentials, fragments, or whitespace"
        ));
    }
    Ok(value.trim_end_matches('?').to_string())
}

fn bounded_usize(
    configured: Option<&String>,
    default: usize,
    min: usize,
    max: usize,
    name: &str,
) -> Result<usize, String> {
    let Some(raw) = configured.map(|v| v.trim()).filter(|v| !v.is_empty()) else {
        return Ok(default);
    };
    let value = raw
        .parse::<usize>()
        .map_err(|_| format!("{name} must be an integer between {min} and {max}"))?;
    if !(min..=max).contains(&value) {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(value)
}

fn parse_labels(configured: Option<&String>) -> Result<HashMap<String, String>, String> {
    let mut labels = HashMap::new();
    labels.insert(SOL_MINT.to_string(), "SOL".to_string());
    let Some(raw) = configured.map(|v| v.trim()).filter(|v| !v.is_empty()) else {
        return Ok(labels);
    };
    for entry in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let (mint, label) = entry
            .split_once(':')
            .ok_or_else(|| "token_labels entries must use mint:LABEL".to_string())?;
        validate_pubkey(mint.trim())?;
        let label = label.trim();
        if label.is_empty()
            || label.len() > 16
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(
                "token label must be 1-16 ASCII letters, numbers, '-', '_', or '.'".to_string(),
            );
        }
        labels.insert(mint.trim().to_string(), label.to_string());
    }
    Ok(labels)
}

fn asset_label(mint: &str, labels: &HashMap<String, String>) -> String {
    labels.get(mint).cloned().unwrap_or_else(|| short_key(mint))
}

fn short_key(value: &str) -> String {
    if value.len() <= 12 {
        return value.to_string();
    }
    format!("{}…{}", &value[..6], &value[value.len() - 4..])
}

fn format_amount(value: f64) -> String {
    if value >= 1_000_000.0 {
        format!("{:.2}M", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.2}K", value / 1_000.0)
    } else if value >= 1.0 {
        format!("{value:.4}")
    } else {
        format!("{value:.6}")
    }
}

fn format_usd(value: f64) -> String {
    let value = if value.abs() < 0.005 { 0.0 } else { value };
    if value >= 1_000_000.0 {
        format!("{:.2}M", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.2}K", value / 1_000.0)
    } else {
        format!("{value:.2}")
    }
}
