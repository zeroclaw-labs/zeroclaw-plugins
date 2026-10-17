//! Pure, host-testable Solana token risk assessment.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;

const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

#[derive(Debug, Clone)]
pub struct RiskConfig {
    pub rpc_url: String,
    pub dex_api_base: String,
    pub max_top1_pct: f64,
    pub max_top10_pct: f64,
    pub min_liquidity_usd: f64,
}

impl RiskConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let rpc_url = section
            .get("rpc_url")
            .cloned()
            .unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string());
        let dex_api_base = section
            .get("dex_api_base")
            .cloned()
            .unwrap_or_else(|| "https://api.dexscreener.com/token-pairs/v1/solana".to_string());
        require_https("rpc_url", &rpc_url)?;
        require_https("dex_api_base", &dex_api_base)?;
        Ok(Self {
            rpc_url,
            dex_api_base,
            max_top1_pct: parse_threshold(section, "max_top1_pct", 20.0)?,
            max_top10_pct: parse_threshold(section, "max_top10_pct", 50.0)?,
            min_liquidity_usd: parse_threshold(section, "min_liquidity_usd", 50_000.0)?,
        })
    }
}

fn require_https(name: &str, value: &str) -> Result<(), String> {
    if value.starts_with("https://") && !value.contains(char::is_whitespace) {
        Ok(())
    } else {
        Err(format!("{name} must be an https URL"))
    }
}

fn parse_threshold(
    section: &HashMap<String, String>,
    key: &str,
    default: f64,
) -> Result<f64, String> {
    let value = section
        .get(key)
        .map(|raw| {
            raw.parse::<f64>()
                .map_err(|_| format!("{key} must be a number"))
        })
        .transpose()?
        .unwrap_or(default);
    if value.is_finite() && value >= 0.0 {
        Ok(value)
    } else {
        Err(format!("{key} must be finite and non-negative"))
    }
}

pub trait RiskDataSource {
    fn mint_account(&self, mint: &str) -> Result<Value, String>;
    fn largest_accounts(&self, mint: &str) -> Result<Value, String>;
    fn liquidity(&self, mint: &str) -> Result<Value, String>;
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskReport {
    pub mint: String,
    pub verdict: &'static str,
    pub program: &'static str,
    pub mint_authority: bool,
    pub freeze_authority: bool,
    pub extensions: Vec<String>,
    pub top1_pct: f64,
    pub top10_pct: f64,
    pub liquidity: LiquiditySummary,
    pub reasons: Vec<String>,
    pub note: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiquiditySummary {
    pub status: &'static str,
    pub deepest_pool_usd: f64,
    pub pools: usize,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Green,
    Amber,
    Red,
}

pub fn assess_token(
    source: &impl RiskDataSource,
    mint: &str,
    config: &RiskConfig,
) -> Result<RiskReport, String> {
    validate_mint(mint)?;
    let account = source.mint_account(mint)?;
    let largest = source.largest_accounts(mint)?;
    let liquidity = source.liquidity(mint)?;
    assess_responses(mint, &account, &largest, &liquidity, config)
}

pub fn assess_responses(
    mint: &str,
    account: &Value,
    largest: &Value,
    liquidity: &Value,
    config: &RiskConfig,
) -> Result<RiskReport, String> {
    validate_mint(mint)?;
    let value = account
        .pointer("/result/value")
        .filter(|value| !value.is_null())
        .ok_or_else(|| "mint account was not found".to_string())?;
    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| "mint response has no owner".to_string())?;
    let program = match owner {
        TOKEN_PROGRAM => "spl-token",
        TOKEN_2022_PROGRAM => "token-2022",
        _ => return Err("account is not owned by an SPL token program".to_string()),
    };
    let info = value
        .pointer("/data/parsed/info")
        .ok_or_else(|| "RPC did not return parsed mint data".to_string())?;
    let supply = parse_u128(info.get("supply"), "mint supply")?;
    if supply == 0 {
        return Err("mint supply is zero; concentration cannot be assessed".to_string());
    }
    let mint_authority = non_null(info.get("mintAuthority"));
    let freeze_authority = non_null(info.get("freezeAuthority"));
    let extensions = extension_names(info.get("extensions"));

    let balances = largest
        .pointer("/result/value")
        .and_then(Value::as_array)
        .ok_or_else(|| "RPC did not return largest token accounts".to_string())?;
    if balances.is_empty() {
        return Err("RPC returned no token accounts".to_string());
    }
    let amounts = balances
        .iter()
        .map(|item| parse_u128(item.get("amount"), "largest-account amount"))
        .collect::<Result<Vec<_>, _>>()?;
    let top1_pct = percent(amounts[0], supply);
    let top10_pct = percent(amounts.iter().take(10).copied().sum(), supply);

    // DEX Screener's current token-pairs endpoint returns a top-level array.
    // Accept the legacy `{ "pairs": [...] }` envelope as well so operators
    // can point at a compatible proxy without changing the core.
    let pairs = liquidity
        .as_array()
        .or_else(|| liquidity.get("pairs").and_then(Value::as_array))
        .ok_or_else(|| "liquidity provider returned no pairs field".to_string())?;
    let solana_pairs = pairs.iter().filter(|pair| {
        pair.get("chainId").and_then(Value::as_str) == Some("solana")
            && (pair.pointer("/baseToken/address").and_then(Value::as_str) == Some(mint)
                || pair.pointer("/quoteToken/address").and_then(Value::as_str) == Some(mint))
    });
    let pool_values = solana_pairs
        .filter_map(|pair| pair.pointer("/liquidity/usd").and_then(Value::as_f64))
        .filter(|value| value.is_finite() && *value >= 0.0)
        .collect::<Vec<_>>();
    let deepest_pool_usd = pool_values.iter().copied().fold(0.0, f64::max);
    let pool_count = pool_values.len();

    let mut severity = Severity::Green;
    let mut reasons = Vec::new();
    if freeze_authority {
        raise(&mut severity, Severity::Red);
        reasons.push("freeze authority is enabled".to_string());
    }
    if mint_authority {
        raise(&mut severity, Severity::Amber);
        reasons.push("mint authority is enabled".to_string());
    }
    for extension in &extensions {
        let normalized = extension.to_ascii_lowercase();
        if normalized.contains("permanentdelegate")
            || normalized.contains("nontransferable")
            || normalized.contains("defaultaccountstate")
        {
            raise(&mut severity, Severity::Red);
            reasons.push(format!("high-impact Token-2022 extension: {extension}"));
        } else if normalized.contains("transferhook") || normalized.contains("transferfee") {
            raise(&mut severity, Severity::Amber);
            reasons.push(format!("review Token-2022 extension: {extension}"));
        }
    }
    if top1_pct > config.max_top1_pct {
        raise(&mut severity, Severity::Red);
        reasons.push(format!("largest account holds {top1_pct:.1}%"));
    }
    if top10_pct > config.max_top10_pct {
        raise(&mut severity, Severity::Amber);
        reasons.push(format!("top 10 accounts hold {top10_pct:.1}%"));
    }
    if pool_count == 0 || deepest_pool_usd == 0.0 {
        raise(&mut severity, Severity::Red);
        reasons.push("no Solana liquidity pool was observed".to_string());
    } else if deepest_pool_usd < config.min_liquidity_usd {
        raise(&mut severity, Severity::Amber);
        reasons.push(format!(
            "deepest observed pool is only ${deepest_pool_usd:.0}"
        ));
    }
    if reasons.is_empty() {
        reasons.push("no configured red or amber signal was observed".to_string());
    }

    Ok(RiskReport {
        mint: mint.to_string(),
        verdict: match severity {
            Severity::Green => "green",
            Severity::Amber => "amber",
            Severity::Red => "red",
        },
        program,
        mint_authority,
        freeze_authority,
        extensions,
        top1_pct: round2(top1_pct),
        top10_pct: round2(top10_pct),
        liquidity: LiquiditySummary {
            status: if pool_count == 0 { "not-observed" } else { "observed" },
            deepest_pool_usd: round2(deepest_pool_usd),
            pools: pool_count,
        },
        reasons,
        note: "Screening signal only; large accounts may be pools or custodians, and observed liquidity is not proof of locked liquidity.",
    })
}

fn validate_mint(mint: &str) -> Result<(), String> {
    if mint.len() < 32 || mint.len() > 44 {
        return Err("mint must be a 32-byte base58 Solana address".to_string());
    }
    let decoded = bs58::decode(mint)
        .into_vec()
        .map_err(|_| "mint must be valid base58".to_string())?;
    if decoded.len() != 32 {
        return Err("mint must decode to 32 bytes".to_string());
    }
    Ok(())
}

fn parse_u128(value: Option<&Value>, label: &str) -> Result<u128, String> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label} is missing"))?
        .parse::<u128>()
        .map_err(|_| format!("{label} is invalid"))
}

fn non_null(value: Option<&Value>) -> bool {
    value.is_some_and(|value| !value.is_null())
}

fn extension_names(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|extensions| {
            extensions
                .iter()
                .filter_map(|extension| {
                    extension
                        .get("extension")
                        .or_else(|| extension.get("extensionType"))
                        .or_else(|| extension.get("type"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn percent(amount: u128, supply: u128) -> f64 {
    (amount as f64 / supply as f64) * 100.0
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn raise(current: &mut Severity, candidate: Severity) {
    if candidate > *current {
        *current = candidate;
    }
}
