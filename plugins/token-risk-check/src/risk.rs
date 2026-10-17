//! Pure parser and conservative risk policy for `token-risk-check`.
//!
//! RPC and index responses are untrusted input. This module accepts JSON
//! values, validates the account owner/type, bounds all collections, and never
//! executes or renders instructions found in remote data.

use std::collections::HashMap;

use serde_json::Value;

pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

const MAX_EXTENSIONS: usize = 64;
const MAX_REASONS: usize = 6;

#[derive(Clone, Debug)]
pub struct RiskConfig {
    pub warn_top1_bps: u64,
    pub high_top1_bps: u64,
    pub warn_top5_bps: u64,
    pub high_top5_bps: u64,
    pub min_liquidity_usd: f64,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            warn_top1_bps: 2_000,
            high_top1_bps: 5_000,
            warn_top5_bps: 5_000,
            high_top5_bps: 8_000,
            min_liquidity_usd: 10_000.0,
        }
    }
}

impl RiskConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let defaults = Self::default();
        Self {
            warn_top1_bps: bounded_u64(section, "warn_top1_bps", defaults.warn_top1_bps, 1, 9_999),
            high_top1_bps: bounded_u64(section, "high_top1_bps", defaults.high_top1_bps, 1, 10_000),
            warn_top5_bps: bounded_u64(section, "warn_top5_bps", defaults.warn_top5_bps, 1, 9_999),
            high_top5_bps: bounded_u64(section, "high_top5_bps", defaults.high_top5_bps, 1, 10_000),
            min_liquidity_usd: section
                .get("min_liquidity_usd")
                .and_then(|value| value.parse::<f64>().ok())
                .filter(|value| value.is_finite() && *value >= 0.0 && *value <= 1_000_000_000.0)
                .unwrap_or(defaults.min_liquidity_usd),
        }
        .normalized()
    }

    fn normalized(mut self) -> Self {
        self.high_top1_bps = self.high_top1_bps.max(self.warn_top1_bps);
        self.high_top5_bps = self.high_top5_bps.max(self.warn_top5_bps);
        self
    }
}

fn bounded_u64(
    section: &HashMap<String, String>,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> u64 {
    section
        .get(key)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (*value >= min) && (*value <= max))
        .unwrap_or(default)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rating {
    Green,
    Amber,
    Red,
}

impl Rating {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "GREEN",
            Self::Amber => "AMBER",
            Self::Red => "RED",
        }
    }

    fn raise(&mut self, next: Self) {
        if rank(next) > rank(*self) {
            *self = next;
        }
    }
}

fn rank(rating: Rating) -> u8 {
    match rating {
        Rating::Green => 0,
        Rating::Amber => 1,
        Rating::Red => 2,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionFinding {
    pub name: String,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Liquidity {
    Skipped,
    Unknown,
    Indexed { usd: f64, pairs: usize },
}

#[derive(Clone, Debug, PartialEq)]
pub struct RiskReport {
    pub rating: Rating,
    pub program: &'static str,
    pub mint_authority_active: bool,
    pub freeze_authority_active: bool,
    pub top1_bps: Option<u64>,
    pub top5_bps: Option<u64>,
    pub extensions: Vec<ExtensionFinding>,
    pub liquidity: Liquidity,
    pub reasons: Vec<String>,
}

impl RiskReport {
    pub fn render_compact(&self) -> String {
        let authority = format!(
            "mint={} freeze={}",
            active(self.mint_authority_active),
            active(self.freeze_authority_active)
        );
        let concentration = match (self.top1_bps, self.top5_bps) {
            (Some(top1), Some(top5)) => {
                format!("top1={} top5={}", pct(top1), pct(top5))
            }
            _ => "concentration=unknown".to_string(),
        };
        let extensions = if self.extensions.is_empty() {
            "none".to_string()
        } else {
            self.extensions
                .iter()
                .take(8)
                .map(|item| match &item.detail {
                    Some(detail) => format!("{}({detail})", item.name),
                    None => item.name.clone(),
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        let liquidity = match self.liquidity {
            Liquidity::Skipped => "liquidity=skipped".to_string(),
            Liquidity::Unknown => "liquidity=unknown".to_string(),
            Liquidity::Indexed { usd, pairs } => {
                format!("liquidity=${} pairs={pairs}", compact_usd(usd))
            }
        };
        let reasons = if self.reasons.is_empty() {
            "no configured warnings".to_string()
        } else {
            self.reasons.join("; ")
        };

        format!(
            "{} heuristic | {} | {} | {} | {} | extensions={} | reasons={}. \
             Read-only preflight; largest accounts are a holder-concentration proxy, not an audit.",
            self.rating.as_str(),
            self.program,
            authority,
            concentration,
            liquidity,
            extensions,
            reasons
        )
    }
}

fn active(value: bool) -> &'static str {
    if value {
        "active"
    } else {
        "revoked"
    }
}

fn pct(bps: u64) -> String {
    format!("{}.{:02}%", bps / 100, bps % 100)
}

fn compact_usd(value: f64) -> String {
    if value >= 1_000_000.0 {
        format!("{:.1}m", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1}k", value / 1_000.0)
    } else {
        format!("{value:.0}")
    }
}

pub fn validate_mint(mint: &str) -> Result<(), String> {
    let bytes = bs58::decode(mint)
        .into_vec()
        .map_err(|_| "mint must be a valid base58 Solana address".to_string())?;
    if bytes.len() != 32 {
        return Err("mint must decode to exactly 32 bytes".to_string());
    }
    Ok(())
}

pub fn analyze(
    mint: &str,
    account_response: &Value,
    largest_response: &Value,
    market_response: Option<&Value>,
    config: &RiskConfig,
) -> Result<RiskReport, String> {
    validate_mint(mint)?;

    let value = account_response
        .pointer("/result/value")
        .ok_or_else(|| "mint account does not exist or RPC response is incomplete".to_string())?;
    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| "mint account owner is missing".to_string())?;
    let program = match owner {
        TOKEN_PROGRAM_ID => "SPL Token",
        TOKEN_2022_PROGRAM_ID => "Token-2022",
        _ => return Err("account is not owned by SPL Token or Token-2022".to_string()),
    };

    let parsed = value
        .pointer("/data/parsed")
        .ok_or_else(|| "RPC did not return jsonParsed mint data".to_string())?;
    if parsed.get("type").and_then(Value::as_str) != Some("mint") {
        return Err("address is token-owned but is not a mint account".to_string());
    }
    let info = parsed
        .get("info")
        .and_then(Value::as_object)
        .ok_or_else(|| "parsed mint info is missing".to_string())?;

    let supply = info
        .get("supply")
        .and_then(as_u128)
        .ok_or_else(|| "mint supply is missing or invalid".to_string())?;
    let mint_authority_active = authority_active(info.get("mintAuthority"));
    let freeze_authority_active = authority_active(info.get("freezeAuthority"));

    let amounts = parse_largest_amounts(largest_response);
    let (top1_bps, top5_bps) = concentration(&amounts, supply);
    let extensions = parse_extensions(info.get("extensions"));
    let liquidity = parse_liquidity(mint, market_response);

    let mut rating = Rating::Green;
    let mut reasons = Vec::new();
    if mint_authority_active {
        warn(
            &mut rating,
            &mut reasons,
            Rating::Amber,
            "mint authority active",
        );
    }
    if freeze_authority_active {
        warn(
            &mut rating,
            &mut reasons,
            Rating::Amber,
            "freeze authority active",
        );
    }

    for extension in &extensions {
        match canonical(&extension.name).as_str() {
            "permanentdelegate" => warn(
                &mut rating,
                &mut reasons,
                Rating::Red,
                "permanent delegate can transfer or burn balances",
            ),
            "defaultaccountstate" if extension.detail.as_deref() == Some("frozen") => warn(
                &mut rating,
                &mut reasons,
                Rating::Red,
                "new token accounts default to frozen",
            ),
            "transferhook" => warn(
                &mut rating,
                &mut reasons,
                Rating::Amber,
                "custom transfer hook executes on transfers",
            ),
            "transferfeeconfig" => warn(
                &mut rating,
                &mut reasons,
                Rating::Amber,
                "protocol transfer fee configured",
            ),
            "mintcloseauthority" => warn(
                &mut rating,
                &mut reasons,
                Rating::Amber,
                "mint close authority configured",
            ),
            "pausable" | "pausableconfig" => warn(
                &mut rating,
                &mut reasons,
                Rating::Amber,
                "token transfers may be paused",
            ),
            "nontransferable" => warn(
                &mut rating,
                &mut reasons,
                Rating::Amber,
                "token is non-transferable",
            ),
            "scaleduiamount" | "scaleduiamountconfig" | "interestbearingconfig" => warn(
                &mut rating,
                &mut reasons,
                Rating::Amber,
                "displayed amount can change independently of raw balance",
            ),
            _ => {}
        }
    }

    if let Some(top1) = top1_bps {
        if top1 >= config.high_top1_bps {
            warn(
                &mut rating,
                &mut reasons,
                Rating::Red,
                "largest token account exceeds high threshold",
            );
        } else if top1 >= config.warn_top1_bps {
            warn(
                &mut rating,
                &mut reasons,
                Rating::Amber,
                "largest token account is concentrated",
            );
        }
    }
    if let Some(top5) = top5_bps {
        if top5 >= config.high_top5_bps {
            warn(
                &mut rating,
                &mut reasons,
                Rating::Red,
                "top five token accounts exceed high threshold",
            );
        } else if top5 >= config.warn_top5_bps {
            warn(
                &mut rating,
                &mut reasons,
                Rating::Amber,
                "top five token accounts are concentrated",
            );
        }
    }

    if let Liquidity::Indexed { usd, pairs } = liquidity {
        if pairs == 0 {
            warn(
                &mut rating,
                &mut reasons,
                Rating::Amber,
                "no indexed Solana liquidity pairs",
            );
        } else if usd < config.min_liquidity_usd {
            warn(
                &mut rating,
                &mut reasons,
                Rating::Amber,
                "indexed liquidity is below configured minimum",
            );
        }
    }

    Ok(RiskReport {
        rating,
        program,
        mint_authority_active,
        freeze_authority_active,
        top1_bps,
        top5_bps,
        extensions,
        liquidity,
        reasons,
    })
}

fn warn(rating: &mut Rating, reasons: &mut Vec<String>, level: Rating, message: &str) {
    rating.raise(level);
    if reasons.len() < MAX_REASONS && !reasons.iter().any(|value| value == message) {
        reasons.push(message.to_string());
    }
}

fn authority_active(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(authority)) if !authority.is_empty())
}

fn parse_largest_amounts(response: &Value) -> Vec<u128> {
    response
        .pointer("/result/value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(20)
        .filter_map(|entry| entry.get("amount").and_then(as_u128))
        .collect()
}

fn concentration(amounts: &[u128], supply: u128) -> (Option<u64>, Option<u64>) {
    if supply == 0 || amounts.is_empty() {
        return (None, None);
    }
    let top1 = ratio_bps(amounts[0], supply);
    let top5_sum = amounts
        .iter()
        .take(5)
        .copied()
        .fold(0u128, u128::saturating_add);
    (Some(top1), Some(ratio_bps(top5_sum, supply)))
}

fn ratio_bps(amount: u128, supply: u128) -> u64 {
    amount
        .saturating_mul(10_000)
        .checked_div(supply)
        .unwrap_or(0)
        .min(10_000) as u64
}

fn parse_extensions(value: Option<&Value>) -> Vec<ExtensionFinding> {
    let Some(extensions) = value.and_then(Value::as_array) else {
        return Vec::new();
    };

    extensions
        .iter()
        .take(MAX_EXTENSIONS)
        .filter_map(|extension| {
            let name = ["extension", "extensionType", "type"]
                .iter()
                .find_map(|key| extension.get(*key).and_then(Value::as_str))?
                .to_string();
            let normalized = canonical(&name);
            let detail = match normalized.as_str() {
                "transferfeeconfig" => find_key(extension, "transferFeeBasisPoints")
                    .and_then(as_u64)
                    .map(|bps| format!("{bps}bps")),
                "transferhook" => find_key(extension, "programId")
                    .and_then(Value::as_str)
                    .map(short_address),
                "defaultaccountstate" => find_key(extension, "state")
                    .and_then(Value::as_str)
                    .map(|state| state.to_ascii_lowercase()),
                _ => None,
            };
            Some(ExtensionFinding { name, detail })
        })
        .collect()
}

fn find_key<'a>(value: &'a Value, wanted: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => {
            if let Some(found) = map.get(wanted) {
                return Some(found);
            }
            map.values().find_map(|child| find_key(child, wanted))
        }
        Value::Array(items) => items
            .iter()
            .take(MAX_EXTENSIONS)
            .find_map(|child| find_key(child, wanted)),
        _ => None,
    }
}

fn canonical(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn short_address(value: &str) -> String {
    if value.len() <= 12 {
        return value.to_string();
    }
    format!("{}...{}", &value[..4], &value[value.len() - 4..])
}

fn parse_liquidity(mint: &str, response: Option<&Value>) -> Liquidity {
    let Some(response) = response else {
        return Liquidity::Unknown;
    };
    if response
        .get("_tokenRiskCheckSkipped")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Liquidity::Skipped;
    }
    let Some(pairs) = response.get("pairs").and_then(Value::as_array) else {
        return Liquidity::Unknown;
    };

    let mut usd = 0.0;
    let mut count = 0usize;
    for pair in pairs.iter().take(100) {
        if pair.get("chainId").and_then(Value::as_str) != Some("solana") {
            continue;
        }
        let base = pair.pointer("/baseToken/address").and_then(Value::as_str);
        let quote = pair.pointer("/quoteToken/address").and_then(Value::as_str);
        if base != Some(mint) && quote != Some(mint) {
            continue;
        }
        if let Some(value) = pair.pointer("/liquidity/usd").and_then(as_f64) {
            if value.is_finite() && value >= 0.0 {
                usd += value;
                count += 1;
            }
        }
    }
    Liquidity::Indexed { usd, pairs: count }
}

fn as_u128(value: &Value) -> Option<u128> {
    value
        .as_str()
        .and_then(|raw| raw.parse::<u128>().ok())
        .or_else(|| value.as_u64().map(u128::from))
}

fn as_u64(value: &Value) -> Option<u64> {
    value
        .as_str()
        .and_then(|raw| raw.parse::<u64>().ok())
        .or_else(|| value.as_u64())
}

fn as_f64(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|raw| raw.parse::<f64>().ok()))
}
