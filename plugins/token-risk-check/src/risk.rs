//! Pure Solana token-risk core. No WIT, HTTP, or wasm-only dependency.
//! The component shim provides data clients; tests provide deterministic mocks.

use std::collections::HashMap;

use serde_json::{json, Map, Value};

const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

pub trait RpcClient {
    fn call(&self, method: &str, params: Value) -> Result<Value, String>;
}

pub trait LiquidityClient {
    fn token_report(&self, mint: &str) -> Result<Value, String>;
}

#[derive(Debug, Clone)]
pub struct RiskConfig {
    pub max_top_holder_percent: f64,
    pub max_top10_holder_percent: f64,
    pub min_liquidity_usd: f64,
    pub min_lp_locked_percent: f64,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            max_top_holder_percent: 20.0,
            max_top10_holder_percent: 60.0,
            min_liquidity_usd: 10_000.0,
            min_lp_locked_percent: 50.0,
        }
    }
}

impl RiskConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let defaults = Self::default();
        Self {
            max_top_holder_percent: parse_bounded(
                section.get("max_top_holder_percent"),
                defaults.max_top_holder_percent,
                0.0,
                100.0,
            ),
            max_top10_holder_percent: parse_bounded(
                section.get("max_top10_holder_percent"),
                defaults.max_top10_holder_percent,
                0.0,
                100.0,
            ),
            min_liquidity_usd: parse_bounded(
                section.get("min_liquidity_usd"),
                defaults.min_liquidity_usd,
                0.0,
                1_000_000_000_000.0,
            ),
            min_lp_locked_percent: parse_bounded(
                section.get("min_lp_locked_percent"),
                defaults.min_lp_locked_percent,
                0.0,
                100.0,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Green,
    Amber,
    Red,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LiquidityStatus {
    pub market_count: usize,
    pub total_liquidity_usd: f64,
    pub lp_provider_count: u64,
    pub locker_count: usize,
    pub locked_liquidity_percent: Option<f64>,
    pub rugged: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RiskReport {
    pub mint: String,
    pub verdict: Verdict,
    pub score: u8,
    pub symbol: Option<String>,
    pub supply: String,
    pub decimals: u8,
    pub program: String,
    pub mint_authority: AuthorityState,
    pub freeze_authority: AuthorityState,
    pub largest_holder_percent: Option<f64>,
    pub top10_holder_percent: Option<f64>,
    pub token2022_extensions: Vec<String>,
    pub liquidity: LiquidityStatus,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityState {
    None,
    Present,
}

impl RiskReport {
    pub fn to_compact_text(&self) -> String {
        let verdict = match self.verdict {
            Verdict::Green => "GREEN",
            Verdict::Amber => "AMBER",
            Verdict::Red => "RED",
        };
        let mint_short = short_key(&self.mint);
        let symbol = self.symbol.as_deref().unwrap_or("unknown");
        let largest = format_percent(self.largest_holder_percent);
        let top10 = format_percent(self.top10_holder_percent);
        let locked = format_percent(self.liquidity.locked_liquidity_percent);
        let extensions = if self.token2022_extensions.is_empty() {
            "none".to_string()
        } else {
            self.token2022_extensions.join(", ")
        };
        let reasons = if self.reasons.is_empty() {
            "No configured risk flags tripped.".to_string()
        } else {
            self.reasons.join("; ")
        };

        format!(
            "Token risk: {verdict} ({}/100)\nMint: {mint_short} ({symbol})\nProgram: {}\nSupply: {} decimals={}\nAuthorities: mint={}, freeze={}\nHolders: largest={largest}, top10={top10}\nLP: {} markets, ${:.2} liquidity, {} providers, {} lockers, locked={locked}\nToken-2022 extensions: {extensions}\nReasons: {reasons}",
            self.score,
            self.program,
            self.supply,
            self.decimals,
            authority_label(self.mint_authority),
            authority_label(self.freeze_authority),
            self.liquidity.market_count,
            self.liquidity.total_liquidity_usd,
            self.liquidity.lp_provider_count,
            self.liquidity.locker_count,
        )
    }
}

pub fn check_token_risk(
    rpc: &impl RpcClient,
    liquidity_client: &impl LiquidityClient,
    mint: &str,
    cfg: &RiskConfig,
) -> Result<RiskReport, String> {
    validate_mint(mint)?;
    let account = rpc.call(
        "getAccountInfo",
        json!([mint, { "encoding": "jsonParsed", "commitment": "confirmed" }]),
    )?;
    let value = required_object(account.get("value"), "mint account value")?;
    let parsed = value
        .get("data")
        .and_then(|v| v.get("parsed"))
        .ok_or_else(|| "mint account is missing parsed data".to_string())?;
    let info = required_object(parsed.get("info"), "mint account info")?;

    let program = required_string(value.get("owner"), "mint owner program")?.to_string();
    let supply_raw = required_string(info.get("supply"), "mint supply")?.to_string();
    let supply_amount = parse_u128(&supply_raw)
        .ok_or_else(|| "mint supply is not a valid unsigned integer".to_string())?;
    let decimals = required_u64(info.get("decimals"), "mint decimals")
        .and_then(|n| u8::try_from(n).map_err(|_| "mint decimals exceed u8".to_string()))?;
    let mint_authority = required_authority(info, "mintAuthority")?;
    let freeze_authority = required_authority(info, "freezeAuthority")?;
    let token2022_extensions = extensions(info)?;

    let market_report = liquidity_client.token_report(mint)?;
    let liquidity = parse_liquidity_report(&market_report, mint)?;
    let (largest_holder_percent, top10_holder_percent) =
        parse_holder_concentration(&market_report, supply_amount)?;
    let symbol = market_report
        .pointer("/tokenMeta/symbol")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut score = 0u8;
    let mut reasons = Vec::new();

    if !matches!(program.as_str(), TOKEN_PROGRAM | TOKEN_2022_PROGRAM) {
        score = score.saturating_add(60);
        reasons.push("mint is not owned by the canonical SPL Token or Token-2022 program".into());
    }
    if mint_authority == AuthorityState::Present {
        score = score.saturating_add(25);
        reasons.push("mint authority is still present".into());
    }
    if freeze_authority == AuthorityState::Present {
        score = score.saturating_add(20);
        reasons.push("freeze authority is still present".into());
    }
    if let Some(p) = largest_holder_percent {
        if p > 50.0 {
            score = score.saturating_add(45);
            reasons.push(format!("largest holder controls a severe share ({p:.2}%)"));
        } else if p > cfg.max_top_holder_percent {
            score = score.saturating_add(15);
            reasons.push(format!("largest holder exceeds configured cap ({p:.2}%)"));
        }
    }
    if let Some(p) = top10_holder_percent {
        if p > 80.0 {
            score = score.saturating_add(30);
            reasons.push(format!("top 10 holders control a severe share ({p:.2}%)"));
        } else if p > cfg.max_top10_holder_percent {
            score = score.saturating_add(15);
            reasons.push(format!("top 10 holders exceed configured cap ({p:.2}%)"));
        }
    }
    for ext in &token2022_extensions {
        let weight = extension_weight(ext);
        if weight > 0 {
            score = score.saturating_add(weight);
            reasons.push(format!("Token-2022 extension requires review: {ext}"));
        }
    }
    if supply_amount == 0 {
        score = score.saturating_add(10);
        reasons.push("mint reports zero supply".into());
    }
    if liquidity.rugged {
        score = 100;
        reasons.push("liquidity provider flags the token as rugged".into());
    } else if liquidity.market_count == 0 || liquidity.total_liquidity_usd == 0.0 {
        score = score.saturating_add(25);
        reasons.push("no verified LP market liquidity".into());
    } else {
        if liquidity.total_liquidity_usd < cfg.min_liquidity_usd {
            score = score.saturating_add(20);
            reasons.push(format!(
                "market liquidity is below configured floor (${:.2})",
                liquidity.total_liquidity_usd
            ));
        }
        match liquidity.locked_liquidity_percent {
            Some(p) if p < cfg.min_lp_locked_percent => {
                score = score.saturating_add(10);
                reasons.push(format!("reported locked LP liquidity is low ({p:.2}%)"));
            }
            None => {
                score = score.saturating_add(10);
                reasons.push("LP lock percentage is unavailable".into());
            }
            Some(_) => {}
        }
    }

    let verdict = if score >= 60 {
        Verdict::Red
    } else if score >= 10 {
        Verdict::Amber
    } else {
        Verdict::Green
    };

    Ok(RiskReport {
        mint: mint.to_string(),
        verdict,
        score: score.min(100),
        symbol,
        supply: supply_raw,
        decimals,
        program,
        mint_authority,
        freeze_authority,
        largest_holder_percent,
        top10_holder_percent,
        token2022_extensions,
        liquidity,
        reasons,
    })
}

fn parse_liquidity_report(report: &Value, mint: &str) -> Result<LiquidityStatus, String> {
    let reported_mint = required_string(report.get("mint"), "liquidity report mint")?;
    if reported_mint != mint {
        return Err("liquidity report mint does not match requested mint".to_string());
    }
    let total_liquidity_usd =
        required_number(report.get("totalMarketLiquidity"), "total market liquidity")?;
    let lp_provider_count = required_u64(report.get("totalLPProviders"), "LP provider count")?;
    let rugged = report
        .get("rugged")
        .and_then(Value::as_bool)
        .ok_or_else(|| "liquidity report is missing rugged flag".to_string())?;
    let markets = nullable_array(report.get("markets"), "liquidity markets")?;
    let locker_count = nullable_collection_len(report.get("lockers"), "liquidity lockers")?;

    let mut locked_usd = 0.0;
    let mut saw_locked_usd = false;
    for (index, market) in markets.iter().enumerate() {
        if let Some(value) = market.pointer("/lp/lpLockedUSD") {
            let amount = required_number(Some(value), &format!("market {index} locked LP USD"))?;
            locked_usd += amount;
            saw_locked_usd = true;
        }
    }
    let locked_liquidity_percent = if total_liquidity_usd > 0.0 && saw_locked_usd {
        Some(((locked_usd / total_liquidity_usd) * 100.0).clamp(0.0, 100.0))
    } else {
        None
    };

    Ok(LiquidityStatus {
        market_count: markets.len(),
        total_liquidity_usd,
        lp_provider_count,
        locker_count,
        locked_liquidity_percent,
        rugged,
    })
}

fn parse_holder_concentration(
    report: &Value,
    supply_amount: u128,
) -> Result<(Option<f64>, Option<f64>), String> {
    let rows = match report.get("topHolders") {
        Some(Value::Array(rows)) => rows,
        Some(Value::Null) if supply_amount == 0 => return Ok((None, None)),
        Some(Value::Null) => {
            return Err("holder report is unavailable for a non-zero supply".to_string())
        }
        _ => return Err("holder report is missing or malformed".to_string()),
    };
    if rows.is_empty() && supply_amount > 0 {
        return Err("holder report is empty for a non-zero supply".to_string());
    }

    let mut by_owner = HashMap::<String, u128>::new();
    for (index, row) in rows.iter().enumerate() {
        let owner = required_string(row.get("owner"), &format!("holder {index} owner"))?;
        let amount = required_u128(row.get("amount"), &format!("holder {index} amount"))?;
        let entry = by_owner.entry(owner.to_string()).or_default();
        *entry = entry
            .checked_add(amount)
            .ok_or_else(|| format!("holder {index} owner amount overflowed"))?;
    }

    let mut owner_amounts = by_owner.into_values().collect::<Vec<_>>();
    owner_amounts.sort_unstable_by(|left, right| right.cmp(left));
    let top_sum = owner_amounts
        .iter()
        .take(10)
        .try_fold(0u128, |sum, amount| sum.checked_add(*amount))
        .ok_or_else(|| "top-holder amount sum overflowed".to_string())?;
    if top_sum > supply_amount && supply_amount > 0 {
        return Err("top-holder amounts exceed mint supply".to_string());
    }

    Ok((
        percent_of(owner_amounts.first().copied(), supply_amount),
        percent_of(Some(top_sum), supply_amount),
    ))
}

fn parse_bounded(value: Option<&String>, fallback: f64, minimum: f64, maximum: f64) -> f64 {
    value
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && (*v >= minimum) && (*v <= maximum))
        .unwrap_or(fallback)
}

fn validate_mint(mint: &str) -> Result<(), String> {
    let decoded = bs58::decode(mint)
        .into_vec()
        .map_err(|_| "mint must be valid Solana base58".to_string())?;
    if decoded.len() != 32 {
        return Err("mint must decode to a 32-byte Solana public key".to_string());
    }
    Ok(())
}

fn required_object<'a>(
    value: Option<&'a Value>,
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{label} is missing or malformed"))
}

fn required_string<'a>(value: Option<&'a Value>, label: &str) -> Result<&'a str, String> {
    value
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{label} is missing or malformed"))
}

fn required_u64(value: Option<&Value>, label: &str) -> Result<u64, String> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{label} is missing or malformed"))
}

fn required_u128(value: Option<&Value>, label: &str) -> Result<u128, String> {
    value
        .and_then(|value| {
            value
                .as_u64()
                .map(u128::from)
                .or_else(|| value.as_str().and_then(parse_u128))
        })
        .ok_or_else(|| format!("{label} is missing or malformed"))
}

fn required_number(value: Option<&Value>, label: &str) -> Result<f64, String> {
    let number = value
        .and_then(Value::as_f64)
        .or_else(|| value.and_then(Value::as_str).and_then(|s| s.parse().ok()))
        .filter(|n: &f64| n.is_finite() && *n >= 0.0)
        .ok_or_else(|| format!("{label} is missing or malformed"))?;
    Ok(number)
}

fn required_authority(info: &Map<String, Value>, field: &str) -> Result<AuthorityState, String> {
    match info.get(field) {
        Some(Value::Null) => Ok(AuthorityState::None),
        Some(Value::String(value)) if value.is_empty() => Ok(AuthorityState::None),
        Some(Value::String(_)) => Ok(AuthorityState::Present),
        Some(_) => Err(format!("{field} is malformed")),
        None => Err(format!("{field} is missing")),
    }
}

fn nullable_array<'a>(value: Option<&'a Value>, label: &str) -> Result<&'a [Value], String> {
    match value {
        Some(Value::Array(values)) => Ok(values),
        Some(Value::Null) => Ok(&[]),
        _ => Err(format!("{label} is missing or malformed")),
    }
}

fn nullable_collection_len(value: Option<&Value>, label: &str) -> Result<usize, String> {
    match value {
        Some(Value::Object(values)) => Ok(values.len()),
        Some(Value::Array(values)) => Ok(values.len()),
        Some(Value::Null) => Ok(0),
        _ => Err(format!("{label} is missing or malformed")),
    }
}

fn parse_u128(value: &str) -> Option<u128> {
    value.parse::<u128>().ok()
}

fn percent_of(amount: Option<u128>, total: u128) -> Option<f64> {
    if total == 0 {
        return None;
    }
    amount.map(|n| (n as f64 / total as f64) * 100.0)
}

fn extensions(info: &Map<String, Value>) -> Result<Vec<String>, String> {
    match info.get("extensions") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .enumerate()
            .map(|(index, extension)| {
                extension
                    .get("extension")
                    .or_else(|| extension.get("type"))
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| format!("Token-2022 extension {index} is malformed"))
            })
            .collect(),
        Some(_) => Err("Token-2022 extensions are malformed".to_string()),
    }
}

fn extension_weight(name: &str) -> u8 {
    match name {
        "transferHook" | "permanentDelegate" => 30,
        "transferFeeConfig" | "nonTransferable" => 20,
        "confidentialTransferMint" | "confidentialTransferFeeConfig" => 15,
        "defaultAccountState" | "pausable" | "interestBearingConfig" | "scaledUiAmountConfig" => 10,
        "metadataPointer" | "tokenMetadata" | "groupPointer" | "groupMemberPointer"
        | "immutableOwner" | "memoTransfer" => 0,
        _ => 10,
    }
}

fn authority_label(state: AuthorityState) -> &'static str {
    match state {
        AuthorityState::None => "none",
        AuthorityState::Present => "present",
    }
}

fn format_percent(value: Option<f64>) -> String {
    value
        .map(|v| format!("{v:.2}%"))
        .unwrap_or_else(|| "unknown".to_string())
}

fn short_key(key: &str) -> String {
    if key.len() <= 12 {
        return key.to_string();
    }
    format!("{}...{}", &key[..4], &key[key.len() - 4..])
}
