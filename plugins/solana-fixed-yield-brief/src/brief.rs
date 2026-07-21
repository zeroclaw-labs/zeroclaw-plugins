//! Pure fixed-yield selection, quote-request, scoring, and rendering core.
//!
//! There is no wasm, HTTP, wallet, or signing dependency here. Host tests pass
//! fixture data through [`MarketDataSource`], exercising the same path used by
//! the component while guaranteeing that tests never touch a live endpoint.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use serde_json::{json, Value};

const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;
const SECONDS_PER_YEAR: f64 = 31_557_600.0;
const SOL_MINT: &str = "So11111111111111111111111111111111111111112";
const BULKSOL_MINT: &str = "BULKoNSGzxtCqzwTvg5hFJg8fx6dqZRScyXe5LYMfxrn";
const MAX_MARKETS_TO_QUOTE: usize = 8;
const MAX_VAULTS: usize = 256;
const MAX_SY_TOKENS: usize = 256;
const MAX_VENUES_PER_TYPE: usize = 16;
const MIN_HURDLE_APY_BPS: u32 = 100;
const MIN_EXECUTION_COST_LAMPORTS: u64 = 100_000;
const MIN_EXCESS_LAMPORTS: u64 = 1_000_000;
const MIN_TVL_MULTIPLE: u32 = 20;

fn default_hurdle_apy_bps() -> u32 {
    550
}

fn default_execution_cost_lamports() -> u64 {
    1_000_000
}

fn default_minimum_excess_lamports() -> u64 {
    1_000_000
}

fn default_minimum_tvl_multiple() -> u32 {
    20
}

fn default_max_results() -> u8 {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefArgs {
    /// SOL-denominated normalized notional used by Exponent's quote math.
    /// This is not proof that the caller can fund the underlying base-token leg.
    pub sol_notional_lamports: u64,
    #[serde(default = "default_hurdle_apy_bps")]
    pub hurdle_apy_bps: u32,
    #[serde(default = "default_execution_cost_lamports")]
    pub execution_cost_lamports: u64,
    #[serde(default = "default_minimum_excess_lamports")]
    pub minimum_excess_lamports: u64,
    #[serde(default = "default_minimum_tvl_multiple")]
    pub minimum_tvl_multiple: u32,
    #[serde(default = "default_max_results")]
    pub max_results: u8,
}

impl BriefArgs {
    fn validate(&self) -> Result<(), String> {
        if !(1_000_000..=10_000_000_000_000).contains(&self.sol_notional_lamports) {
            return Err("sol_notional_lamports must be between 0.001 and 10,000 SOL".to_string());
        }
        if !(MIN_HURDLE_APY_BPS..=100_000).contains(&self.hurdle_apy_bps) {
            return Err("hurdle_apy_bps must be between 100 and 100000".to_string());
        }
        if !(MIN_EXECUTION_COST_LAMPORTS..=self.sol_notional_lamports)
            .contains(&self.execution_cost_lamports)
        {
            return Err(
                "execution_cost_lamports must be at least 100000 and not exceed sol_notional_lamports"
                    .to_string(),
            );
        }
        if !(MIN_EXCESS_LAMPORTS..=self.sol_notional_lamports)
            .contains(&self.minimum_excess_lamports)
        {
            return Err(
                "minimum_excess_lamports must be at least 1000000 and not exceed sol_notional_lamports"
                    .to_string(),
            );
        }
        if !(MIN_TVL_MULTIPLE..=1_000).contains(&self.minimum_tvl_multiple) {
            return Err("minimum_tvl_multiple must be between 20 and 1000".to_string());
        }
        if !(1..=3).contains(&self.max_results) {
            return Err("max_results must be between 1 and 3".to_string());
        }
        Ok(())
    }
}

/// Fixed market-data boundary. The wasm shim implements it with fixed HTTPS
/// endpoints; host tests implement it with in-memory fixtures.
pub trait MarketDataSource {
    fn now_unix_seconds(&self) -> Result<u64, String>;
    fn vaults(&self) -> Result<Value, String>;
    fn sy_tokens(&self) -> Result<Value, String>;
    fn quote(&self, request: &Value) -> Result<Value, String>;
}

#[derive(Debug, Clone)]
pub struct BriefReport {
    pub output: String,
    pub markets_eligible: usize,
    pub quotes_attempted: usize,
    pub quotes_succeeded: usize,
}

#[derive(Debug, Deserialize)]
struct Vault {
    address: String,
    end_timestamp: String,
    pt_mint: String,
    sy_token: String,
    #[serde(default)]
    orderbooks: Vec<AddressRecord>,
    #[serde(default)]
    clmm_markets: Vec<AddressRecord>,
    pt_price: Option<f64>,
    implied_apy: Option<f64>,
    underlying_apy: Option<f64>,
    years_to_maturity: Option<f64>,
    tvl_in_base_token: Option<u64>,
    sy_exchange_rate: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct AddressRecord {
    address: String,
}

#[derive(Debug, Deserialize)]
struct SyToken {
    mint: String,
    quote_asset: Asset,
    underlying_asset: Asset,
}

#[derive(Debug, Deserialize)]
struct Asset {
    mint: String,
    decimals: u8,
}

#[derive(Debug, Clone)]
struct MarketRequest {
    label: String,
    underlying_mint: String,
    maturity: String,
    vault_address: String,
    pt_mint: String,
    orderbook_addresses: Vec<String>,
    clmm_addresses: Vec<String>,
    sy_exchange_rate: f64,
    pt_price: f64,
    implied_apy: f64,
    underlying_apy: f64,
    years_to_maturity: f64,
    tvl_lamports: u64,
}

#[derive(Debug, Deserialize)]
struct QuoteEnvelope {
    success: bool,
    data: Option<QuoteData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuoteData {
    total_out_amount: u64,
    total_fees: u64,
    is_legacy_market: bool,
    #[serde(default)]
    routes: Vec<QuoteRoute>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuoteRoute {
    source: String,
    source_address: String,
    in_amount: u64,
    out_amount: u64,
    fees: u64,
    percentage: f64,
}

#[derive(Debug, Clone)]
struct ScoredCandidate {
    label: String,
    underlying_mint: String,
    maturity: String,
    pt_mint: String,
    projected_profit_lamports: i128,
    excess_lamports: i128,
    quote_apy_bps: u32,
    underlying_apy_bps: u32,
    tvl_multiple: u64,
    fee_out_lamports: u64,
    route: &'static str,
    meets_excess_floor: bool,
}

pub fn generate_brief<S: MarketDataSource>(
    source: &S,
    args: &BriefArgs,
) -> Result<BriefReport, String> {
    args.validate()?;

    let now_unix_seconds = source
        .now_unix_seconds()
        .map_err(|e| format!("host clock unavailable: {e}"))?;

    let vaults_value = source
        .vaults()
        .map_err(|e| format!("vault catalog unavailable: {e}"))?;
    let sy_tokens_value = source
        .sy_tokens()
        .map_err(|e| format!("SY token catalog unavailable: {e}"))?;

    let vaults: Vec<Vault> = serde_json::from_value(vaults_value)
        .map_err(|_| "vault catalog schema mismatch".to_string())?;
    let sy_tokens: Vec<SyToken> = serde_json::from_value(sy_tokens_value)
        .map_err(|_| "SY token catalog schema mismatch".to_string())?;
    if vaults.len() > MAX_VAULTS {
        return Err(format!(
            "vault catalog exceeds the {MAX_VAULTS}-entry safety limit"
        ));
    }
    if sy_tokens.len() > MAX_SY_TOKENS {
        return Err(format!(
            "SY token catalog exceeds the {MAX_SY_TOKENS}-entry safety limit"
        ));
    }

    let mut markets = eligible_markets(vaults, sy_tokens, args, now_unix_seconds);
    let markets_eligible = markets.len();
    markets.truncate(MAX_MARKETS_TO_QUOTE);
    let quotes_attempted = markets.len();

    let mut scored = Vec::new();
    let mut quotes_succeeded = 0usize;
    for market in markets {
        let request = quote_request(&market, args.sol_notional_lamports);
        let Ok(value) = source.quote(&request) else {
            continue;
        };
        let Ok(envelope) = serde_json::from_value::<QuoteEnvelope>(value) else {
            continue;
        };
        if !envelope.success {
            continue;
        }
        let Some(data) = envelope.data else {
            continue;
        };
        if let Some(candidate) = score_quote(&market, data, args) {
            quotes_succeeded += 1;
            scored.push(candidate);
        }
    }

    scored.sort_by(|a, b| {
        b.excess_lamports
            .cmp(&a.excess_lamports)
            .then_with(|| b.quote_apy_bps.cmp(&a.quote_apy_bps))
    });
    scored.truncate(args.max_results as usize);

    if quotes_attempted > 0 && quotes_succeeded == 0 {
        return Err(format!(
            "UNPROVEN: 0/{quotes_attempted} attempted quotes were coherent across {markets_eligible} eligible catalog markets"
        ));
    }

    Ok(BriefReport {
        output: render_brief(
            &scored,
            args,
            markets_eligible,
            quotes_succeeded,
            quotes_attempted,
        ),
        markets_eligible,
        quotes_attempted,
        quotes_succeeded,
    })
}

fn eligible_markets(
    vaults: Vec<Vault>,
    sy_tokens: Vec<SyToken>,
    args: &BriefArgs,
    now_unix_seconds: u64,
) -> Vec<MarketRequest> {
    let sy_by_mint: HashMap<String, SyToken> = sy_tokens
        .into_iter()
        .filter(|sy| is_base58_address(&sy.mint))
        .map(|sy| (sy.mint.clone(), sy))
        .collect();

    let minimum_tvl = args
        .sol_notional_lamports
        .saturating_mul(args.minimum_tvl_multiple as u64);
    let hurdle = args.hurdle_apy_bps as f64 / 10_000.0;

    let mut markets: Vec<MarketRequest> = vaults
        .into_iter()
        .filter_map(|vault| {
            let sy = sy_by_mint.get(&vault.sy_token)?;
            if sy.quote_asset.mint != SOL_MINT || sy.quote_asset.decimals != 9 {
                return None;
            }
            if sy.underlying_asset.decimals != 9 || !is_base58_address(&sy.underlying_asset.mint) {
                return None;
            }
            if !is_base58_address(&vault.address)
                || !is_base58_address(&vault.pt_mint)
                || !is_base58_address(&vault.sy_token)
            {
                return None;
            }
            let end_unix_seconds = parse_utc_timestamp(&vault.end_timestamp)?;
            if end_unix_seconds <= now_unix_seconds {
                return None;
            }
            let maturity = vault.end_timestamp.get(..10)?.to_string();
            let implied_apy = finite_range(vault.implied_apy?, 0.0, 1.0)?;
            let underlying_apy = finite_range(vault.underlying_apy.unwrap_or(0.0), 0.0, 1.0)?;
            let years_to_maturity = (end_unix_seconds - now_unix_seconds) as f64 / SECONDS_PER_YEAR;
            let reported_years = finite_range(vault.years_to_maturity?, 0.0, 1.0)?;
            if !(0.0..=1.0).contains(&years_to_maturity)
                || (years_to_maturity - reported_years).abs() > 3.0 / 365.25
            {
                return None;
            }
            let pt_price = finite_range(vault.pt_price?, 0.5, 1.5)?;
            if pt_price >= 1.0 || implied_apy <= hurdle {
                return None;
            }
            let tvl_lamports = vault.tvl_in_base_token?;
            if tvl_lamports < minimum_tvl {
                return None;
            }
            let sy_exchange_rate = finite_range(
                vault.sy_exchange_rate.unwrap_or(1.0),
                0.000_001,
                1_000_000.0,
            )?;
            let orderbook_addresses = bounded_venue_addresses(vault.orderbooks)?;
            let clmm_addresses = bounded_venue_addresses(vault.clmm_markets)?;
            if orderbook_addresses.is_empty() && clmm_addresses.is_empty() {
                return None;
            }
            Some(MarketRequest {
                label: safe_asset_label(&sy.underlying_asset.mint),
                underlying_mint: sy.underlying_asset.mint.clone(),
                maturity,
                vault_address: vault.address,
                pt_mint: vault.pt_mint,
                orderbook_addresses,
                clmm_addresses,
                sy_exchange_rate,
                pt_price,
                implied_apy,
                underlying_apy,
                years_to_maturity,
                tvl_lamports,
            })
        })
        .collect();

    markets.sort_by(|a, b| {
        (b.implied_apy - hurdle)
            .partial_cmp(&(a.implied_apy - hurdle))
            .unwrap_or(Ordering::Equal)
            .then_with(|| b.tvl_lamports.cmp(&a.tvl_lamports))
    });
    markets
}

fn quote_request(market: &MarketRequest, sol_notional_lamports: u64) -> Value {
    json!({
        "vaultAddress": market.vault_address,
        "direction": "BASE_TO_PT",
        "inAmount": sol_notional_lamports,
        "syExchangeRate": market.sy_exchange_rate,
        "orderbookAddresses": market.orderbook_addresses,
        "clmmAddresses": market.clmm_addresses,
        "legacyMarketAddresses": [],
        "includeLegacyMarkets": false,
        "maxRoutes": 3
    })
}

fn score_quote(
    market: &MarketRequest,
    data: QuoteData,
    args: &BriefArgs,
) -> Option<ScoredCandidate> {
    if data.is_legacy_market
        || data.total_out_amount == 0
        || data.total_fees > data.total_out_amount
    {
        return None;
    }
    let expected_out = args.sol_notional_lamports as f64 / market.pt_price;
    let quoted_out = data.total_out_amount as f64;
    if !expected_out.is_finite()
        || quoted_out < expected_out * 0.95
        || quoted_out > expected_out * 1.05
    {
        return None;
    }
    let quote_growth = quoted_out / args.sol_notional_lamports as f64;
    let quote_apy = quote_growth.powf(1.0 / market.years_to_maturity) - 1.0;
    if !quote_apy.is_finite() || (quote_apy - market.implied_apy).abs() > 0.05 {
        return None;
    }
    let route = validate_routes(market, &data, args.sol_notional_lamports)?;
    let annual_hurdle = args.hurdle_apy_bps as f64 / 10_000.0;
    let hurdle_growth = (1.0 + annual_hurdle).powf(market.years_to_maturity) - 1.0;
    if !hurdle_growth.is_finite() || hurdle_growth < 0.0 {
        return None;
    }
    let hurdle_profit = (args.sol_notional_lamports as f64 * hurdle_growth).round() as i128;
    let gross_profit = data.total_out_amount as i128 - args.sol_notional_lamports as i128;
    let projected_profit = gross_profit - args.execution_cost_lamports as i128;
    let excess = projected_profit - hurdle_profit;

    Some(ScoredCandidate {
        label: market.label.clone(),
        underlying_mint: market.underlying_mint.clone(),
        maturity: market.maturity.clone(),
        pt_mint: market.pt_mint.clone(),
        projected_profit_lamports: projected_profit,
        excess_lamports: excess,
        quote_apy_bps: apy_to_bps(quote_apy),
        underlying_apy_bps: apy_to_bps(market.underlying_apy),
        tvl_multiple: market.tvl_lamports / args.sol_notional_lamports,
        fee_out_lamports: data.total_fees,
        route,
        meets_excess_floor: excess >= args.minimum_excess_lamports as i128,
    })
}

fn validate_routes(
    market: &MarketRequest,
    data: &QuoteData,
    sol_notional_lamports: u64,
) -> Option<&'static str> {
    if data.routes.is_empty() || data.routes.len() > 3 {
        return None;
    }
    let mut input_sum = 0_u64;
    let mut output_sum = 0_u64;
    let mut fee_sum = 0_u64;
    let mut percentage_sum = 0.0_f64;
    let mut dominant = (0.0_f64, "router");

    for route in &data.routes {
        let source = match route.source.as_str() {
            "CLMM" if market.clmm_addresses.contains(&route.source_address) => "CLMM",
            "ORDERBOOK" if market.orderbook_addresses.contains(&route.source_address) => {
                "orderbook"
            }
            _ => return None,
        };
        if !is_base58_address(&route.source_address)
            || route.in_amount == 0
            || route.out_amount == 0
            || route.fees > route.out_amount
            || !route.percentage.is_finite()
            || route.percentage <= 0.0
            || route.percentage > 100.0
        {
            return None;
        }
        input_sum = input_sum.checked_add(route.in_amount)?;
        output_sum = output_sum.checked_add(route.out_amount)?;
        fee_sum = fee_sum.checked_add(route.fees)?;
        percentage_sum += route.percentage;
        if route.percentage > dominant.0 {
            dominant = (route.percentage, source);
        }
    }

    if input_sum != sol_notional_lamports
        || output_sum != data.total_out_amount
        || fee_sum != data.total_fees
        || (percentage_sum - 100.0).abs() > 0.01
    {
        return None;
    }
    Some(dominant.1)
}

fn render_brief(
    candidates: &[ScoredCandidate],
    args: &BriefArgs,
    markets_eligible: usize,
    quotes_succeeded: usize,
    quotes_attempted: usize,
) -> String {
    let mut output = format!(
        "T0 fixed-yield brief — normalized SOL notional {:.6}; hurdle {:.2}%; estimated other costs {:.6} SOL; excess floor {:.6} SOL; TVL floor {}x; quote coverage {}/{} attempted; {} eligible.\n",
        args.sol_notional_lamports as f64 / LAMPORTS_PER_SOL,
        args.hurdle_apy_bps as f64 / 100.0,
        args.execution_cost_lamports as f64 / LAMPORTS_PER_SOL,
        args.minimum_excess_lamports as f64 / LAMPORTS_PER_SOL,
        args.minimum_tvl_multiple,
        quotes_succeeded,
        quotes_attempted,
        markets_eligible,
    );

    if candidates.is_empty() {
        output.push_str(
            "No catalog market cleared the prequote SOL-normalization, maturity, APY, and depth gates.\n",
        );
    } else {
        for (index, candidate) in candidates.iter().enumerate() {
            let floor = if candidate.meets_excess_floor {
                "floor met"
            } else {
                "below floor"
            };
            output.push_str(&format!(
                "{}. {} {}: projected normalized term {} SOL; excess {} vs hurdle ({}); quote APY {:.2}% (underlying {:.2}%); TVL {}x; fee {:.6} PT; {}; base mint {}; PT mint {}.\n",
                index + 1,
                candidate.label,
                candidate.maturity,
                signed_sol(candidate.projected_profit_lamports),
                signed_sol(candidate.excess_lamports),
                floor,
                candidate.quote_apy_bps as f64 / 100.0,
                candidate.underlying_apy_bps as f64 / 100.0,
                candidate.tvl_multiple,
                candidate.fee_out_lamports as f64 / LAMPORTS_PER_SOL,
                candidate.route,
                candidate.underlying_mint,
                candidate.pt_mint,
            ));
        }
    }
    if quotes_succeeded < quotes_attempted || quotes_attempted < markets_eligible {
        output.push_str(
            "Coverage is partial; failed or unattempted markets are unproven, not negative.\n",
        );
    }
    output.push_str(
        "Projection assumes successful normalized-par redemption at maturity; market fee is already in PT output. Underlying base-token acquisition/redemption is not quoted and must be verified independently. Quote is not transaction simulation or execution approval. Protocol and underlying-asset risk remain.",
    );
    output
}

fn signed_sol(lamports: i128) -> String {
    let sign = if lamports >= 0 { "+" } else { "-" };
    let magnitude = lamports.unsigned_abs() as f64 / LAMPORTS_PER_SOL;
    format!("{sign}{magnitude:.6}")
}

fn apy_to_bps(apy: f64) -> u32 {
    (apy * 10_000.0).round().clamp(0.0, u32::MAX as f64) as u32
}

fn finite_range(value: f64, minimum_exclusive: f64, maximum_inclusive: f64) -> Option<f64> {
    (value.is_finite() && value > minimum_exclusive && value <= maximum_inclusive).then_some(value)
}

fn bounded_venue_addresses(records: Vec<AddressRecord>) -> Option<Vec<String>> {
    let mut seen = HashSet::new();
    let mut addresses = Vec::new();
    for record in records {
        if !is_base58_address(&record.address) {
            return None;
        }
        if seen.insert(record.address.clone()) {
            if addresses.len() == MAX_VENUES_PER_TYPE {
                return None;
            }
            addresses.push(record.address);
        }
    }
    Some(addresses)
}

fn safe_asset_label(mint: &str) -> String {
    match mint {
        BULKSOL_MINT => "PT-BulkSOL".to_string(),
        _ => format!("PT-mint:{mint}"),
    }
}

fn parse_utc_timestamp(value: &str) -> Option<u64> {
    if value.len() < 20 || !matches!(value.get(19..), Some("Z") | Some("+00:00")) {
        return None;
    }
    let bytes = value.as_bytes();
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let year = parse_decimal(value.get(0..4)?)? as i32;
    let month = parse_decimal(value.get(5..7)?)? as u32;
    let day = parse_decimal(value.get(8..10)?)? as u32;
    let hour = parse_decimal(value.get(11..13)?)? as u32;
    let minute = parse_decimal(value.get(14..16)?)? as u32;
    let second = parse_decimal(value.get(17..19)?)? as u32;
    if !(1970..=2200).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if days < 0 {
        return None;
    }
    let seconds = (days as u64)
        .checked_mul(86_400)?
        .checked_add(hour as u64 * 3_600)?
        .checked_add(minute as u64 * 60)?
        .checked_add(second as u64)?;
    Some(seconds)
}

fn parse_decimal(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())?
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

// Howard Hinnant's civil-date conversion, offset to the Unix epoch.
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i32::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = (adjusted_year - era * 400) as u32;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era as i64 * 146_097 + day_of_era as i64 - 719_468
}

fn is_base58_address(value: &str) -> bool {
    (32..=44).contains(&value.len())
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'1'..=b'9'
                    | b'A'..=b'H'
                    | b'J'..=b'N'
                    | b'P'..=b'Z'
                    | b'a'..=b'k'
                    | b'm'..=b'z'
            )
        })
}
