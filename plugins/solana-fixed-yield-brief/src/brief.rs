//! Pure fixed-yield selection, quote-request, scoring, and rendering core.
//!
//! There is no wasm, HTTP, wallet, or signing dependency here. Host tests pass
//! fixture data through [`ExponentDataSource`], exercising the same path used by
//! the component while guaranteeing that tests never touch a live endpoint.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use serde_json::{json, Value};

const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;
const SECONDS_PER_YEAR: f64 = 31_557_600.0;
const SOL_MINT: &str = "So11111111111111111111111111111111111111112";
const BULKSOL_MINT: &str = "BULKoNSGzxtCqzwTvg5hFJg8fx6dqZRScyXe5LYMfxrn";
const MAX_MARKETS_TO_QUOTE: usize = 8;
const QUOTES_PER_RESULT: usize = 3;
const MAX_VAULTS: usize = 256;
const MAX_SY_TOKENS: usize = 256;
const MAX_VENUES_PER_TYPE: usize = 16;
const MIN_SOL_NOTIONAL_LAMPORTS: u64 = 1_000_000;
const MAX_SOL_NOTIONAL_LAMPORTS: u64 = 10_000_000_000_000;
const MIN_HURDLE_APY_BPS: u32 = 550;
const MAX_HURDLE_APY_BPS: u32 = 100_000;
const MIN_EXECUTION_COST_LAMPORTS: u64 = 1_000_000;
const MIN_EXCESS_LAMPORTS: u64 = 1_000_000;
const MIN_TVL_MULTIPLE: u32 = 20;
const MAX_TVL_MULTIPLE: u32 = 1_000;
const MIN_RESULTS: u8 = 1;
const MAX_RESULTS: u8 = 3;
const MAX_MATURITY_DRIFT_YEARS: f64 = 3.0 / 365.25;
const MAX_APY_DRIFT: f64 = 0.05;
const MAX_QUOTE_RELATIVE_DRIFT: f64 = 0.05;
const MAX_ROUTE_PERCENTAGE_DRIFT_POINTS: f64 = 0.01;
const REQUIRED_NORMALIZED_EXCHANGE_RATE: f64 = 1.0;
const MAX_EXCHANGE_RATE_DRIFT: f64 = 1e-9;

fn default_hurdle_apy_bps() -> u32 {
    MIN_HURDLE_APY_BPS
}

fn default_execution_cost_lamports() -> u64 {
    MIN_EXECUTION_COST_LAMPORTS
}

fn default_minimum_excess_lamports() -> u64 {
    MIN_EXCESS_LAMPORTS
}

fn default_minimum_tvl_multiple() -> u32 {
    MIN_TVL_MULTIPLE
}

fn default_max_results() -> u8 {
    MIN_RESULTS
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
        if !(MIN_SOL_NOTIONAL_LAMPORTS..=MAX_SOL_NOTIONAL_LAMPORTS)
            .contains(&self.sol_notional_lamports)
        {
            return Err("sol_notional_lamports must be between 0.001 and 10,000 SOL".to_string());
        }
        if !(MIN_HURDLE_APY_BPS..=MAX_HURDLE_APY_BPS).contains(&self.hurdle_apy_bps) {
            return Err("hurdle_apy_bps must be between 550 and 100000".to_string());
        }
        if !(MIN_EXECUTION_COST_LAMPORTS..=self.sol_notional_lamports)
            .contains(&self.execution_cost_lamports)
        {
            return Err(
                "execution_cost_lamports must be at least 1000000 and not exceed sol_notional_lamports"
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
        if !(MIN_TVL_MULTIPLE..=MAX_TVL_MULTIPLE).contains(&self.minimum_tvl_multiple) {
            return Err("minimum_tvl_multiple must be between 20 and 1000".to_string());
        }
        if !(MIN_RESULTS..=MAX_RESULTS).contains(&self.max_results) {
            return Err("max_results must be between 1 and 3".to_string());
        }
        Ok(())
    }

    /// One source of truth for tool discovery defaults and runtime bounds.
    pub fn parameters_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "sol_notional_lamports": {
                    "type": "integer",
                    "minimum": MIN_SOL_NOTIONAL_LAMPORTS,
                    "maximum": MAX_SOL_NOTIONAL_LAMPORTS,
                    "description": "SOL-denominated normalized quote notional in lamports; not proof that the underlying base-token leg is funded."
                },
                "hurdle_apy_bps": {
                    "type": "integer",
                    "minimum": MIN_HURDLE_APY_BPS,
                    "maximum": MAX_HURDLE_APY_BPS,
                    "default": default_hurdle_apy_bps(),
                    "description": "Alternative annual yield in basis points; the conservative floor is 550 (5.50%)."
                },
                "execution_cost_lamports": {
                    "type": "integer",
                    "minimum": MIN_EXECUTION_COST_LAMPORTS,
                    "default": default_execution_cost_lamports(),
                    "description": "Estimated total of base-token acquisition/redemption, entry, priority, tip, and other non-market costs."
                },
                "minimum_excess_lamports": {
                    "type": "integer",
                    "minimum": MIN_EXCESS_LAMPORTS,
                    "default": default_minimum_excess_lamports(),
                    "description": "Minimum projected normalized term advantage required for the floor-met label."
                },
                "minimum_tvl_multiple": {
                    "type": "integer",
                    "minimum": MIN_TVL_MULTIPLE,
                    "maximum": MAX_TVL_MULTIPLE,
                    "default": default_minimum_tvl_multiple(),
                    "description": "Require reported normalized TVL to be at least this multiple of quote notional."
                },
                "max_results": {
                    "type": "integer",
                    "minimum": MIN_RESULTS,
                    "maximum": MAX_RESULTS,
                    "default": default_max_results()
                }
            },
            "required": ["sol_notional_lamports"],
            "additionalProperties": false
        })
    }
}

/// Exponent-specific data boundary. The wasm shim implements it with fixed
/// HTTPS endpoints; host tests implement it with in-memory fixtures.
pub trait ExponentDataSource {
    fn now_unix_seconds(&self) -> Result<u64, String>;
    fn vaults(&self) -> Result<Value, String>;
    fn sy_tokens(&self) -> Result<Value, String>;
    fn quote(&self, request: &Value) -> Result<Value, String>;
}

#[derive(Debug, Clone)]
pub struct BriefReport {
    pub output: String,
    pub candidates: Vec<BriefCandidate>,
    pub markets_eligible: usize,
    pub quotes_attempted: usize,
    pub quotes_succeeded: usize,
    pub diagnostics: QuoteDiagnostics,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuoteDiagnostics {
    pub fetch_failed: usize,
    pub schema_rejected: usize,
    pub upstream_rejected: usize,
    pub integrity_rejected: usize,
    pub clock_rejected: usize,
}

#[derive(Debug, Clone)]
pub struct BriefCandidate {
    pub label: String,
    pub underlying_mint: String,
    pub maturity: String,
    pub pt_mint: String,
    pub projected_profit_lamports: i128,
    pub excess_lamports: i128,
    pub quote_apy_bps: u32,
    pub underlying_apy_bps: Option<u32>,
    pub tvl_multiple: u64,
    pub fee_pt_atoms: u64,
    pub route: &'static str,
    pub meets_excess_floor: bool,
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
    decimals: u8,
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
    underlying_apy: Option<f64>,
    end_unix_seconds: u64,
    years_to_maturity: f64,
    base_tvl_atoms: u64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NormalizedSolLamports(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BaseAtoms(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PtAtoms(u64);

pub fn generate_brief<S: ExponentDataSource>(
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

    let catalog_rows = vaults.len();
    let mut markets = eligible_markets(vaults, sy_tokens, args, now_unix_seconds)?;
    let markets_eligible = markets.len();
    if markets_eligible == 0 {
        return Err(format!(
            "UNPROVEN: 0/{catalog_rows} Exponent vault rows passed bounded quote eligibility"
        ));
    }
    let quote_budget = usize::from(args.max_results)
        .saturating_mul(QUOTES_PER_RESULT)
        .min(MAX_MARKETS_TO_QUOTE);
    markets.truncate(quote_budget);
    let quotes_attempted = markets.len();

    let mut scored = Vec::new();
    let mut quotes_succeeded = 0usize;
    let mut diagnostics = QuoteDiagnostics::default();
    for market in markets {
        let normalized_notional = NormalizedSolLamports(args.sol_notional_lamports);
        let Some(base_notional) = normalized_to_base_atoms(&market, normalized_notional) else {
            diagnostics.integrity_rejected += 1;
            continue;
        };
        let request = quote_request(&market, base_notional);
        let Ok(value) = source.quote(&request) else {
            diagnostics.fetch_failed += 1;
            continue;
        };
        let Ok(envelope) = serde_json::from_value::<QuoteEnvelope>(value) else {
            diagnostics.schema_rejected += 1;
            continue;
        };
        if !envelope.success {
            diagnostics.upstream_rejected += 1;
            continue;
        }
        let Some(data) = envelope.data else {
            diagnostics.schema_rejected += 1;
            continue;
        };
        let Ok(scored_at) = source.now_unix_seconds() else {
            diagnostics.clock_rejected += 1;
            continue;
        };
        if scored_at < now_unix_seconds || scored_at >= market.end_unix_seconds {
            diagnostics.clock_rejected += 1;
            continue;
        }
        let current_years = (market.end_unix_seconds - scored_at) as f64 / SECONDS_PER_YEAR;
        if let Some(candidate) = score_quote(&market, data, args, base_notional, current_years) {
            quotes_succeeded += 1;
            scored.push(candidate);
        } else {
            diagnostics.integrity_rejected += 1;
        }
    }

    scored.sort_by(|a, b| {
        b.excess_lamports
            .cmp(&a.excess_lamports)
            .then_with(|| b.quote_apy_bps.cmp(&a.quote_apy_bps))
            .then_with(|| a.pt_mint.cmp(&b.pt_mint))
    });
    scored.truncate(args.max_results as usize);

    if quotes_attempted > 0 && quotes_succeeded == 0 {
        return Err(format!(
            "UNPROVEN: 0/{quotes_attempted} coherent Exponent quotes across {markets_eligible} eligible markets (fetch {}, schema {}, upstream {}, integrity {}, clock {})",
            diagnostics.fetch_failed,
            diagnostics.schema_rejected,
            diagnostics.upstream_rejected,
            diagnostics.integrity_rejected,
            diagnostics.clock_rejected,
        ));
    }

    let mut report = BriefReport {
        output: String::new(),
        candidates: scored,
        markets_eligible,
        quotes_attempted,
        quotes_succeeded,
        diagnostics,
    };
    report.output = render_brief(&report, args);
    Ok(report)
}

fn eligible_markets(
    vaults: Vec<Vault>,
    sy_tokens: Vec<SyToken>,
    args: &BriefArgs,
    now_unix_seconds: u64,
) -> Result<Vec<MarketRequest>, String> {
    let mut sy_by_mint = HashMap::new();
    for sy in sy_tokens {
        if !is_solana_pubkey(&sy.mint) {
            continue;
        }
        if sy_by_mint.insert(sy.mint.clone(), sy).is_some() {
            return Err("UNPROVEN: duplicate Exponent SY mint identity".to_string());
        }
    }

    let minimum_tvl = args
        .sol_notional_lamports
        .saturating_mul(args.minimum_tvl_multiple as u64);
    let mut seen_vaults = HashSet::new();
    let mut seen_pt_mints = HashSet::new();
    let mut markets = Vec::new();
    for vault in vaults {
        let maybe_market = (|| {
            if !is_solana_pubkey(&vault.address)
                || !is_solana_pubkey(&vault.pt_mint)
                || !is_solana_pubkey(&vault.sy_token)
            {
                return None;
            }
            if !seen_vaults.insert(vault.address.clone())
                || !seen_pt_mints.insert(vault.pt_mint.clone())
            {
                return Some(Err(
                    "UNPROVEN: duplicate Exponent vault or PT mint identity".to_string(),
                ));
            }
            let sy = sy_by_mint.get(&vault.sy_token)?;
            if sy.decimals != 9 || sy.quote_asset.mint != SOL_MINT || sy.quote_asset.decimals != 9 {
                return None;
            }
            if sy.underlying_asset.decimals != 9 || !is_solana_pubkey(&sy.underlying_asset.mint) {
                return None;
            }
            let end_unix_seconds = parse_utc_timestamp(&vault.end_timestamp)?;
            if end_unix_seconds <= now_unix_seconds {
                return None;
            }
            let maturity = vault.end_timestamp.get(..10)?.to_string();
            let implied_apy = finite_range(vault.implied_apy?, 0.0, 1.0)?;
            let underlying_apy = match vault.underlying_apy {
                Some(value) => Some(finite_inclusive_range(value, 0.0, 1.0)?),
                None => None,
            };
            let years_to_maturity = (end_unix_seconds - now_unix_seconds) as f64 / SECONDS_PER_YEAR;
            let reported_years = finite_range(vault.years_to_maturity?, 0.0, 1.0)?;
            if !(0.0..=1.0).contains(&years_to_maturity)
                || (years_to_maturity - reported_years).abs() > MAX_MATURITY_DRIFT_YEARS
            {
                return None;
            }
            let pt_price = finite_range(vault.pt_price?, 0.5, 1.5)?;
            if pt_price >= 1.0 {
                return None;
            }
            let price_implied_apy = (1.0 / pt_price).powf(1.0 / years_to_maturity) - 1.0;
            if !price_implied_apy.is_finite()
                || (price_implied_apy - implied_apy).abs() > MAX_APY_DRIFT
            {
                return None;
            }
            let base_tvl_atoms = vault.tvl_in_base_token?;
            if base_tvl_atoms < minimum_tvl {
                return None;
            }
            let sy_exchange_rate = finite_range(vault.sy_exchange_rate?, 0.000_001, 1_000_000.0)?;
            if (sy_exchange_rate - REQUIRED_NORMALIZED_EXCHANGE_RATE).abs()
                > MAX_EXCHANGE_RATE_DRIFT
            {
                return None;
            }
            let orderbook_addresses = bounded_venue_addresses(vault.orderbooks)?;
            let clmm_addresses = bounded_venue_addresses(vault.clmm_markets)?;
            if orderbook_addresses.is_empty() && clmm_addresses.is_empty() {
                return None;
            }
            Some(Ok(MarketRequest {
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
                end_unix_seconds,
                years_to_maturity,
                base_tvl_atoms,
            }))
        })();
        match maybe_market {
            Some(Ok(market)) => markets.push(market),
            Some(Err(error)) => return Err(error),
            None => {}
        }
    }

    markets.sort_by(|a, b| {
        estimated_catalog_excess(b, args)
            .cmp(&estimated_catalog_excess(a, args))
            .then_with(|| b.base_tvl_atoms.cmp(&a.base_tvl_atoms))
            .then_with(|| a.pt_mint.cmp(&b.pt_mint))
    });
    Ok(markets)
}

fn normalized_to_base_atoms(
    market: &MarketRequest,
    normalized: NormalizedSolLamports,
) -> Option<BaseAtoms> {
    ((market.sy_exchange_rate - REQUIRED_NORMALIZED_EXCHANGE_RATE).abs() <= MAX_EXCHANGE_RATE_DRIFT)
        .then_some(BaseAtoms(normalized.0))
}

fn quote_request(market: &MarketRequest, base_notional: BaseAtoms) -> Value {
    json!({
        "vaultAddress": market.vault_address,
        "direction": "BASE_TO_PT",
        "inAmount": base_notional.0,
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
    base_notional: BaseAtoms,
    years_to_maturity: f64,
) -> Option<BriefCandidate> {
    if data.is_legacy_market
        || data.total_out_amount == 0
        || data.total_fees > data.total_out_amount
    {
        return None;
    }
    let expected_out = base_notional.0 as f64 / market.pt_price;
    let quoted_out = data.total_out_amount as f64;
    if !expected_out.is_finite()
        || quoted_out < expected_out * (1.0 - MAX_QUOTE_RELATIVE_DRIFT)
        || quoted_out > expected_out * (1.0 + MAX_QUOTE_RELATIVE_DRIFT)
    {
        return None;
    }
    let quote_growth = quoted_out / base_notional.0 as f64;
    let quote_apy = quote_growth.powf(1.0 / years_to_maturity) - 1.0;
    if !quote_apy.is_finite() || (quote_apy - market.implied_apy).abs() > MAX_APY_DRIFT {
        return None;
    }
    let route = validate_routes(market, &data, base_notional)?;
    let hurdle_profit = hurdle_profit_lamports(
        NormalizedSolLamports(args.sol_notional_lamports),
        args.hurdle_apy_bps,
        years_to_maturity,
    )?;
    let pt_at_maturity = PtAtoms(data.total_out_amount);
    let normalized_at_maturity = pt_redemption_to_normalized(market, pt_at_maturity)?;
    let gross_profit = normalized_at_maturity.0 as i128 - args.sol_notional_lamports as i128;
    let projected_profit = gross_profit - args.execution_cost_lamports as i128;
    let excess = projected_profit - hurdle_profit;

    Some(BriefCandidate {
        label: market.label.clone(),
        underlying_mint: market.underlying_mint.clone(),
        maturity: market.maturity.clone(),
        pt_mint: market.pt_mint.clone(),
        projected_profit_lamports: projected_profit,
        excess_lamports: excess,
        quote_apy_bps: apy_to_bps(quote_apy),
        underlying_apy_bps: market.underlying_apy.map(apy_to_bps),
        tvl_multiple: market.base_tvl_atoms / base_notional.0,
        fee_pt_atoms: data.total_fees,
        route,
        meets_excess_floor: excess >= args.minimum_excess_lamports as i128,
    })
}

fn validate_routes(
    market: &MarketRequest,
    data: &QuoteData,
    base_notional: BaseAtoms,
) -> Option<&'static str> {
    if data.routes.is_empty() || data.routes.len() > 3 {
        return None;
    }
    let mut input_sum = 0_u64;
    let mut output_sum = 0_u64;
    let mut fee_sum = 0_u64;
    let mut percentage_sum = 0.0_f64;
    let mut dominant = (0_u64, "router");

    for route in &data.routes {
        let source = match route.source.as_str() {
            "CLMM" if market.clmm_addresses.contains(&route.source_address) => "CLMM",
            "ORDERBOOK" if market.orderbook_addresses.contains(&route.source_address) => {
                "orderbook"
            }
            _ => return None,
        };
        if !is_solana_pubkey(&route.source_address)
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
        let expected_percentage = route.in_amount as f64 * 100.0 / base_notional.0 as f64;
        if (route.percentage - expected_percentage).abs() > MAX_ROUTE_PERCENTAGE_DRIFT_POINTS {
            return None;
        }
        if route.in_amount > dominant.0 {
            dominant = (route.in_amount, source);
        }
    }

    if input_sum != base_notional.0
        || output_sum != data.total_out_amount
        || fee_sum != data.total_fees
        || (percentage_sum - 100.0).abs() > MAX_ROUTE_PERCENTAGE_DRIFT_POINTS
    {
        return None;
    }
    Some(dominant.1)
}

fn render_brief(report: &BriefReport, args: &BriefArgs) -> String {
    let mut output = format!(
        "T0 Exponent | normalized {:.6} SOL; hurdle {:.2}%; costs/floor {:.6}/{:.6} SOL; TVL >= {}x; coverage {}/{} quotes ({} eligible).\n",
        args.sol_notional_lamports as f64 / LAMPORTS_PER_SOL,
        args.hurdle_apy_bps as f64 / 100.0,
        args.execution_cost_lamports as f64 / LAMPORTS_PER_SOL,
        args.minimum_excess_lamports as f64 / LAMPORTS_PER_SOL,
        args.minimum_tvl_multiple,
        report.quotes_succeeded,
        report.quotes_attempted,
        report.markets_eligible,
    );

    for (index, candidate) in report.candidates.iter().enumerate() {
        let floor = if candidate.meets_excess_floor {
            "met"
        } else {
            "below"
        };
        let underlying = candidate
            .underlying_apy_bps
            .map(|bps| format!("{:.2}%", bps as f64 / 100.0))
            .unwrap_or_else(|| "n/a".to_string());
        output.push_str(&format!(
                "{} {} {} | term {} SOL; excess {} ({}); APY {:.2}%/underlying {}; TVL {}x; fee {:.6} PT; {}.\nIDs base={} PT={}.\n",
                index + 1,
                candidate.label,
                candidate.maturity,
                signed_sol(candidate.projected_profit_lamports),
                signed_sol(candidate.excess_lamports),
                floor,
                candidate.quote_apy_bps as f64 / 100.0,
                underlying,
                candidate.tvl_multiple,
                candidate.fee_pt_atoms as f64 / LAMPORTS_PER_SOL,
                candidate.route,
                candidate.underlying_mint,
                candidate.pt_mint,
            ));
    }
    if report.quotes_succeeded < report.quotes_attempted
        || report.quotes_attempted < report.markets_eligible
    {
        output.push_str("Partial coverage is unproven. ");
    }
    output.push_str(
        "Assumes normalized-par redemption. Base acquisition/redemption is unquoted; not simulation or approval. Exponent, underlying, depeg, and liquidity risks remain.",
    );
    output
}

fn signed_sol(lamports: i128) -> String {
    let sign = if lamports >= 0 { "+" } else { "-" };
    let magnitude = lamports.unsigned_abs() as f64 / LAMPORTS_PER_SOL;
    format!("{sign}{magnitude:.6}")
}

fn estimated_catalog_excess(market: &MarketRequest, args: &BriefArgs) -> i128 {
    let expected_pt_atoms = (args.sol_notional_lamports as f64 / market.pt_price).round() as i128;
    let gross = expected_pt_atoms - args.sol_notional_lamports as i128;
    let Some(hurdle) = hurdle_profit_lamports(
        NormalizedSolLamports(args.sol_notional_lamports),
        args.hurdle_apy_bps,
        market.years_to_maturity,
    ) else {
        return i128::MIN;
    };
    gross - args.execution_cost_lamports as i128 - hurdle
}

fn pt_redemption_to_normalized(
    market: &MarketRequest,
    pt_at_maturity: PtAtoms,
) -> Option<NormalizedSolLamports> {
    ((market.sy_exchange_rate - REQUIRED_NORMALIZED_EXCHANGE_RATE).abs() <= MAX_EXCHANGE_RATE_DRIFT)
        .then_some(NormalizedSolLamports(pt_at_maturity.0))
}

fn hurdle_profit_lamports(
    notional: NormalizedSolLamports,
    hurdle_apy_bps: u32,
    years_to_maturity: f64,
) -> Option<i128> {
    let annual_hurdle = hurdle_apy_bps as f64 / 10_000.0;
    let hurdle_growth = (1.0 + annual_hurdle).powf(years_to_maturity) - 1.0;
    (hurdle_growth.is_finite() && hurdle_growth >= 0.0)
        .then_some((notional.0 as f64 * hurdle_growth).round() as i128)
}

fn apy_to_bps(apy: f64) -> u32 {
    (apy * 10_000.0).round().clamp(0.0, u32::MAX as f64) as u32
}

fn finite_range(value: f64, minimum_exclusive: f64, maximum_inclusive: f64) -> Option<f64> {
    (value.is_finite() && value > minimum_exclusive && value <= maximum_inclusive).then_some(value)
}

fn finite_inclusive_range(value: f64, minimum: f64, maximum: f64) -> Option<f64> {
    (value.is_finite() && value >= minimum && value <= maximum).then_some(value)
}

fn bounded_venue_addresses(records: Vec<AddressRecord>) -> Option<Vec<String>> {
    let mut seen = HashSet::new();
    let mut addresses = Vec::new();
    for record in records {
        if !is_solana_pubkey(&record.address) {
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
        _ => "PT".to_string(),
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

fn is_solana_pubkey(value: &str) -> bool {
    (32..=44).contains(&value.len())
        && bs58::decode(value)
            .into_vec()
            .is_ok_and(|bytes| bytes.len() == 32)
}
