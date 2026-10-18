//! Pure logic for the `jupiter-quote` tool.
//!
//! Everything here — resolving config, validating mints and the amount,
//! building the Jupiter Quote API URL, parsing the response, and summarizing the
//! route for an LLM — has no wit-bindgen or wasm dependency, so it compiles and
//! tests on the host with a plain `cargo test`. The wasm component reuses the
//! exact same functions through `lib.rs`, keeping the component glue too thin to
//! be wrong.

use std::collections::HashMap;

use serde_json::Value;

/// Base URL of Jupiter's free (no-API-key) "lite" host. The full quote endpoint
/// is `{base}/swap/v1/quote`. Verified current as of 2026-07: the older
/// `quote-api.jup.ag/v6` host is superseded, and `api.jup.ag` now requires an
/// `x-api-key`, while `lite-api.jup.ag` stays key-free (rate limited to
/// ~30 req/min).
pub const DEFAULT_JUPITER_BASE_URL: &str = "https://lite-api.jup.ag";

/// Runtime configuration resolved from the plugin's own jailed config section.
pub struct QuoteConfig {
    /// Base URL for Jupiter's swap host (`{base}/swap/v1/quote`).
    pub jupiter_base_url: String,
}

impl QuoteConfig {
    /// Build from the flat `string -> string` section the host injects. An
    /// absent, empty, or whitespace-only `jupiter_base_url` falls back to the
    /// public lite host, which is also exactly what an unprivileged plugin (no
    /// `config_read` permission) sees.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let jupiter_base_url = section
            .get("jupiter_base_url")
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| DEFAULT_JUPITER_BASE_URL.to_string());
        Self { jupiter_base_url }
    }
}

/// Validated inputs for a quote request.
pub struct QuoteParams {
    pub input_mint: String,
    pub output_mint: String,
    /// Amount in the input token's base units, as a canonical decimal string.
    pub amount: String,
    /// Optional slippage tolerance in basis points; when `None`, Jupiter's own
    /// default is used.
    pub slippage_bps: Option<u32>,
}

/// Validate a base58-encoded Solana mint/public key: it must decode cleanly to
/// exactly 32 bytes. Returns the trimmed, normalized address on success.
pub fn validate_mint(mint: &str) -> Result<String, String> {
    let trimmed = mint.trim();
    if trimmed.is_empty() {
        return Err("mint is empty".to_string());
    }
    let decoded = bs58::decode(trimmed)
        .into_vec()
        .map_err(|e| format!("mint is not valid base58: {e}"))?;
    if decoded.len() != 32 {
        return Err(format!(
            "mint must decode to 32 bytes, got {}",
            decoded.len()
        ));
    }
    Ok(trimmed.to_string())
}

/// Validate a base-unit amount string: it must be a positive integer (no
/// decimal point — Jupiter takes raw base units). Leading zeros are tolerated
/// and stripped; the canonical decimal form is returned.
pub fn validate_amount(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("amount is empty".to_string());
    }
    if !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(
            "amount must be an integer in base units (no decimal point, no sign)".to_string(),
        );
    }
    let value: u128 = trimmed
        .parse()
        .map_err(|_| "amount is too large to represent".to_string())?;
    if value == 0 {
        return Err("amount must be greater than zero".to_string());
    }
    Ok(value.to_string())
}

/// Normalize an incoming JSON `amount` (a string or an integer number) into a
/// validated canonical base-unit string.
pub fn amount_from_json(v: &Value) -> Result<String, String> {
    match v {
        Value::String(s) => validate_amount(s),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                validate_amount(&u.to_string())
            } else {
                Err("amount must be a non-negative integer in base units".to_string())
            }
        }
        _ => Err("amount must be a string or integer in base units".to_string()),
    }
}

/// Build the Jupiter Quote API URL for the given params:
/// `{base}/swap/v1/quote?inputMint=..&outputMint=..&amount=..&slippageBps=..`.
/// `restrictIntermediateTokens=true` biases the router toward liquid,
/// lower-risk intermediate tokens. `slippageBps` is only appended when set.
pub fn build_quote_url(base_url: &str, params: &QuoteParams) -> String {
    let base = base_url.trim_end_matches('/');
    let mut url = format!(
        "{base}/swap/v1/quote?inputMint={}&outputMint={}&amount={}&restrictIntermediateTokens=true",
        params.input_mint, params.output_mint, params.amount
    );
    if let Some(bps) = params.slippage_bps {
        url.push_str(&format!("&slippageBps={bps}"));
    }
    url
}

/// One hop in the routed swap, summarized for a language model.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteHop {
    /// AMM/DEX label, e.g. "Meteora", "Raydium".
    pub label: String,
    pub input_mint: String,
    pub output_mint: String,
    /// Percentage of the split routed through this hop.
    pub percent: f64,
}

/// A parsed, LLM-friendly view of a Jupiter quote.
#[derive(Debug, Clone, PartialEq)]
pub struct Quote {
    pub input_mint: String,
    pub output_mint: String,
    /// Input amount in base units (echoed by Jupiter), exact string.
    pub in_amount: String,
    /// Output amount in base units, exact string.
    pub out_amount: String,
    /// Minimum out after slippage (Jupiter's `otherAmountThreshold`).
    pub other_amount_threshold: Option<String>,
    /// Price impact as a percentage number (e.g. 0.12 == 0.12%).
    pub price_impact_pct: f64,
    /// Slippage tolerance Jupiter applied, in basis points.
    pub slippage_bps: Option<u64>,
    /// "ExactIn" / "ExactOut".
    pub swap_mode: Option<String>,
    /// USD value of the swap, when Jupiter reports it.
    pub swap_usd_value: Option<String>,
    /// Ordered route hops.
    pub route: Vec<RouteHop>,
}

/// Parse a Jupiter `swap/v1/quote` response. A Jupiter `error` field is
/// surfaced as `Err` so the caller can report it to the model.
pub fn parse_quote_response(body: &str) -> Result<Quote, String> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| format!("Jupiter quote response is not valid JSON: {e}"))?;

    if let Some(err) = v.get("error") {
        let msg = err
            .as_str()
            .or_else(|| err.get("message").and_then(Value::as_str))
            .unwrap_or("unknown Jupiter error");
        return Err(format!("Jupiter error: {msg}"));
    }

    let input_mint = v
        .get("inputMint")
        .and_then(Value::as_str)
        .ok_or("quote missing inputMint")?
        .to_string();
    let output_mint = v
        .get("outputMint")
        .and_then(Value::as_str)
        .ok_or("quote missing outputMint")?
        .to_string();
    let in_amount = v
        .get("inAmount")
        .and_then(Value::as_str)
        .ok_or("quote missing inAmount")?
        .to_string();
    let out_amount = v
        .get("outAmount")
        .and_then(Value::as_str)
        .ok_or("quote missing outAmount")?
        .to_string();

    // priceImpactPct comes back as a string ("0", "0.0012", ...).
    let price_impact_pct = v
        .get("priceImpactPct")
        .and_then(number_from_json)
        .map(|n| n * 100.0)
        .unwrap_or(0.0);

    let route = v
        .get("routePlan")
        .and_then(Value::as_array)
        .map(|plan| {
            plan.iter()
                .filter_map(|hop| {
                    let info = hop.get("swapInfo")?;
                    Some(RouteHop {
                        label: info
                            .get("label")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .to_string(),
                        input_mint: info
                            .get("inputMint")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        output_mint: info
                            .get("outputMint")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        percent: hop.get("percent").and_then(number_from_json).unwrap_or(0.0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Quote {
        input_mint,
        output_mint,
        in_amount,
        out_amount,
        other_amount_threshold: v
            .get("otherAmountThreshold")
            .and_then(Value::as_str)
            .map(str::to_string),
        price_impact_pct,
        slippage_bps: v.get("slippageBps").and_then(Value::as_u64),
        swap_mode: v
            .get("swapMode")
            .and_then(Value::as_str)
            .map(str::to_string),
        swap_usd_value: v
            .get("swapUsdValue")
            .and_then(Value::as_str)
            .map(str::to_string),
        route,
    })
}

/// Read a JSON value that may be a number or a numeric string as an `f64`.
fn number_from_json(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
}

/// Render the route as a one-line human summary, e.g.
/// `"So111.. -> EPjF.. via Meteora (100%)"` or a multi-hop chain. Returns
/// `"direct"` when there is a single 100% hop and `"no route"` when empty.
pub fn route_summary(route: &[RouteHop]) -> String {
    if route.is_empty() {
        return "no route".to_string();
    }
    route
        .iter()
        .map(|h| format!("{} ({}%)", h.label, trim_float(h.percent)))
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// Format a compact number without a trailing `.0` for whole values.
fn trim_float(n: f64) -> String {
    if n.fract() == 0.0 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// Format a parsed quote as a compact JSON object string — the `output` the
/// tool hands back to the model. All amounts stay as exact base-unit strings;
/// the route is summarized both structurally and as a one-line description.
pub fn format_output(q: &Quote, base_url: &str) -> String {
    let hops: Vec<Value> = q
        .route
        .iter()
        .map(|h| {
            serde_json::json!({
                "label": h.label,
                "input_mint": h.input_mint,
                "output_mint": h.output_mint,
                "percent": h.percent,
            })
        })
        .collect();

    serde_json::json!({
        "input_mint": q.input_mint,
        "output_mint": q.output_mint,
        "in_amount": q.in_amount,
        "out_amount": q.out_amount,
        "other_amount_threshold": q.other_amount_threshold,
        "price_impact_pct": q.price_impact_pct,
        "slippage_bps": q.slippage_bps,
        "swap_mode": q.swap_mode,
        "swap_usd_value": q.swap_usd_value,
        "hops": q.route.len(),
        "route": hops,
        "route_summary": route_summary(&q.route),
        "jupiter_base_url": base_url,
    })
    .to_string()
}
