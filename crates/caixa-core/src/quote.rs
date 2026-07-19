//! BRL → USDC quote helpers (HTTP GET via injected transport).

use serde_json::Value;

use crate::rpc::{HttpGet, RpcError};

#[derive(Debug, Clone)]
pub struct QuoteInput {
    pub amount_brl: f64,
    /// Optional override; default CoinGecko simple price.
    pub price_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct QuoteResult {
    pub amount_brl: f64,
    pub usdc_per_brl: f64,
    pub amount_usdc: f64,
    /// Fixed 6-decimal USDC string for Solana Pay / transfers.
    pub amount_usdc_str: String,
}

/// Quote USDC from BRL using a USD-priced feed.
///
/// Expects CoinGecko-shaped JSON: `{ "usd-coin": { "brl": <number> } }`
/// where `brl` is BRL per 1 USDC. Then `usdc = brl_amount / brl_per_usdc`.
pub fn quote_brl_to_usdc<H: HttpGet>(http: &H, input: &QuoteInput) -> Result<QuoteResult, RpcError> {
    if !(input.amount_brl.is_finite() && input.amount_brl > 0.0) {
        return Err(RpcError("amount_brl must be a positive finite number".into()));
    }
    if input.amount_brl > 1_000_000.0 {
        return Err(RpcError("amount_brl exceeds hard ceiling".into()));
    }
    let url = input.price_url.clone().unwrap_or_else(|| {
        "https://api.coingecko.com/api/v3/simple/price?ids=usd-coin&vs_currencies=brl".into()
    });
    let body = http.get_json(&url)?;
    let brl_per_usdc = extract_brl_per_usdc(&body)?;
    if !(brl_per_usdc.is_finite() && brl_per_usdc > 0.0) {
        return Err(RpcError("invalid FX rate".into()));
    }
    let amount_usdc = input.amount_brl / brl_per_usdc;
    let amount_usdc_str = format_usdc(amount_usdc);
    Ok(QuoteResult {
        amount_brl: input.amount_brl,
        usdc_per_brl: 1.0 / brl_per_usdc,
        amount_usdc,
        amount_usdc_str,
    })
}

fn extract_brl_per_usdc(body: &Value) -> Result<f64, RpcError> {
    body.pointer("/usd-coin/brl")
        .and_then(Value::as_f64)
        .or_else(|| body.get("brl").and_then(Value::as_f64))
        .ok_or_else(|| RpcError("price JSON missing usd-coin.brl".into()))
}

pub fn format_usdc(amount: f64) -> String {
    // USDC has 6 decimals; round half-up via integer micros.
    let micros = (amount * 1_000_000.0).round() as i64;
    let whole = micros / 1_000_000;
    let frac = (micros % 1_000_000).unsigned_abs();
    format!("{whole}.{frac:06}")
}

/// Convert a decimal USDC string to base units (6 decimals).
pub fn usdc_to_base_units(amount: &str) -> Result<u64, String> {
    let (whole, frac) = match amount.split_once('.') {
        Some((w, f)) => (w, f),
        None => (amount, ""),
    };
    if whole.is_empty() || !whole.chars().all(|c| c.is_ascii_digit()) {
        return Err("invalid USDC amount".into());
    }
    if frac.chars().any(|c| !c.is_ascii_digit()) || frac.len() > 6 {
        return Err("invalid USDC decimals".into());
    }
    let whole_u: u64 = whole.parse().map_err(|_| "USDC amount too large")?;
    let mut frac_pad = frac.to_string();
    while frac_pad.len() < 6 {
        frac_pad.push('0');
    }
    let frac_u: u64 = frac_pad.parse().map_err(|_| "invalid USDC frac")?;
    whole_u
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(frac_u))
        .ok_or_else(|| "USDC amount overflow".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::MockHttpGet;
    use serde_json::json;

    #[test]
    fn quotes_brl() {
        let http = MockHttpGet {
            body: json!({ "usd-coin": { "brl": 5.0 } }),
        };
        let q = quote_brl_to_usdc(
            &http,
            &QuoteInput {
                amount_brl: 25.0,
                price_url: None,
            },
        )
        .unwrap();
        assert_eq!(q.amount_usdc_str, "5.000000");
    }

    #[test]
    fn base_units() {
        assert_eq!(usdc_to_base_units("25").unwrap(), 25_000_000);
        assert_eq!(usdc_to_base_units("25.5").unwrap(), 25_500_000);
        assert_eq!(usdc_to_base_units("0.000001").unwrap(), 1);
        assert!(usdc_to_base_units("1.1234567").is_err());
    }
}
