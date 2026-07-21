use serde_json::Value;
use std::borrow::Cow;
use std::collections::BTreeSet;

use crate::model::LiquidityEvidence;
use crate::solana::validate_mint;

pub const MAX_LIQUIDITY_PAIRS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiquidityError {
    InvalidShape,
    BoundExceeded,
}

pub fn parse_usd_micros(value: &Value) -> Result<u128, LiquidityError> {
    let text: Cow<'_, str> = match value {
        Value::String(v) => Cow::Borrowed(v),
        Value::Number(v) => Cow::Owned(v.to_string()),
        _ => return Err(LiquidityError::InvalidShape),
    };
    let text = text.as_ref();
    if text.is_empty() || text.len() > 32 || text.starts_with('-') || text.contains(['e', 'E']) {
        return Err(LiquidityError::InvalidShape);
    }
    let mut split = text.split('.');
    let whole = split.next().ok_or(LiquidityError::InvalidShape)?;
    let fraction = split.next().unwrap_or("");
    if split.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 6
    {
        return Err(LiquidityError::InvalidShape);
    }
    let whole = whole
        .parse::<u128>()
        .map_err(|_| LiquidityError::BoundExceeded)?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u128>()
            .map_err(|_| LiquidityError::InvalidShape)?
            * 10_u128.pow((6 - fraction.len()) as u32)
    };
    whole
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(fraction))
        .ok_or(LiquidityError::BoundExceeded)
}

pub fn parse_liquidity(mint: &str, body: &str) -> Result<LiquidityEvidence, LiquidityError> {
    validate_mint(mint).map_err(|_| LiquidityError::InvalidShape)?;
    let rows: Value = serde_json::from_str(body).map_err(|_| LiquidityError::InvalidShape)?;
    let rows = rows.as_array().ok_or(LiquidityError::InvalidShape)?;
    if rows.len() > MAX_LIQUIDITY_PAIRS {
        return Err(LiquidityError::BoundExceeded);
    }
    let mut indexed = 0_usize;
    let mut positive = 0_usize;
    let mut total = 0_u128;
    let mut pair_addresses = BTreeSet::new();
    for row in rows {
        if row.get("chainId").and_then(Value::as_str) != Some("solana") {
            continue;
        }
        let base = row
            .get("baseToken")
            .and_then(|v| v.get("address"))
            .and_then(Value::as_str);
        let quote = row
            .get("quoteToken")
            .and_then(|v| v.get("address"))
            .and_then(Value::as_str);
        if base != Some(mint) && quote != Some(mint) {
            continue;
        }
        let pair_address = row
            .get("pairAddress")
            .and_then(Value::as_str)
            .ok_or(LiquidityError::InvalidShape)?;
        if pair_address.is_empty()
            || pair_address.len() > 128
            || !pair_addresses.insert(pair_address)
        {
            return Err(LiquidityError::InvalidShape);
        }
        indexed += 1;
        let usd = row
            .get("liquidity")
            .and_then(|v| v.get("usd"))
            .ok_or(LiquidityError::InvalidShape)
            .and_then(parse_usd_micros)?;
        if usd > 0 {
            positive += 1;
        }
        total = total
            .checked_add(usd)
            .ok_or(LiquidityError::BoundExceeded)?;
    }
    Ok(LiquidityEvidence {
        status: if positive > 0 {
            "observed"
        } else {
            "not_observed"
        },
        indexed_pair_count: indexed,
        positive_pair_count: positive,
        total_liquidity_usd_micros: Some(total.to_string()),
        lp_control_status: "unknown_not_inferred_from_indexed_pairs",
    })
}
