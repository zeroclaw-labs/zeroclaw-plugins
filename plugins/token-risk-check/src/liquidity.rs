use serde::Deserialize;

use crate::risk::{validate_mint, RiskError};

const DEXSCREENER_TOKEN_PAIRS_URL: &str = "https://api.dexscreener.com/token-pairs/v1/solana/";
const MAX_PAIRS: usize = 100;
const MAX_NUMBER_CHARS: usize = 32;
const MAX_FIELD_CHARS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityStatus {
    Observed,
    NotObserved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidityEvidence {
    pub status: LiquidityStatus,
    pub pair_count: usize,
    pub max_liquidity_usd: Option<String>,
    pub source: String,
}

pub fn liquidity_url(mint: &str) -> Result<String, RiskError> {
    validate_mint(mint)?;
    Ok(format!("{DEXSCREENER_TOKEN_PAIRS_URL}{mint}"))
}

pub fn assess_liquidity(mint: &str, body: &str) -> Result<LiquidityEvidence, RiskError> {
    validate_mint(mint)?;

    let pairs: Vec<DexPair> =
        serde_json::from_str(body).map_err(|_| RiskError::MalformedLiquidityResponse)?;
    if pairs.len() > MAX_PAIRS {
        return Err(RiskError::MalformedLiquidityResponse);
    }

    let mut maximum: Option<(serde_json::Number, String)> = None;
    for pair in pairs.iter() {
        validate_pair(pair, mint)?;
        let liquidity = pair.liquidity.usd.clone();
        let serialized = liquidity.to_string();
        if serialized.len() > MAX_NUMBER_CHARS || !is_finite_non_negative(&liquidity) {
            return Err(RiskError::MalformedLiquidityResponse);
        }

        if maximum
            .as_ref()
            .map(|(current, _)| compare_numbers(&liquidity, current).is_gt())
            .unwrap_or(true)
        {
            maximum = Some((liquidity, serialized));
        }
    }

    let status = match maximum.as_ref() {
        Some((number, _)) if is_positive(number) => LiquidityStatus::Observed,
        _ => LiquidityStatus::NotObserved,
    };
    let max_liquidity_usd = maximum.map(|(_, serialized)| serialized);

    Ok(LiquidityEvidence {
        status,
        pair_count: pairs.len(),
        max_liquidity_usd,
        source: "dexscreener".to_owned(),
    })
}

fn validate_pair(pair: &DexPair, mint: &str) -> Result<(), RiskError> {
    if pair.chain_id != "solana"
        || pair.chain_id.len() > MAX_FIELD_CHARS
        || pair.pair_address.len() > MAX_FIELD_CHARS
        || pair.base_token.address.len() > MAX_FIELD_CHARS
        || pair.quote_token.address.len() > MAX_FIELD_CHARS
        || (pair.base_token.address != mint && pair.quote_token.address != mint)
    {
        return Err(RiskError::MalformedLiquidityResponse);
    }
    validate_mint(&pair.pair_address).map_err(|_| RiskError::MalformedLiquidityResponse)
}

fn is_finite_non_negative(number: &serde_json::Number) -> bool {
    match number.as_f64() {
        Some(value) => value.is_finite() && value >= 0.0,
        None => number.as_u64().is_some(),
    }
}

fn compare_numbers(left: &serde_json::Number, right: &serde_json::Number) -> std::cmp::Ordering {
    match (left.as_u64(), right.as_u64()) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => left
            .as_f64()
            .expect("validated finite number")
            .total_cmp(&right.as_f64().expect("validated finite number")),
    }
}

fn is_positive(number: &serde_json::Number) -> bool {
    number
        .as_u64()
        .map(|value| value > 0)
        .unwrap_or_else(|| number.as_f64().is_some_and(|value| value > 0.0))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DexPair {
    chain_id: String,
    pair_address: String,
    base_token: DexToken,
    quote_token: DexToken,
    liquidity: DexLiquidity,
}

#[derive(Deserialize)]
struct DexToken {
    address: String,
}

#[derive(Deserialize)]
struct DexLiquidity {
    usd: serde_json::Number,
}
