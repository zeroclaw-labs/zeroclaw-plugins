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
    Unknown,
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

    let mut maximum: Option<BoundedDecimal> = None;
    for pair in pairs.iter() {
        validate_pair(pair, mint)?;
        let liquidity = BoundedDecimal::parse(pair.liquidity.usd.get())?;

        if maximum
            .as_ref()
            .map(|current| liquidity.cmp(current).is_gt())
            .unwrap_or(true)
        {
            maximum = Some(liquidity);
        }
    }

    let status = match maximum.as_ref() {
        Some(number) if number.is_positive() => LiquidityStatus::Observed,
        _ => LiquidityStatus::NotObserved,
    };
    let max_liquidity_usd = maximum.map(|number| number.canonical);

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundedDecimal {
    canonical: String,
    integer: String,
    fraction: String,
}

impl BoundedDecimal {
    /// Accept only non-negative JSON decimals without exponent notation:
    /// `0|[1-9][0-9]*(\.[0-9]+)?`.
    fn parse(raw: &str) -> Result<Self, RiskError> {
        if raw.is_empty() || raw.len() > MAX_NUMBER_CHARS {
            return Err(RiskError::MalformedLiquidityResponse);
        }

        let (integer, fraction) = match raw.split_once('.') {
            Some((integer, fraction)) => (integer, Some(fraction)),
            None => (raw, None),
        };
        if !valid_integer(integer)
            || fraction.is_some_and(|fraction| {
                fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(RiskError::MalformedLiquidityResponse);
        }

        let fraction = fraction.unwrap_or_default();
        let canonical_fraction = fraction.trim_end_matches('0');
        let canonical = if canonical_fraction.is_empty() {
            integer.to_owned()
        } else {
            format!("{integer}.{canonical_fraction}")
        };

        Ok(Self {
            canonical,
            integer: integer.to_owned(),
            fraction: fraction.to_owned(),
        })
    }

    fn is_positive(&self) -> bool {
        self.integer != "0" || self.fraction.bytes().any(|byte| byte != b'0')
    }

    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self.is_positive(), other.is_positive()) {
            (false, false) => return std::cmp::Ordering::Equal,
            (false, true) => return std::cmp::Ordering::Less,
            (true, false) => return std::cmp::Ordering::Greater,
            (true, true) => {}
        }

        match self.integer.len().cmp(&other.integer.len()) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
        match self.integer.cmp(&other.integer) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }

        let scale = self.fraction.len().max(other.fraction.len());
        for index in 0..scale {
            match self
                .fraction_digit_at(index)
                .cmp(&other.fraction_digit_at(index))
            {
                std::cmp::Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        std::cmp::Ordering::Equal
    }

    fn fraction_digit_at(&self, index: usize) -> u8 {
        self.fraction.as_bytes().get(index).copied().unwrap_or(b'0')
    }
}

fn valid_integer(integer: &str) -> bool {
    integer == "0"
        || integer
            .strip_prefix(|character: char| character.is_ascii_digit() && character != '0')
            .is_some_and(|rest| rest.bytes().all(|byte| byte.is_ascii_digit()))
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
    usd: Box<serde_json::value::RawValue>,
}
