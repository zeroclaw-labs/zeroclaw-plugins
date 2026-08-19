use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TokenSignals {
    pub mint_authority_present: bool,
    pub freeze_authority_present: bool,
    pub holder_count: u64,
    pub top_holder_bps: u16,
    pub liquidity_usd_cents: u64,
    pub metadata_verified: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RiskReport {
    pub score: u8,
    pub level: &'static str,
    pub flags: Vec<&'static str>,
}

pub fn assess(s: &TokenSignals) -> RiskReport {
    let mut score: u16 = 0;
    let mut flags = Vec::new();
    if s.mint_authority_present {
        score += 25;
        flags.push("mint_authority_enabled");
    }
    if s.freeze_authority_present {
        score += 25;
        flags.push("freeze_authority_enabled");
    }
    if s.holder_count < 25 {
        score += 15;
        flags.push("few_holders");
    }
    if s.top_holder_bps >= 5000 {
        score += 20;
        flags.push("concentrated_holders");
    }
    if s.liquidity_usd_cents < 10_000 {
        score += 10;
        flags.push("thin_liquidity");
    }
    if !s.metadata_verified {
        score += 5;
        flags.push("metadata_unverified");
    }
    let score = score.min(100) as u8;
    let level = match score {
        0..=24 => "low",
        25..=49 => "medium",
        50..=74 => "high",
        _ => "critical",
    };
    RiskReport {
        score,
        level,
        flags,
    }
}

/// Extracts the safe, provider-independent portion of a parsed SPL mint account.
/// Missing optional fields remain conservative (authority present/metadata unverified).
pub fn signals_from_mint_account(account: &Value) -> Result<TokenSignals, &'static str> {
    let info = account
        .pointer("/value/data/parsed/info")
        .ok_or("missing parsed mint info")?;
    let supply = info
        .get("supply")
        .and_then(Value::as_str)
        .ok_or("missing mint supply")?
        .parse::<u64>()
        .map_err(|_| "invalid mint supply")?;
    let _decimals = info
        .get("decimals")
        .and_then(Value::as_u64)
        .ok_or("missing mint decimals")?;
    let _ = supply;
    Ok(TokenSignals {
        mint_authority_present: !info.get("mintAuthority").is_some_and(Value::is_null),
        freeze_authority_present: !info.get("freezeAuthority").is_some_and(Value::is_null),
        metadata_verified: false,
        ..Default::default()
    })
}

pub fn holder_stats(accounts: &Value) -> Result<(u64, u16), &'static str> {
    let rows = accounts
        .as_array()
        .ok_or("holder account result is not an array")?;
    let mut amounts = Vec::with_capacity(rows.len());
    for row in rows {
        let amount = row
            .pointer("/account/data/parsed/info/tokenAmount/amount")
            .and_then(Value::as_str)
            .ok_or("holder amount missing")?
            .parse::<u128>()
            .map_err(|_| "holder amount invalid")?;
        if amount > 0 {
            amounts.push(amount);
        }
    }
    let total: u128 = amounts.iter().sum();
    let top = amounts.into_iter().max().unwrap_or(0);
    let bps = top
        .saturating_mul(10_000)
        .checked_div(total)
        .unwrap_or(0)
        .min(10_000) as u16;
    Ok((rows.len() as u64, bps))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clean_token_is_low_risk() {
        let r = assess(&TokenSignals {
            holder_count: 1_000,
            top_holder_bps: 1200,
            liquidity_usd_cents: 2_000_000,
            metadata_verified: true,
            ..Default::default()
        });
        assert_eq!(r.level, "low");
        assert!(r.flags.is_empty());
    }
    #[test]
    fn dangerous_controls_and_concentration_are_critical() {
        let r = assess(&TokenSignals {
            mint_authority_present: true,
            freeze_authority_present: true,
            holder_count: 2,
            top_holder_bps: 9000,
            ..Default::default()
        });
        assert_eq!(r.level, "critical");
        assert_eq!(r.score, 100);
        assert!(r.flags.contains(&"freeze_authority_enabled"));
    }

    #[test]
    fn parses_mint_authorities_conservatively() {
        let value: Value = serde_json::json!({"value":{"data":{"parsed":{"info":{
            "mintAuthority":"Auth", "freezeAuthority":null, "supply":"1000", "decimals":6
        }}}}});
        let s = signals_from_mint_account(&value).unwrap();
        assert!(s.mint_authority_present);
        assert!(!s.freeze_authority_present);
        assert!(!s.metadata_verified);
    }
    #[test]
    fn computes_holder_concentration_without_float() {
        let v = serde_json::json!([
            {"account":{"data":{"parsed":{"info":{"tokenAmount":{"amount":"900"}}}}}},
            {"account":{"data":{"parsed":{"info":{"tokenAmount":{"amount":"100"}}}}}}
        ]);
        assert_eq!(holder_stats(&v).unwrap(), (2, 9000));
    }
}
