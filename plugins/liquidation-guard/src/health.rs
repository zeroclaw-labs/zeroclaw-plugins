//! Pure health math: buffer/tier, both liquidation-price forecast
//! directions, interest drift, and parameter/ADL/dust flags for a Kamino
//! Lend obligation.
//!
//! No I/O, no `crate::kamino`/`crate::net` imports — the pipeline slice
//! adapts decoded Kamino facts into [`PositionFacts`]. Every ratio here is a
//! FRACTION (0.799, not 79.9); config thresholds arrive as fractions too.

/// Snapshot of a Kamino obligation, already borrow-factor-adjusted.
pub struct PositionFacts {
    /// Fraction; borrow-factor-adjusted.
    pub ltv: f64,
    /// Fraction.
    pub liq_ltv: f64,
    /// BF-adjusted total borrow, USD.
    pub borrow_usd: f64,
    /// Total liquidatable deposit, USD.
    pub deposit_usd: f64,
    pub collateral_symbol: String,
    pub debt_symbol: String,
    /// Kamino oracle price, USD per ui token.
    pub collateral_price: f64,
    /// Kamino oracle price, USD per ui token, dominant debt asset.
    pub debt_price: f64,
    /// SOL per LST token, when collateral is an LST.
    pub lst_stake_rate: Option<f64>,
    pub multi_volatile_collateral: bool,
    pub elevation_group: u8,
    /// Symbols with autodeleverageEnabled.
    pub adl_assets: Vec<String>,
    pub position_value_usd: f64,
    /// Dust threshold from the payload (`market.state.
    /// minFullLiquidationValueThreshold`); `None` when the payload doesn't
    /// carry it -> dust check suppressed, never a fabricated default.
    pub min_full_liquidation_value_usd: Option<f64>,
    /// Fraction, from /reserves/metrics.
    pub borrow_apy: Option<f64>,
    /// Fraction, totalBorrow/totalSupply.
    pub utilization: Option<f64>,
}

/// Decoded from the operator-supplied `prev_snapshot` by the pipeline.
pub struct PriorSnapshotFacts {
    pub ltv: f64,
    pub liq_ltv: f64,
    pub collateral_price: f64,
    pub elevation_group: u8,
}

/// Tier thresholds, fractions.
pub struct Thresholds {
    pub watch: f64,
    pub warn: f64,
    pub critical: f64,
}

#[derive(PartialEq, Debug)]
pub enum Tier {
    Ok,
    Watch,
    Warn,
    Critical,
}

pub struct HealthReport {
    /// `(liq_ltv - ltv) / liq_ltv`.
    pub buffer: f64,
    pub tier: Tier,
    /// `P * ltv / liq_ltv`.
    pub liq_price_collateral_drop: Option<f64>,
    /// `P * liq_ltv / ltv`, always in the DEBT asset's own price — the
    /// collateral's stake rate is unrelated to it and never applied.
    pub liq_price_debt_rise: Option<f64>,
    /// `Some(collateral_price / lst_stake_rate)` when the collateral-drop
    /// forecast was converted to the underlying SOL level: the current SOL
    /// spot, so the renderer can quote threshold AND spot in the SAME
    /// denomination. `None` = no conversion happened.
    pub sol_spot_price: Option<f64>,
    /// LTV delta vs prior at ~flat prices (`|ΔP/P| < 1%`).
    pub interest_drift: Option<f64>,
    /// Fraction, from `/reserves/metrics`, pass-through of
    /// `PositionFacts.borrow_apy` for the drift line's parenthetical.
    pub borrow_apy: Option<f64>,
    /// Fraction, pass-through of `PositionFacts.utilization`.
    pub utilization: Option<f64>,
    /// `liq_ltv` or `elevation_group` changed vs prior.
    pub param_alert: Option<String>,
    pub adl_warning: Option<String>,
    /// `position_value_usd < min_full_liquidation_value_usd`.
    pub dust_warning: bool,
    /// `== multi_volatile_collateral`.
    pub correlated_move_assumption: bool,
}

fn tier_for(buffer: f64, t: &Thresholds) -> Tier {
    if buffer >= t.watch {
        Tier::Ok
    } else if buffer >= t.warn {
        Tier::Watch
    } else if buffer >= t.critical {
        Tier::Warn
    } else {
        Tier::Critical
    }
}

/// Assess a position's health. Total function: no I/O, no NaN on zero
/// denominators (`liq_ltv == 0` clamps buffer to 0.0 and disables both
/// forecasts; `ltv == 0` disables the debt-rise forecast only).
pub fn assess(
    f: &PositionFacts,
    prior: Option<&PriorSnapshotFacts>,
    t: &Thresholds,
) -> HealthReport {
    let buffer = if f.liq_ltv == 0.0 {
        0.0
    } else {
        (f.liq_ltv - f.ltv) / f.liq_ltv
    };
    let tier = tier_for(buffer, t);

    // Both forecasts are suppressed unless they come out finite: an
    // obligation with debt and zero liquidatable deposit has an infinite
    // `ltv` (the honest value — see `kamino::map_obligation`), and
    // `$inf` is not a price anyone can watch for.
    let mut liq_price_collateral_drop = if f.liq_ltv == 0.0 {
        None
    } else {
        Some(f.collateral_price * f.ltv / f.liq_ltv)
    }
    .filter(|p| p.is_finite());
    // A non-finite `ltv` must suppress this line too, not merely survive the
    // `is_finite` filter below: `debt_price * liq_ltv / INFINITY` is exactly
    // `0.0`, which IS finite, so an infinitely-levered position would print
    // "Liquidated if USDG > $0.00" — a fabricated threshold, and the one
    // number this module must never invent.
    let liq_price_debt_rise = if f.ltv == 0.0 || !f.ltv.is_finite() {
        None
    } else {
        Some(f.debt_price * f.liq_ltv / f.ltv)
    }
    .filter(|p| p.is_finite());

    // LST collateral: Kamino prices LSTs by stake rate, never spot — so a
    // "JitoSOL price fall" is really SOL falling, and SOL is the level the
    // user can actually watch on an exchange. Convert the COLLATERAL-drop
    // forecast only, and hand out the matching SOL spot so the renderer
    // quotes threshold and spot in one denomination.
    //
    // The debt-rise forecast is NOT converted: it is denominated in the debt
    // asset's own oracle price, which has nothing to do with the
    // collateral's stake rate (USDG debt against JitoSOL collateral would
    // otherwise be quoted at 1/rate of its real level).
    let mut sol_spot_price = None;
    if let Some(rate) = f.lst_stake_rate {
        if rate != 0.0 {
            liq_price_collateral_drop = liq_price_collateral_drop.map(|p| p / rate);
            sol_spot_price = Some(f.collateral_price / rate);
        }
    }

    let interest_drift = prior.and_then(|p| {
        if p.collateral_price == 0.0 {
            return None;
        }
        let move_frac = (f.collateral_price - p.collateral_price).abs() / p.collateral_price;
        (move_frac < 0.01).then_some(f.ltv - p.ltv)
    });

    let param_alert = prior.and_then(|p| {
        let liq_ltv_changed = f.liq_ltv != p.liq_ltv;
        let group_changed = f.elevation_group != p.elevation_group;
        if !liq_ltv_changed && !group_changed {
            return None;
        }
        let mut parts = Vec::new();
        if liq_ltv_changed {
            parts.push(format!("liq_ltv {} -> {}", p.liq_ltv, f.liq_ltv));
        }
        if group_changed {
            parts.push(format!(
                "elevation_group {} -> {}",
                p.elevation_group, f.elevation_group
            ));
        }
        Some(parts.join(", "))
    });

    let hit: Vec<&str> = f
        .adl_assets
        .iter()
        .map(String::as_str)
        .filter(|s| *s == f.collateral_symbol || *s == f.debt_symbol)
        .collect();
    let adl_warning =
        (!hit.is_empty()).then(|| format!("autodeleverage enabled on: {}", hit.join(", ")));

    let dust_warning = f
        .min_full_liquidation_value_usd
        .is_some_and(|threshold| f.position_value_usd < threshold);

    HealthReport {
        buffer,
        tier,
        liq_price_collateral_drop,
        liq_price_debt_rise,
        sol_spot_price,
        interest_drift,
        borrow_apy: f.borrow_apy,
        utilization: f.utilization,
        param_alert,
        adl_warning,
        dust_warning,
        correlated_move_assumption: f.multi_volatile_collateral,
    }
}
