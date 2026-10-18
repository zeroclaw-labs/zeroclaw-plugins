use liquidation_guard::health::{assess, PositionFacts, PriorSnapshotFacts, Thresholds, Tier};

fn thresholds() -> Thresholds {
    Thresholds {
        watch: 0.25,
        warn: 0.15,
        critical: 0.07,
    }
}

fn facts() -> PositionFacts {
    PositionFacts {
        ltv: 0.5,
        liq_ltv: 0.8,
        borrow_usd: 500.0,
        deposit_usd: 1000.0,
        collateral_symbol: "SOL".to_string(),
        debt_symbol: "USDC".to_string(),
        collateral_price: 100.0,
        // Matches collateral_price so tests written before F1 (debt-rise
        // denominated in debt_price, not collateral_price) keep the same
        // expected numbers; `debt_rise_denominated_in_debt_price` below
        // overrides this to prove the two are independent.
        debt_price: 100.0,
        lst_stake_rate: None,
        multi_volatile_collateral: false,
        elevation_group: 0,
        adl_assets: Vec::new(),
        position_value_usd: 1000.0,
        min_full_liquidation_value_usd: Some(2.0),
        borrow_apy: None,
        utilization: None,
    }
}

/// harden F13: percents leaking into these fraction-only modules produce a
/// wildly wrong buffer. liq_ltv=0.799, ltv=0.755 -> buffer ~5.5%, well under
/// the 7% critical threshold -> CRITICAL. If a caller passed 79.9/75.5
/// (percent, not fraction) the buffer would come out totally different.
#[test]
fn fraction_units_regression() {
    let mut f = facts();
    f.liq_ltv = 0.799;
    f.ltv = 0.755;
    let report = assess(&f, None, &thresholds());
    assert!(!report.buffer.is_nan());
    assert!(
        (report.buffer - 0.0550_688).abs() < 1e-4,
        "buffer was {}",
        report.buffer
    );
    assert!(report.buffer < 0.07);
    assert_eq!(report.tier, Tier::Critical);
}

#[test]
fn tier_boundaries_exact() {
    let t = thresholds();
    // liq_ltv = 1.0 so buffer == (1 - ltv), easy to hit exact boundaries.
    let mut f = facts();
    f.liq_ltv = 1.0;

    f.ltv = 1.0 - 0.25; // buffer == watch
    assert_eq!(assess(&f, None, &t).tier, Tier::Ok);

    f.ltv = 1.0 - 0.15; // buffer == warn
    assert_eq!(assess(&f, None, &t).tier, Tier::Watch);

    f.ltv = 1.0 - 0.07; // buffer == critical
    assert_eq!(assess(&f, None, &t).tier, Tier::Warn);

    f.ltv = 1.0 - 0.05; // below critical
    assert_eq!(assess(&f, None, &t).tier, Tier::Critical);
}

#[test]
fn both_forecast_directions() {
    let f = facts(); // collateral_price=100, ltv=0.5, liq_ltv=0.8
    let report = assess(&f, None, &thresholds());
    assert!((report.liq_price_collateral_drop.unwrap() - 62.5).abs() < 1e-9);
    assert!((report.liq_price_debt_rise.unwrap() - 160.0).abs() < 1e-9);
    assert!(report.sol_spot_price.is_none());
}

/// harden F1: debt-rise must be denominated in the debt asset's own price,
/// never the collateral's — the two are unrelated assets (a stablecoin debt
/// against BTC collateral, say).
#[test]
fn debt_rise_denominated_in_debt_price() {
    let mut f = facts(); // collateral_price=100, ltv=0.5, liq_ltv=0.8
    f.debt_price = 1.0; // a stablecoin, wildly different from collateral_price
    let report = assess(&f, None, &thresholds());
    // debt_price * liq_ltv / ltv = 1.0 * 0.8 / 0.5 = 1.6, NOT 160.0 (which
    // is what collateral_price * liq_ltv / ltv would give).
    assert!(
        (report.liq_price_debt_rise.unwrap() - 1.6).abs() < 1e-9,
        "liq_price_debt_rise was {:?}, expected 1.6 (debt_price-denominated)",
        report.liq_price_debt_rise
    );
}

/// The COLLATERAL-drop forecast converts to the SOL level and exposes the
/// matching SOL spot; the DEBT-rise forecast is untouched.
#[test]
fn lst_forecast_converts_collateral_only_and_exposes_sol_spot() {
    let mut f = facts(); // collateral_price=100, debt_price=200, ltv=0.5, liq_ltv=0.8
    f.lst_stake_rate = Some(1.25);
    let report = assess(&f, None, &thresholds());
    assert_eq!(report.sol_spot_price, Some(100.0 / 1.25));
    assert!((report.liq_price_collateral_drop.unwrap() - 62.5 / 1.25).abs() < 1e-9);
}

/// harden DEFECT-1: the collateral's stake rate must NEVER touch the
/// debt-rise forecast. A JitoSOL-collateral / stablecoin-debt position is
/// the common Kamino shape, and dividing a $1.00 stablecoin threshold by a
/// ~1.2 SOL stake rate is dimensionally meaningless.
#[test]
fn lst_stake_rate_never_applied_to_debt_rise() {
    let mut f = facts();
    f.debt_price = 1.0; // stablecoin debt
    f.lst_stake_rate = Some(1.25); // LST collateral
    let report = assess(&f, None, &thresholds());
    // debt_price * liq_ltv / ltv = 1.0 * 0.8 / 0.5 = 1.6 — NOT 1.6 / 1.25.
    assert!(
        (report.liq_price_debt_rise.unwrap() - 1.6).abs() < 1e-9,
        "debt-rise was {:?}, expected 1.6 (undivided by the collateral stake rate)",
        report.liq_price_debt_rise
    );
}

/// An infinite LTV must produce the CRITICAL *verdict*, not merely a
/// non-finite number.
///
/// `tests/kamino.rs::zero_liquidatable_deposit_with_debt_is_not_healthy`
/// pins the mapping (zero liquidatable deposit + outstanding debt -> infinite
/// `ltv`) but asserts an intermediate value. That is not the guarantee that
/// matters: clamping the buffer here — a plausible "fix" for the `-inf`
/// render — would restore the original fail-open bug, where the most
/// liquidatable state on record reported `OK — buffer 100%`, and that test
/// would still pass. This pins the user-visible tier instead.
#[test]
fn infinite_ltv_is_critical_not_ok() {
    let mut f = facts();
    f.ltv = f64::INFINITY;
    let report = assess(&f, None, &thresholds());

    assert_eq!(
        report.tier,
        Tier::Critical,
        "infinite LTV must be CRITICAL, got {:?} at buffer {}",
        report.tier,
        report.buffer
    );
    assert!(
        !report.buffer.is_finite(),
        "an infinite LTV has no finite buffer; clamping it hides the state: {}",
        report.buffer
    );
    // NEITHER forecast may render a price. The debt-rise line is the subtle
    // one: `debt_price * liq_ltv / INFINITY` is exactly 0.0, which IS finite,
    // so an `is_finite` filter alone lets it through and the report prints a
    // fabricated "Liquidated if USDC > $0.00". It must be suppressed outright.
    assert_eq!(report.liq_price_collateral_drop, None);
    assert_eq!(
        report.liq_price_debt_rise, None,
        "an infinite LTV must suppress the debt-rise line, not print $0.00"
    );
}

/// The SOL-level conversion divides by the stake rate, and both absolute
/// values are pinned.
///
/// The denomination-invariance check below is necessary but NOT sufficient on
/// its own: the implementation divides the threshold and the spot by the same
/// rate, so their ratio is invariant *by construction* — flipping both `/
/// rate` to `* rate`, the exact sign error this is meant to catch, preserves
/// it and passes. So the absolutes are asserted first, derived here from the
/// definition rather than from the implementation: a stake rate of 1.25 means
/// 1 LST is worth 1.25 SOL, so an LST priced at $100 implies SOL at
/// $100/1.25 = $80, and the LST-level liquidation threshold of
/// `100 * 0.5/0.8 = $62.50` sits at `62.50/1.25 = $50` of SOL. A multiply
/// would give $78.125 and $125.
#[test]
fn sol_level_conversion_divides_by_the_stake_rate() {
    let mut f = facts();
    let token_level = assess(&f, None, &thresholds());
    let token_drop = token_level.liq_price_collateral_drop.unwrap();
    assert!(
        (token_drop - 62.5).abs() < 1e-12,
        "LST-level threshold was {token_drop}, expected 62.5"
    );

    f.lst_stake_rate = Some(1.25);
    let sol_level = assess(&f, None, &thresholds());
    let sol_drop = sol_level.liq_price_collateral_drop.unwrap();
    let sol_spot = sol_level.sol_spot_price.unwrap();
    assert!(
        (sol_drop - 50.0).abs() < 1e-12,
        "SOL-level threshold was {sol_drop}, expected 50.0 (62.5 / 1.25)"
    );
    assert!(
        (sol_spot - 80.0).abs() < 1e-12,
        "SOL spot was {sol_spot}, expected 80.0 (100.0 / 1.25)"
    );

    // And the required move is unchanged by the change of denomination.
    let token_move = token_drop / f.collateral_price;
    let sol_move = sol_drop / sol_spot;
    assert!(
        (token_move - sol_move).abs() < 1e-12,
        "required move changed with denomination: {token_move} vs {sol_move}"
    );
}

#[test]
fn guarded_division_zero_liq_ltv_is_nan_free() {
    let mut f = facts();
    f.liq_ltv = 0.0;
    let report = assess(&f, None, &thresholds());
    assert!(!report.buffer.is_nan());
    assert_eq!(report.buffer, 0.0);
    assert!(report.liq_price_collateral_drop.is_none());
    // ltv is still nonzero here, so debt-rise is well-defined (P*0/ltv = 0),
    // not None -- only liq_ltv == 0 disables the collateral-drop forecast.
    assert!(!report.liq_price_debt_rise.unwrap().is_nan());
    assert_eq!(report.tier, Tier::Critical);
}

#[test]
fn guarded_division_zero_ltv_is_nan_free() {
    let mut f = facts();
    f.ltv = 0.0;
    let report = assess(&f, None, &thresholds());
    assert!(!report.buffer.is_nan());
    assert!(report.liq_price_debt_rise.is_none());
    assert!(report.liq_price_collateral_drop.is_some());
    assert!(!report.liq_price_collateral_drop.unwrap().is_nan());
}

#[test]
fn guarded_division_zero_deposit_usd_is_nan_free() {
    let mut f = facts();
    f.deposit_usd = 0.0;
    let report = assess(&f, None, &thresholds());
    assert!(!report.buffer.is_nan());
    assert!(!report.liq_price_collateral_drop.unwrap().is_nan());
    assert!(!report.liq_price_debt_rise.unwrap().is_nan());
}

fn prior() -> PriorSnapshotFacts {
    PriorSnapshotFacts {
        ltv: 0.45,
        liq_ltv: 0.8,
        collateral_price: 100.0,
        elevation_group: 0,
    }
}

#[test]
fn interest_drift_only_at_flat_prices() {
    let f = facts(); // ltv=0.5, collateral_price=100 (flat vs prior)
    let report = assess(&f, Some(&prior()), &thresholds());
    assert!((report.interest_drift.unwrap() - (0.5 - 0.45)).abs() < 1e-9);
}

#[test]
fn interest_drift_none_when_price_moved() {
    let mut f = facts();
    f.collateral_price = 105.0; // 5% move, well above the 1% flat-price band
    let report = assess(&f, Some(&prior()), &thresholds());
    assert!(report.interest_drift.is_none());
}

#[test]
fn interest_drift_none_without_prior() {
    let f = facts();
    let report = assess(&f, None, &thresholds());
    assert!(report.interest_drift.is_none());
}

#[test]
fn param_alert_fires_on_liq_ltv_change() {
    let f = facts(); // liq_ltv=0.8, prior liq_ltv=0.8 -> no alert by default
    let report = assess(&f, Some(&prior()), &thresholds());
    assert!(report.param_alert.is_none());

    let mut f2 = facts();
    f2.liq_ltv = 0.78;
    let report2 = assess(&f2, Some(&prior()), &thresholds());
    assert!(report2.param_alert.is_some());
}

#[test]
fn param_alert_fires_on_elevation_group_change_independent_of_tier() {
    let mut f = facts();
    f.elevation_group = 3; // prior elevation_group = 0, everything else flat/healthy
    let report = assess(&f, Some(&prior()), &thresholds());
    assert!(report.param_alert.is_some());
    assert_eq!(report.tier, Tier::Ok);
}

#[test]
fn adl_warning_flags_matching_symbol() {
    let mut f = facts();
    f.adl_assets = vec!["USDC".to_string()];
    let report = assess(&f, None, &thresholds());
    assert!(report.adl_warning.is_some());

    let mut f2 = facts();
    f2.adl_assets = vec!["BONK".to_string()];
    let report2 = assess(&f2, None, &thresholds());
    assert!(report2.adl_warning.is_none());
}

#[test]
fn dust_warning_below_threshold() {
    let mut f = facts();
    f.position_value_usd = 1.0;
    f.min_full_liquidation_value_usd = Some(2.0);
    let report = assess(&f, None, &thresholds());
    assert!(report.dust_warning);

    let mut f2 = facts();
    f2.position_value_usd = 3.0;
    f2.min_full_liquidation_value_usd = Some(2.0);
    let report2 = assess(&f2, None, &thresholds());
    assert!(!report2.dust_warning);
}

/// harden F5: a missing dust threshold (payload didn't carry the field)
/// suppresses the warning outright — never a fabricated default, never a
/// false positive from treating "unknown" as "below".
#[test]
fn dust_warning_suppressed_when_threshold_absent() {
    let mut f = facts();
    f.position_value_usd = 0.01; // would trip any real threshold
    f.min_full_liquidation_value_usd = None;
    let report = assess(&f, None, &thresholds());
    assert!(!report.dust_warning);
}

/// harden F2: `borrow_apy`/`utilization` are a pure pass-through onto
/// `HealthReport` — no new math, no fabrication when absent.
#[test]
fn borrow_apy_and_utilization_pass_through() {
    let mut f = facts();
    f.borrow_apy = Some(0.123);
    f.utilization = Some(0.81);
    let report = assess(&f, None, &thresholds());
    assert_eq!(report.borrow_apy, Some(0.123));
    assert_eq!(report.utilization, Some(0.81));

    let f2 = facts(); // both None by default
    let report2 = assess(&f2, None, &thresholds());
    assert_eq!(report2.borrow_apy, None);
    assert_eq!(report2.utilization, None);
}

#[test]
fn correlated_move_assumption_mirrors_input() {
    let mut f = facts();
    f.multi_volatile_collateral = true;
    let report = assess(&f, None, &thresholds());
    assert!(report.correlated_move_assumption);
}
