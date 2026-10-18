//! Pure remedy-ranking math: given current position facts and the WATCH
//! threshold, compute ranked repay/deposit remedies with simulated
//! outcomes.
//!
//! No I/O, no `crate::kamino`/`crate::net` imports — the pipeline slice
//! adapts decoded Kamino facts into [`RemedyInput`]. Only two remedy kinds
//! may ever be raised (spec safety invariant 3); a third, exposure-reducing
//! kind is structurally excluded from this module.

/// Facts needed to rank remedies. Ratios are fractions (0.799, not 79.9).
pub struct RemedyInput {
    pub borrow_usd: f64,
    pub deposit_usd: f64,
    pub liq_ltv: f64,
    /// WATCH threshold, fraction.
    pub watch: f64,
    pub debt_symbol: String,
    /// USD per ui token.
    pub debt_price: f64,
    pub collateral_symbol: String,
    pub collateral_price: f64,
    /// Config cap on repay ui amount; `None` disables the rescue
    /// transaction (the repay remedy is still computed and printed).
    pub max_repay_ui: Option<f64>,
    /// Deposit remedy increases exposure to a falling asset.
    pub collateral_is_falling: bool,
}

#[derive(PartialEq, Debug)]
pub enum RemedyKind {
    Repay,
    Deposit,
}

pub struct Remedy {
    pub kind: RemedyKind,
    /// Token amount to repay / deposit.
    pub ui_amount: f64,
    /// Simulated resulting LTV.
    pub resulting_ltv: f64,
    /// Simulated resulting buffer.
    pub resulting_buffer: f64,
    /// Wallet balance required.
    pub needs_balance_ui: f64,
    pub capped_by_max_repay: bool,
}

fn safe_div(numerator: f64, denominator: f64) -> f64 {
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

/// Simulate the resulting LTV/buffer for a hypothetical borrow/deposit pair.
///
/// Zero deposit with debt remaining has no finite LTV, and `safe_div`'s 0.0
/// fallback was the wrong answer here: it reported `ltv = 0` and therefore
/// `buffer = (liq_ltv - 0) / liq_ltv = 100%`, so `check` printed a
/// fully-healthy remedy outcome — "Repay 5000 USDG -> LTV 0.0%, buffer
/// 100.0%" — two lines under its own "no liquidatable collateral backing an
/// outstanding debt" verdict, on the same report. Infinity is the honest
/// value: it renders as `n/a` rather than a fabricated number, and matches how
/// `kamino::map_obligation` reports exactly this state.
fn simulate(borrow_usd: f64, deposit_usd: f64, liq_ltv: f64) -> (f64, f64) {
    let ltv = if deposit_usd != 0.0 {
        borrow_usd / deposit_usd
    } else if borrow_usd > 0.0 {
        f64::INFINITY
    } else {
        0.0
    };
    let buffer = safe_div(liq_ltv - ltv, liq_ltv);
    (ltv, buffer)
}

/// Rank remedies that restore the position to the WATCH boundary
/// (`t = liq_ltv * (1 - watch)`), never "just under the line" (no grace
/// period; liquidation rounds repeat). Returns an empty vec when the
/// position is already at/above the WATCH buffer.
pub fn rank(i: &RemedyInput) -> Vec<Remedy> {
    let t = i.liq_ltv * (1.0 - i.watch);

    let repay_delta_usd = i.borrow_usd - t * i.deposit_usd;
    if repay_delta_usd <= 0.0 {
        return Vec::new();
    }

    let mut repay_ui = safe_div(repay_delta_usd, i.debt_price);
    let mut capped_by_max_repay = false;
    if let Some(cap) = i.max_repay_ui {
        if repay_ui > cap {
            repay_ui = cap;
            capped_by_max_repay = true;
        }
    }
    let (repay_ltv, repay_buffer) = simulate(
        i.borrow_usd - repay_ui * i.debt_price,
        i.deposit_usd,
        i.liq_ltv,
    );
    let repay = Remedy {
        kind: RemedyKind::Repay,
        ui_amount: repay_ui,
        resulting_ltv: repay_ltv,
        resulting_buffer: repay_buffer,
        needs_balance_ui: repay_ui,
        capped_by_max_repay,
    };

    let deposit_delta_usd = safe_div(i.borrow_usd, t) - i.deposit_usd;
    let deposit_ui = safe_div(deposit_delta_usd, i.collateral_price);
    let (deposit_ltv, deposit_buffer) = simulate(
        i.borrow_usd,
        i.deposit_usd + deposit_ui * i.collateral_price,
        i.liq_ltv,
    );
    let deposit = Remedy {
        kind: RemedyKind::Deposit,
        ui_amount: deposit_ui,
        resulting_ltv: deposit_ltv,
        resulting_buffer: deposit_buffer,
        needs_balance_ui: deposit_ui,
        capped_by_max_repay: false,
    };

    // Repay always first; deposit second (v1 has exactly these two kinds,
    // so `collateral_is_falling` cannot reorder a 2-element vec — it is
    // documentation for a future ranking, not live logic here).
    //
    // The deposit remedy drops out when the target LTV `t` is not positive
    // (`liq_ltv == 0` — no deposit is liquidatable): the required deposit is
    // `B/t`, unbounded there, so `safe_div`'s 0.0 fallback turns it NEGATIVE
    // — "Deposit -5.0 SOL", an instruction nobody can follow. Repay stays
    // meaningful in that state (repay everything), so only the undefined
    // remedy is suppressed, matching how `health::assess` suppresses the
    // forecasts it cannot compute rather than printing a made-up number.
    if t > 0.0 {
        vec![repay, deposit]
    } else {
        vec![repay]
    }
}
