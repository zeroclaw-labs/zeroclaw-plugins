//! Pure tool-result text formatting: [`HealthReport`], ranked [`Remedy`]s,
//! position metadata, and an optional rescue payload become the final text
//! an agent (and, transitively, a user) reads.
//!
//! No I/O, no parsing of network payloads — everything here is already a
//! decoded fact. Strings that originate from API payloads (symbols, alert
//! text) are interpolated as inert display data only: never branched on,
//! never used as a formatting directive.
//!
//! Deviations from the illustrative example in the issue, driven by the
//! actual (frozen, upstream) `HealthReport`/`PositionFacts` contracts:
//! - `HealthReport` exposes only the `buffer` fraction, not raw `ltv` /
//!   `liq_ltv`, so the tier line reports buffer only (no reconstructable
//!   absolute LTV/liq_ltv — the ratio is recoverable from `buffer` but the
//!   two absolute values are not, and fabricating them would violate the
//!   "never render a confident number without real data behind it" spirit
//!   of the stale-data invariant).
//!
//! The debt-rise forecast line's "now" price comes from `PositionMeta.
//! debt_price` (the dominant debt asset's own oracle price), never
//! `collateral_price` — the two are unrelated assets. The drift line's
//! borrow-APY/utilization parenthetical only appears when both fields are
//! `Some`; either or both absent omits that piece rather than fabricating
//! it.

use crate::health::{HealthReport, Tier};
use crate::remedy::{Remedy, RemedyKind};
use crate::rescue::RESCUE_CU_LIMIT;

/// Static identity/display facts for one obligation. Not derived by pure
/// math (that's `health`/`remedy`'s job) — report.rs owns this shape
/// directly since it's purely about what to print and where it came from.
pub struct PositionMeta {
    pub obligation: String,
    pub market: String,
    pub collateral_symbol: String,
    pub debt_symbol: String,
    /// Kamino oracle price, USD per ui token.
    pub collateral_price: f64,
    /// Kamino oracle price, USD per ui token, dominant debt asset — the
    /// "now" value on the debt-rise forecast line.
    pub debt_price: f64,
    /// Names of price rows judged stale by the pipeline's freshness check.
    pub stale_price_names: Vec<String>,
}

/// Formatted rescue-transaction facts. The transaction itself is unsigned
/// data; this struct carries only what the operator needs to inspect it.
pub struct RescueText {
    pub tx_base64: String,
    pub repay_ui: f64,
    pub debt_symbol: String,
    pub amount_native: u64,
    /// Which cap bound the repay amount: "max_repay_ui" | "requested" |
    /// "computed" | "balance" (F7 — the wallet-balance read is a
    /// first-class min-candidate in `guard::run_rescue`, never a silent
    /// pre-cap, so `"balance"` here is always truthful).
    pub capped_by: String,
    /// `Some(fee)` when the built tx carries compute-budget instructions
    /// (opt-in via config `priority_fee_microlamports`); renders one extra
    /// line naming the fee and compute limit. `None` renders nothing.
    pub priority_fee_microlamports: Option<u64>,
    /// `Some(account)` when the built tx carries an `AdvanceNonceAccount`
    /// instruction and the message blockhash is a durable-nonce value
    /// (opt-in via config `nonce_account`); renders one extra line naming
    /// the account. `None` renders nothing.
    pub nonce_account: Option<String>,
}

/// Formatted deposit-transaction facts, mirroring [`RescueText`] for the
/// deposit remedy (v11-deposit-encoder).
pub struct DepositText {
    pub tx_base64: String,
    pub deposit_ui: f64,
    pub collateral_symbol: String,
    pub amount_native: u64,
    /// Which cap bound the deposit amount: "max_deposit_ui" | "requested" |
    /// "computed" | "balance" — same truthful-label mechanism as
    /// [`RescueText::capped_by`].
    pub capped_by: String,
    /// `Some(fee)` when the built tx carries compute-budget instructions
    /// (opt-in via config `priority_fee_microlamports`). `None` renders
    /// nothing.
    pub priority_fee_microlamports: Option<u64>,
    /// `Some(account)` when the built tx carries an `AdvanceNonceAccount`
    /// instruction (opt-in via config `nonce_account`). `None` renders
    /// nothing.
    pub nonce_account: Option<String>,
}

/// Custody invariant: rescue/deposit output always carries this sentence
/// verbatim — the single copy both [`render_rescue`] and [`render_deposit`]
/// reference (never duplicated as a second string literal).
const CUSTODY_SENTENCE: &str =
    "Unsigned. Nothing here can sign or broadcast. Inspect and sign in your own wallet.";

/// Fraction -> percent string, one decimal (percents only at the display
/// edge; internal math stays fractions everywhere else). A non-finite ratio
/// renders as `n/a` rather than `inf`/`NaN`, which read as crashes.
fn pct(fraction: f64) -> String {
    if !fraction.is_finite() {
        return "n/a".to_string();
    }
    format!("{:.1}", fraction * 100.0)
}

fn signed_pct(fraction: f64) -> String {
    if fraction >= 0.0 {
        format!("+{}", pct(fraction))
    } else {
        pct(fraction)
    }
}

/// Token amount -> display string. A flat `{:.1}` is wrong for high-value
/// small-unit assets: a real 0.066111 cbBTC remedy renders as "0.1"
/// (overstating the amount the user must hold by 51%), and anything under
/// 0.05 renders as "0.0" — an amount nobody can act on. Six decimals covers
/// every mint this plugin touches, and the trailing padding is trimmed so
/// ordinary amounts still read as before (2553.2 stays "2553.2").
///
/// A non-finite amount renders as `n/a`, matching [`pct`]: `remedy::rank`
/// divides by an oracle price to size every remedy, so an unbounded one would
/// otherwise print "Repay inf USDG" — an instruction nobody can follow, and
/// the same fabricated-number failure the health forecasts already suppress.
fn amt(v: f64) -> String {
    if !v.is_finite() {
        return "n/a".to_string();
    }
    let s = format!("{v:.6}");
    let trimmed = s.trim_end_matches('0');
    match trimmed.strip_suffix('.') {
        Some(whole) => format!("{whole}.0"),
        None => trimmed.to_string(),
    }
}

fn tier_name(t: &Tier) -> &'static str {
    match t {
        Tier::Ok => "OK",
        Tier::Watch => "WATCH",
        Tier::Warn => "WARN",
        Tier::Critical => "CRITICAL",
    }
}

/// USD price -> display string. `${:.2}` collapses every sub-cent asset to
/// `$0.00` (a BONK forecast threshold of $0.0000188 is unusable), so prices
/// below a cent carry significant digits instead of a fixed 2 decimals.
fn usd(v: f64) -> String {
    if v != 0.0 && v.abs() < 0.01 {
        format!("{v:.8}")
    } else {
        format!("{v:.2}")
    }
}

fn pct_change(threshold: f64, now: f64) -> f64 {
    if now == 0.0 {
        0.0
    } else {
        (threshold - now) / now
    }
}

fn forecast_line(symbol: &str, cmp: &str, threshold: f64, now: f64, sol_level: bool) -> String {
    let mut line = format!(
        "Liquidated if {symbol} {cmp} ${} (now ${}, {}%)",
        usd(threshold),
        usd(now),
        signed_pct(pct_change(threshold, now))
    );
    if sol_level {
        line.push_str(" (underlying SOL level via stake rate)");
    }
    line
}

fn remedy_line(m: &PositionMeta, r: &Remedy) -> String {
    let (verb, symbol) = match r.kind {
        RemedyKind::Repay => ("Repay", m.debt_symbol.as_str()),
        RemedyKind::Deposit => ("Deposit", m.collateral_symbol.as_str()),
    };
    let mut line = format!(
        "{verb} {} {symbol} \u{2192} LTV {}%, buffer {}% (needs {} {symbol} in wallet)",
        amt(r.ui_amount),
        pct(r.resulting_ltv),
        pct(r.resulting_buffer),
        amt(r.needs_balance_ui)
    );
    if r.capped_by_max_repay {
        line.push_str(" (capped by max_repay_ui)");
    }
    line
}

/// Render one obligation's `check` result: tier, forecasts, drift, alerts,
/// ranked remedies, stale-data warning, snapshot round-trip — in that
/// fixed order.
pub fn render_check(
    m: &PositionMeta,
    h: &HealthReport,
    remedies: &[Remedy],
    snapshot: &str,
) -> String {
    let mut lines = Vec::new();

    // 1. Tier line. An infinite LTV (debt outstanding against zero
    // liquidatable deposit) has no finite buffer, so it is named in words
    // instead of printed as `-inf%`.
    lines.push(if h.buffer.is_finite() {
        format!("{} — buffer {}%", tier_name(&h.tier), pct(h.buffer))
    } else {
        format!(
            "{} — no liquidatable collateral backing an outstanding debt",
            tier_name(&h.tier)
        )
    });

    // 2. Forecast, both directions when present. Each line quotes its
    // threshold and its spot in the SAME denomination — otherwise the
    // percentage between them is meaningless. When the collateral forecast
    // was converted to the SOL level, the symbol and the spot move with it;
    // the debt line is always the debt asset's own price and is never
    // annotated.
    if let Some(threshold) = h.liq_price_collateral_drop {
        let (symbol, spot) = match h.sol_spot_price {
            Some(sol_spot) => ("SOL", sol_spot),
            None => (m.collateral_symbol.as_str(), m.collateral_price),
        };
        lines.push(forecast_line(
            symbol,
            "<",
            threshold,
            spot,
            h.sol_spot_price.is_some(),
        ));
    }
    if let Some(threshold) = h.liq_price_debt_rise {
        lines.push(forecast_line(
            &m.debt_symbol,
            ">",
            threshold,
            m.debt_price,
            false,
        ));
    }

    // 3. Drift line, with an optional borrow-APY/utilization parenthetical
    // — never fabricated: each piece renders only when its field is Some.
    if let Some(delta) = h.interest_drift {
        let mut parts = Vec::new();
        if let Some(apy) = h.borrow_apy {
            parts.push(format!("borrow APY {}%", pct(apy)));
        }
        if let Some(util) = h.utilization {
            parts.push(format!("utilization {}%", pct(util)));
        }
        let mut line = format!("Drift since last snapshot: LTV {}pp", signed_pct(delta));
        if !parts.is_empty() {
            line.push_str(&format!(" ({})", parts.join(", ")));
        }
        lines.push(line);
    }

    // 4. Parameter alert — its own alert class.
    if let Some(alert) = &h.param_alert {
        lines.push(format!("PARAM ALERT: {alert}"));
    }

    // 5. ADL warning, then dust warning.
    if let Some(adl) = &h.adl_warning {
        lines.push(format!("ADL WARNING: {adl}"));
    }
    if h.dust_warning {
        lines.push(
            "DUST WARNING: position value is below the minimum full-liquidation size — \
             expect 100%-in-one-round liquidation, no partial grace."
                .to_string(),
        );
    }

    // 6. Correlated-move assumption label.
    if h.correlated_move_assumption {
        lines.push("assumes correlated move across multi-volatile collateral".to_string());
    }

    // 7. Ranked remedies with simulated outcomes.
    for r in remedies {
        lines.push(remedy_line(m, r));
    }

    // 8. Stale-data warning — a stale price never renders as a confident
    // number without this.
    if !m.stale_price_names.is_empty() {
        lines.push(format!("STALE DATA: {}", m.stale_price_names.join(", ")));
    }

    // 9. Snapshot round-trip, always last.
    lines.push(format!("snapshot: {snapshot}"));

    lines.join("\n")
}

/// Join per-obligation `render_check` renders into one portfolio result.
pub fn render_portfolio(sections: &[String]) -> String {
    sections.join("\n\n")
}

/// Render the `rescue` result: custody sentence, unsigned tx, amount, cap
/// bound, an added warning when that cap is the wallet balance (F7 — such a
/// repay is not sized to restore the WATCH boundary), required wallet
/// balance, snapshot round-trip.
pub fn render_rescue(m: &PositionMeta, r: &RescueText, snapshot: &str) -> String {
    let mut out = format!(
        "{custody}\n\n\
         Obligation: {obligation} ({market})\n\
         Repay {repay_ui} {debt} ({amount_native} native units) — capped by {capped_by}.\n",
        custody = CUSTODY_SENTENCE,
        obligation = m.obligation,
        market = m.market,
        repay_ui = amt(r.repay_ui),
        debt = r.debt_symbol,
        amount_native = r.amount_native,
        capped_by = r.capped_by,
    );
    if !m.stale_price_names.is_empty() {
        out.push_str(&format!(
            "STALE DATA: {} — this amount was sized from a price past its own \
             max age. Re-check before signing.\n",
            m.stale_price_names.join(", ")
        ));
    }
    if r.capped_by == "balance" {
        out.push_str(
            "WARNING: this repay is capped by your wallet balance, not the computed \
             remedy — it does NOT restore the WATCH boundary.\n",
        );
    }
    if let Some(fee) = r.priority_fee_microlamports {
        out.push_str(&format!(
            "priority fee: {fee} microlamports/CU (compute limit {RESCUE_CU_LIMIT})\n"
        ));
    }
    if let Some(account) = &r.nonce_account {
        out.push_str(&format!(
            "durable nonce: {account} (transaction does not expire until the nonce advances)\n"
        ));
    }
    out.push_str(&format!(
        "Requires {repay_ui} {debt} in wallet.\n\
         tx (base64): {tx}\n\n\
         snapshot: {snapshot}",
        repay_ui = amt(r.repay_ui),
        debt = r.debt_symbol,
        tx = r.tx_base64,
    ));
    out
}

/// Render the `deposit` result: custody sentence, unsigned tx, amount, cap
/// bound, an added warning when that cap is the wallet balance (mirrors
/// [`render_rescue`] exactly, deposit wording), required wallet balance,
/// snapshot round-trip.
pub fn render_deposit(m: &PositionMeta, d: &DepositText, snapshot: &str) -> String {
    let mut out = format!(
        "{custody}\n\n\
         Obligation: {obligation} ({market})\n\
         Deposit {deposit_ui} {collateral} ({amount_native} native units) — capped by {capped_by}.\n",
        custody = CUSTODY_SENTENCE,
        obligation = m.obligation,
        market = m.market,
        deposit_ui = amt(d.deposit_ui),
        collateral = d.collateral_symbol,
        amount_native = d.amount_native,
        capped_by = d.capped_by,
    );
    if !m.stale_price_names.is_empty() {
        out.push_str(&format!(
            "STALE DATA: {} — this amount was sized from a price past its own \
             max age. Re-check before signing.\n",
            m.stale_price_names.join(", ")
        ));
    }
    if d.capped_by == "balance" {
        out.push_str(
            "WARNING: this deposit is capped by your wallet balance, not the computed \
             remedy — it does NOT restore the WATCH boundary.\n",
        );
    }
    if let Some(fee) = d.priority_fee_microlamports {
        out.push_str(&format!(
            "priority fee: {fee} microlamports/CU (compute limit {RESCUE_CU_LIMIT})\n"
        ));
    }
    if let Some(account) = &d.nonce_account {
        out.push_str(&format!(
            "durable nonce: {account} (transaction does not expire until the nonce advances)\n"
        ));
    }
    out.push_str(&format!(
        "Requires {deposit_ui} {collateral} in wallet.\n\
         tx (base64): {tx}\n\n\
         snapshot: {snapshot}",
        deposit_ui = amt(d.deposit_ui),
        collateral = d.collateral_symbol,
        tx = d.tx_base64,
    ));
    out
}
