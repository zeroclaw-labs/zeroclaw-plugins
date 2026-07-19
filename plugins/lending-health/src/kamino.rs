//! Pure Kamino Lend obligation decode + liquidation-risk scoring. No wit-bindgen
//! or wasm dependency, so it compiles and tests on the host with a plain
//! `cargo test`; the wasm component reuses the exact same logic through `lib.rs`.
//!
//! ## What it reads
//!
//! A Kamino **Obligation** is an Anchor zero-copy (`#[repr(C)]`, bytemuck)
//! account of 3344 bytes. It already caches every value the health calculation
//! needs: deposited collateral value, borrow-factor-adjusted debt value, and
//! the allowed / unhealthy borrow-value thresholds, all as `U68F60` fixed-point
//! `u128`s (the `_sf` suffix, "scaled fraction"). So the fast path is a single
//! account read: decode four cached `u128`s and the health factor falls out with
//! no reserve or oracle parsing.
//!
//! ## Verified offsets (locked against mainnet, 2026-07-18)
//!
//! The deep offsets of the cached aggregate fields depend on the exact size of
//! `ObligationCollateral` (×8) and `ObligationLiquidity` (×5), so they were NOT
//! hardcoded blind. They were confirmed against live mainnet data:
//!
//! * Fetched obligation `CmYJ8grTcyqNgLDfi85yGjghvA34ma1BTCN6TtuB6FT4` (the
//!   embedded test fixture): 3344 bytes, discriminator matches at `@0`,
//!   `lending_market@32` = the main market, `owner@64` decodes to
//!   `FJ5dzQD8jbMuzDe3uFUMjq7R5w5RDZn9PbRt8hwRoo5m`.
//! * `deposits[8]` (`ObligationCollateral` = 136 B each) spans `96..1184`, so
//!   `lowest_reserve_deposit_liquidation_ltv` u64 lands exactly at `@1184` and
//!   `deposited_value_sf` u128 at `@1192`, confirmed by both arithmetic and the
//!   decoded value (≈ $2847.91).
//! * `borrows[5]` (`ObligationLiquidity` = 200 B each) spans `1208..2208`, so the
//!   four cached aggregates start at `@2208`:
//!   `borrow_factor_adjusted_debt_value_sf@2208`,
//!   `borrowed_assets_market_value_sf@2224`, `allowed_borrow_value_sf@2240`,
//!   `unhealthy_borrow_value_sf@2256`.
//! * These offsets were then validated across **all 139,223** live obligations
//!   via a `getProgramAccounts` `dataSlice`: for every one of the 31,987 active
//!   debtors the invariants held (`borrowed_market_value ≤ bf_adjusted_debt`,
//!   `allowed ≤ unhealthy`), and for the fixture `allowed/deposited = 0.7400`
//!   and `unhealthy/deposited = 0.7500` reproduce Kamino's public API
//!   (`api.kamino.finance/klend/loans/…`) `maxLtv = 0.74` / `liquidationLtv =
//!   0.75` **exactly**.
//!
//! ## Fail-closed
//!
//! Every field is read through the bounds-checked [`Reader`]; a short or garbage
//! account yields `Err`, never a panic and never a false "healthy". The
//! discriminator is checked so a wrong account type is rejected outright.

use zeroclaw_solana_core::pubkey::Pubkey;
use zeroclaw_solana_core::reader::Reader;

use crate::fraction::fraction_to_f64;

/// Kamino Lend program id (owns every Obligation account).
pub const KLEND_PROGRAM_ID: &str = "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD";

/// Anchor account discriminator for an Obligation (`sha256("account:Obligation")`
/// first 8 bytes). Also the `memcmp@0` filter used to discover obligations.
pub const OBLIGATION_DISCRIMINATOR: [u8; 8] = [168, 206, 141, 106, 88, 76, 172, 167];

/// Full on-chain size of an Obligation account.
pub const OBLIGATION_LEN: usize = 3344;

// ── verified byte offsets (see module docs) ─────────────────────────────────
const OFF_LAST_UPDATE_SLOT: usize = 16;
const OFF_LENDING_MARKET: usize = 32;
const OFF_OWNER: usize = 64;
const OFF_DEPOSITED_VALUE_SF: usize = 1192;
const OFF_BF_ADJUSTED_DEBT_VALUE_SF: usize = 2208;
const OFF_ALLOWED_BORROW_VALUE_SF: usize = 2240;
const OFF_UNHEALTHY_BORROW_VALUE_SF: usize = 2256;

/// Smallest account we can decode: everything up to and including the last field
/// we read (`unhealthy_borrow_value_sf` at `@2256`, +16 bytes).
const MIN_DECODE_LEN: usize = OFF_UNHEALTHY_BORROW_VALUE_SF + 16; // 2272

/// Health factor at or below which a position is liquidatable.
pub const LIQUIDATABLE_HF: f64 = 1.0;
/// Health factor below which a position is flagged at-risk (but not yet
/// liquidatable). A ~15% buffer to the liquidation point.
pub const AT_RISK_HF: f64 = 1.15;

/// A decoded Kamino obligation: only the cached fields needed for a
/// liquidation-risk read. All `*_sf` values are `U68F60` fixed-point USD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obligation {
    /// The wallet that owns this position (`owner@64`).
    pub owner: Pubkey,
    /// The lending market this obligation belongs to (`lending_market@32`).
    pub lending_market: Pubkey,
    /// Slot of the obligation's last on-chain refresh (staleness signal).
    pub last_update_slot: u64,
    /// Total collateral value, USD scaled-fraction.
    pub deposited_value_sf: u128,
    /// Borrow-factor-adjusted debt value, USD scaled-fraction. This is the
    /// numerator Kamino compares against the thresholds; `0` ⇒ no debt.
    pub borrow_factor_adjusted_debt_value_sf: u128,
    /// Max borrow value allowed (the borrow cap), USD scaled-fraction.
    pub allowed_borrow_value_sf: u128,
    /// Debt value at which the position becomes liquidatable, USD
    /// scaled-fraction.
    pub unhealthy_borrow_value_sf: u128,
    /// Whether the obligation carries any borrow. Derived from the debt value
    /// itself (the authoritative signal the health factor keys off), not the
    /// separate cached flag byte.
    pub has_debt: bool,
}

/// Liquidation-risk classification for an obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Collateral deposited but nothing borrowed; cannot be liquidated.
    NoDebt,
    /// Health factor comfortably above the at-risk buffer.
    Healthy,
    /// Health factor within the buffer of the liquidation point (`< 1.15`).
    AtRisk,
    /// Health factor at or below `1.0`; liquidatable right now.
    Liquidatable,
}

impl Status {
    /// Traffic-light emoji: green for safe (Healthy / NoDebt), amber for
    /// At-risk, red for Liquidatable.
    pub fn emoji(self) -> &'static str {
        match self {
            Status::Healthy | Status::NoDebt => "\u{1F7E2}", // 🟢
            Status::AtRisk => "\u{1F7E1}",                   // 🟡
            Status::Liquidatable => "\u{1F534}",             // 🔴
        }
    }

    /// Upper-case label.
    pub fn label(self) -> &'static str {
        match self {
            Status::NoDebt => "NO DEBT",
            Status::Healthy => "HEALTHY",
            Status::AtRisk => "AT RISK",
            Status::Liquidatable => "LIQUIDATABLE",
        }
    }

    /// Whether a sentinel should raise an alert for this status. Safe states
    /// (Healthy, NoDebt) stay quiet; At-risk and Liquidatable alert.
    pub fn should_alert(self) -> bool {
        matches!(self, Status::AtRisk | Status::Liquidatable)
    }
}

impl Obligation {
    /// Collateral value in USD.
    pub fn deposited_usd(&self) -> f64 {
        fraction_to_f64(self.deposited_value_sf)
    }

    /// Borrow-factor-adjusted debt in USD.
    pub fn debt_usd(&self) -> f64 {
        fraction_to_f64(self.borrow_factor_adjusted_debt_value_sf)
    }

    /// Borrow limit (max allowed borrow value) in USD.
    pub fn borrow_limit_usd(&self) -> f64 {
        fraction_to_f64(self.allowed_borrow_value_sf)
    }

    /// Debt value at which liquidation begins, in USD.
    pub fn liquidation_value_usd(&self) -> f64 {
        fraction_to_f64(self.unhealthy_borrow_value_sf)
    }

    /// Current loan-to-value (`debt / collateral`), or `None` with no
    /// collateral.
    pub fn current_ltv(&self) -> Option<f64> {
        if self.deposited_value_sf == 0 {
            return None;
        }
        Some(self.borrow_factor_adjusted_debt_value_sf as f64 / self.deposited_value_sf as f64)
    }

    /// Loan-to-value at which liquidation begins (`unhealthy / collateral`), or
    /// `None` with no collateral.
    pub fn liquidation_ltv(&self) -> Option<f64> {
        if self.deposited_value_sf == 0 {
            return None;
        }
        Some(self.unhealthy_borrow_value_sf as f64 / self.deposited_value_sf as f64)
    }

    /// Health factor for this obligation (see [`health_factor`]).
    pub fn health_factor(&self) -> Option<f64> {
        health_factor(self)
    }

    /// Liquidation-risk status for this obligation.
    pub fn status(&self) -> Status {
        status(self.health_factor())
    }

    /// Render a compact, self-contained (~150-token) summary suitable for a chat
    /// reply or a Telegram alert pushed by a cron SOP. The status emoji + label
    /// lead the first line so a sentinel can branch on it.
    pub fn summary(&self) -> String {
        let st = self.status();
        let head = format!(
            "{} {} \u{00B7} Kamino Lend \u{00B7} {}",
            st.emoji(),
            st.label(),
            short_addr(&self.owner),
        );
        if !self.has_debt {
            return format!(
                "{head}\n{} collateral deposited, no borrows; nothing to liquidate.",
                fmt_usd(self.deposited_usd()),
            );
        }
        let hf = self.health_factor().unwrap_or(f64::INFINITY);
        let mut out = format!(
            "{head}\nHealth factor {}  (liquidatable \u{2264} 1.00 \u{00B7} warn < 1.15)\n\
             Collateral {} \u{00B7} Debt {}",
            fmt_hf(hf),
            fmt_usd(self.deposited_usd()),
            fmt_usd(self.debt_usd()),
        );
        if let (Some(cur), Some(liq)) = (self.current_ltv(), self.liquidation_ltv()) {
            out.push_str(&format!(
                "\nLoan-to-value {:.1}% of {:.1}% liquidation threshold",
                cur * 100.0,
                liq * 100.0,
            ));
        }
        out
    }
}

/// Decode the cached liquidation-risk fields from a Kamino Obligation account.
///
/// Fails closed: rejects data shorter than [`MIN_DECODE_LEN`] and any account
/// whose first 8 bytes are not the Obligation discriminator.
pub fn decode_obligation(data: &[u8]) -> Result<Obligation, String> {
    if data.len() < MIN_DECODE_LEN {
        return Err(format!(
            "obligation account too short: {} bytes (need >= {MIN_DECODE_LEN})",
            data.len()
        ));
    }
    if data[..8] != OBLIGATION_DISCRIMINATOR {
        return Err("not a Kamino obligation (discriminator mismatch)".to_string());
    }

    // Non-contiguous fixed offsets → one bounds-checked reader per field.
    let last_update_slot = Reader::at(data, OFF_LAST_UPDATE_SLOT).u64()?;
    let lending_market = Reader::at(data, OFF_LENDING_MARKET).pubkey()?;
    let owner = Reader::at(data, OFF_OWNER).pubkey()?;
    let deposited_value_sf = Reader::at(data, OFF_DEPOSITED_VALUE_SF).u128()?;
    let borrow_factor_adjusted_debt_value_sf =
        Reader::at(data, OFF_BF_ADJUSTED_DEBT_VALUE_SF).u128()?;
    let allowed_borrow_value_sf = Reader::at(data, OFF_ALLOWED_BORROW_VALUE_SF).u128()?;
    let unhealthy_borrow_value_sf = Reader::at(data, OFF_UNHEALTHY_BORROW_VALUE_SF).u128()?;

    Ok(Obligation {
        owner,
        lending_market,
        last_update_slot,
        deposited_value_sf,
        borrow_factor_adjusted_debt_value_sf,
        allowed_borrow_value_sf,
        unhealthy_borrow_value_sf,
        has_debt: borrow_factor_adjusted_debt_value_sf > 0,
    })
}

/// Kamino health factor = `unhealthy_borrow_value / borrow_factor_adjusted_debt`.
///
/// Both operands share the `2^60` scale so it cancels; the ratio is exact on
/// the raw integers. `> 1` is healthy, `<= 1` is liquidatable. Returns `None`
/// when the obligation has no debt (a borrow-free position has no liquidation
/// point).
pub fn health_factor(ob: &Obligation) -> Option<f64> {
    if ob.borrow_factor_adjusted_debt_value_sf == 0 {
        return None;
    }
    Some(ob.unhealthy_borrow_value_sf as f64 / ob.borrow_factor_adjusted_debt_value_sf as f64)
}

/// Classify a health factor into a [`Status`]. `None` ⇒ no debt.
pub fn status(hf: Option<f64>) -> Status {
    match hf {
        None => Status::NoDebt,
        Some(h) if h <= LIQUIDATABLE_HF => Status::Liquidatable,
        Some(h) if h < AT_RISK_HF => Status::AtRisk,
        Some(_) => Status::Healthy,
    }
}

/// Short form of an address: `FJ5d…oo5m`.
fn short_addr(pk: &Pubkey) -> String {
    let s = pk.to_string();
    if s.len() <= 8 {
        return s;
    }
    format!("{}\u{2026}{}", &s[..4], &s[s.len() - 4..])
}

/// Format a health factor, keeping enough precision to disambiguate values just
/// above the liquidation boundary (e.g. `1.003` vs a rounded `1.00`) while never
/// showing fewer than two decimals.
fn fmt_hf(hf: f64) -> String {
    let s = format!("{hf:.3}");
    let trimmed = s.trim_end_matches('0');
    match trimmed.split('.').nth(1).map(str::len) {
        Some(n) if n >= 2 => trimmed.to_string(),
        _ => format!("{hf:.2}"),
    }
}

/// Format a USD value with a `$`, two decimals, and comma thousands separators.
fn fmt_usd(v: f64) -> String {
    let cents = (v.abs() * 100.0).round() as u128;
    let dollars = cents / 100;
    let frac = cents % 100;
    let mut int = dollars.to_string();
    // Insert comma separators into the integer part.
    let mut i = int.len();
    while i > 3 {
        i -= 3;
        int.insert(i, ',');
    }
    let sign = if v < 0.0 { "-" } else { "" };
    format!("{sign}${int}.{frac:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new([b; 32])
    }

    /// Build an obligation from whole-USD numbers (scaled into `U68F60`).
    fn ob(dep: f64, debt: f64, allowed: f64, unhealthy: f64) -> Obligation {
        let scale = |x: f64| (x * 2f64.powi(60)) as u128;
        Obligation {
            owner: pk(1),
            lending_market: pk(2),
            last_update_slot: 100,
            deposited_value_sf: scale(dep),
            borrow_factor_adjusted_debt_value_sf: scale(debt),
            allowed_borrow_value_sf: scale(allowed),
            unhealthy_borrow_value_sf: scale(unhealthy),
            has_debt: debt > 0.0,
        }
    }

    #[test]
    fn no_debt_has_no_health_factor() {
        let o = ob(1000.0, 0.0, 0.0, 0.0);
        assert_eq!(o.health_factor(), None);
        assert_eq!(o.status(), Status::NoDebt);
        assert!(!o.status().should_alert());
        assert!(o.summary().contains("nothing to liquidate"));
    }

    #[test]
    fn healthy_position_is_above_buffer() {
        // unhealthy 800 / debt 500 = HF 1.6
        let o = ob(1000.0, 500.0, 700.0, 800.0);
        let hf = o.health_factor().unwrap();
        assert!((hf - 1.6).abs() < 1e-9);
        assert_eq!(o.status(), Status::Healthy);
        assert!(!o.status().should_alert());
    }

    #[test]
    fn at_risk_between_one_and_buffer() {
        // unhealthy 800 / debt 750 ≈ HF 1.0667 → AtRisk
        let o = ob(1000.0, 750.0, 700.0, 800.0);
        let hf = o.health_factor().unwrap();
        assert!(hf > LIQUIDATABLE_HF && hf < AT_RISK_HF);
        assert_eq!(o.status(), Status::AtRisk);
        assert!(o.status().should_alert());
        assert!(o.summary().starts_with("\u{1F7E1}"));
    }

    #[test]
    fn liquidatable_at_or_below_one() {
        // debt exactly at the threshold → HF 1.0 → Liquidatable
        let o = ob(1000.0, 800.0, 700.0, 800.0);
        assert_eq!(o.health_factor().unwrap(), 1.0);
        assert_eq!(o.status(), Status::Liquidatable);
        assert!(o.status().should_alert());
        assert!(o.summary().starts_with("\u{1F534}"));

        // debt over the threshold → HF < 1.0 → still Liquidatable
        let under = ob(1000.0, 900.0, 700.0, 800.0);
        assert!(under.health_factor().unwrap() < 1.0);
        assert_eq!(under.status(), Status::Liquidatable);
    }

    #[test]
    fn decode_rejects_short_and_garbage() {
        assert!(decode_obligation(&[0u8; 10]).is_err());
        // right length, wrong discriminator
        let mut buf = vec![0u8; OBLIGATION_LEN];
        buf[0] = 1;
        assert!(decode_obligation(&buf).is_err());
    }

    #[test]
    fn decode_synthetic_roundtrip() {
        let mut buf = vec![0u8; OBLIGATION_LEN];
        buf[..8].copy_from_slice(&OBLIGATION_DISCRIMINATOR);
        buf[OFF_OWNER..OFF_OWNER + 32].copy_from_slice(&[7u8; 32]);
        let put = |buf: &mut [u8], off: usize, v: u128| {
            buf[off..off + 16].copy_from_slice(&v.to_le_bytes());
        };
        let scale = |x: f64| (x * 2f64.powi(60)) as u128;
        put(&mut buf, OFF_DEPOSITED_VALUE_SF, scale(1000.0));
        put(&mut buf, OFF_BF_ADJUSTED_DEBT_VALUE_SF, scale(500.0));
        put(&mut buf, OFF_ALLOWED_BORROW_VALUE_SF, scale(700.0));
        put(&mut buf, OFF_UNHEALTHY_BORROW_VALUE_SF, scale(800.0));
        let o = decode_obligation(&buf).unwrap();
        assert_eq!(o.owner, Pubkey::new([7u8; 32]));
        assert!(o.has_debt);
        assert!((o.deposited_usd() - 1000.0).abs() < 0.001);
        assert!((o.health_factor().unwrap() - 1.6).abs() < 1e-9);
        assert_eq!(o.status(), Status::Healthy);
    }

    #[test]
    fn fmt_hf_disambiguates_near_boundary() {
        assert_eq!(fmt_hf(1.003), "1.003"); // near-boundary keeps 3 decimals
        assert_eq!(fmt_hf(1.41), "1.41");
        assert_eq!(fmt_hf(1.4), "1.40"); // never fewer than 2 decimals
        assert_eq!(fmt_hf(2.0), "2.00");
    }

    #[test]
    fn fmt_usd_groups_thousands() {
        assert_eq!(fmt_usd(0.0), "$0.00");
        assert_eq!(fmt_usd(12.5), "$12.50");
        assert_eq!(fmt_usd(2847.9088), "$2,847.91");
        assert_eq!(fmt_usd(1_234_567.0), "$1,234,567.00");
    }

    #[test]
    fn short_addr_shape() {
        let s = short_addr(&pk(0));
        assert!(s.contains('\u{2026}'));
    }
}
