//! Safe decimal amount parsing, formatting, and cap comparison.
//!
//! Uses fixed-scale integer arithmetic (no floating point) so values are
//! exact for BRL (2 decimals) and USDC (6 decimals).

use std::cmp::Ordering;
use std::fmt;

/// Maximum supported integer digits before the decimal point.
const MAX_INTEGER_DIGITS: usize = 18;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmountError {
    Empty,
    InvalidFormat,
    TooManyDecimals { max: u32, got: u32 },
    Overflow,
    Negative,
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AmountError::Empty => write!(f, "amount is empty"),
            AmountError::InvalidFormat => write!(f, "invalid amount format"),
            AmountError::TooManyDecimals { max, got } => {
                write!(f, "too many decimal places: got {got}, max {max}")
            }
            AmountError::Overflow => write!(f, "amount overflow"),
            AmountError::Negative => write!(f, "negative amounts not allowed"),
        }
    }
}

impl std::error::Error for AmountError {}

/// A decimal amount stored as an integer scaled by `10^scale`.
///
/// Example: `"12.34"` with scale 2 → `value = 1234`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedAmount {
    /// Scaled integer value (always non-negative).
    pub value: u128,
    /// Number of decimal places the value is scaled by.
    pub scale: u32,
}

/// Parse a decimal amount string into a [`ParsedAmount`] with the given scale.
///
/// Accepts optional leading `+`, integer or fractional forms (`"10"`, `"10.5"`,
/// `"10.50"`). Rejects negatives, empty strings, scientific notation, and more
/// fractional digits than `scale`.
pub fn parse_decimal(s: &str, scale: u32) -> Result<ParsedAmount, AmountError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(AmountError::Empty);
    }
    if s.starts_with('-') {
        return Err(AmountError::Negative);
    }
    let s = s.strip_prefix('+').unwrap_or(s);
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(AmountError::InvalidFormat);
    }
    if s.chars().filter(|&c| c == '.').count() > 1 {
        return Err(AmountError::InvalidFormat);
    }
    // Reject leading/trailing-only dots or multiple dots already handled.
    if s == "." {
        return Err(AmountError::InvalidFormat);
    }

    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };

    // Allow empty integer part for ".5" style? Reject for safety.
    if int_part.is_empty() {
        return Err(AmountError::InvalidFormat);
    }
    if int_part.len() > MAX_INTEGER_DIGITS {
        return Err(AmountError::Overflow);
    }
    if !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(AmountError::InvalidFormat);
    }
    if !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(AmountError::InvalidFormat);
    }
    if frac_part.len() as u32 > scale {
        return Err(AmountError::TooManyDecimals {
            max: scale,
            got: frac_part.len() as u32,
        });
    }

    let mut int_val: u128 = if int_part.is_empty() {
        0
    } else {
        int_part.parse().map_err(|_| AmountError::Overflow)?
    };

    let factor = ten_pow(scale).ok_or(AmountError::Overflow)?;
    int_val = int_val.checked_mul(factor).ok_or(AmountError::Overflow)?;

    let mut frac_val: u128 = if frac_part.is_empty() {
        0
    } else {
        frac_part.parse().map_err(|_| AmountError::Overflow)?
    };
    // Pad fractional part to full scale: "12.3" with scale 2 → 30
    let pad = scale.saturating_sub(frac_part.len() as u32);
    if pad > 0 {
        let pad_factor = ten_pow(pad).ok_or(AmountError::Overflow)?;
        frac_val = frac_val
            .checked_mul(pad_factor)
            .ok_or(AmountError::Overflow)?;
    }

    let value = int_val.checked_add(frac_val).ok_or(AmountError::Overflow)?;

    Ok(ParsedAmount { value, scale })
}

/// Compare `amount` against `max` (both decimal strings at `scale`).
///
/// Returns `Ok(Ordering)` or an error if either fails to parse.
pub fn compare_amount(amount: &str, max: &str, scale: u32) -> Result<Ordering, AmountError> {
    let a = parse_decimal(amount, scale)?;
    let b = parse_decimal(max, scale)?;
    // Same scale after parse_decimal.
    Ok(a.value.cmp(&b.value))
}

/// Return true if `amount <= max` at the given scale.
pub fn within_cap(amount: &str, max: &str, scale: u32) -> Result<bool, AmountError> {
    Ok(matches!(
        compare_amount(amount, max, scale)?,
        Ordering::Less | Ordering::Equal
    ))
}

/// Format a scaled amount as a BRL string with exactly 2 decimal places
/// when needed (trims trailing zeros only if whole? Spec: up to 2 decimals).
///
/// Always emits at least one integer digit and exactly 2 fractional digits
/// for payment payloads (e.g. `"150.00"`).
pub fn format_brl(amount: &ParsedAmount) -> String {
    format_fixed(amount, 2)
}

/// Format a scaled amount as USDC with up to 6 decimal places.
/// Trailing zeros after the last non-zero fractional digit are trimmed,
/// but at least one fractional digit is kept if the original scale > 0 and
/// the value is non-integral in 6-dp form? Spec says "up to 6 decimals".
///
/// Emits shortest form without trailing zeros (e.g. `"27.272727"` or `"10"`).
pub fn format_usdc(amount: &ParsedAmount) -> String {
    format_up_to(amount, 6)
}

/// Format with exactly `decimals` fractional digits (zero-padded).
pub fn format_fixed(amount: &ParsedAmount, decimals: u32) -> String {
    let rescaled = rescale(amount, decimals);
    let factor = ten_pow(decimals).unwrap_or(1);
    let whole = rescaled / factor;
    let frac = rescaled % factor;
    if decimals == 0 {
        return whole.to_string();
    }
    format!("{whole}.{frac:0width$}", width = decimals as usize)
}

/// Format with up to `decimals` fractional digits, trimming trailing zeros.
pub fn format_up_to(amount: &ParsedAmount, decimals: u32) -> String {
    let fixed = format_fixed(amount, decimals);
    if decimals == 0 {
        return fixed;
    }
    // Trim trailing zeros after decimal; if all zero, drop the decimal point.
    if let Some((whole, frac)) = fixed.split_once('.') {
        let trimmed = frac.trim_end_matches('0');
        if trimmed.is_empty() {
            whole.to_string()
        } else {
            format!("{whole}.{trimmed}")
        }
    } else {
        fixed
    }
}

/// Convert `amount_brl` / `rate` → USDC amount string (scale 6).
///
/// `rate` is BRL per 1 USDC (e.g. `"5.5"`). Result is truncated toward zero
/// to 6 decimal places.
pub fn brl_to_usdc(amount_brl: &str, brl_per_usdc: &str) -> Result<String, AmountError> {
    // Work in micro-units: brl_cents / rate → usdc with 6 dp.
    // usdc = brl / rate
    // Use: usdc_scaled = brl_scaled * 10^(usdc_scale) / rate_scaled
    // with brl_scale=2, rate_scale=6, usdc_scale=6 for precision.
    let brl = parse_decimal(amount_brl, 2)?;
    let rate = parse_decimal(brl_per_usdc, 6)?;
    if rate.value == 0 {
        return Err(AmountError::InvalidFormat);
    }
    // brl.value is * 10^2, rate.value is * 10^6
    // usdc = brl / rate = (brl.value / 10^2) / (rate.value / 10^6)
    //      = brl.value * 10^6 / (rate.value * 10^2)
    // usdc_scaled_6 = usdc * 10^6 = brl.value * 10^12 / (rate.value * 10^2)
    //               = brl.value * 10^10 / rate.value
    let numer = brl
        .value
        .checked_mul(ten_pow(10).ok_or(AmountError::Overflow)?)
        .ok_or(AmountError::Overflow)?;
    let usdc_scaled = numer / rate.value; // floor
    Ok(format_up_to(
        &ParsedAmount {
            value: usdc_scaled,
            scale: 6,
        },
        6,
    ))
}

/// Largest decimal scale accepted when comparing an on-chain amount against an
/// expected decimal string. SPL mints top out at 9 decimals in practice; the
/// headroom exists so an over-precise `expected` is still compared exactly
/// instead of being rounded in the payer's favour.
const MAX_COMPARE_SCALE: u32 = 24;

/// Format an integer amount of **minor units** (e.g. `1_000_000` at 6 decimals)
/// as a decimal string in shortest form (`"1"`, `"27.27"`, `"0.5"`).
///
/// Exact: no floating point anywhere on the path.
pub fn format_minor_units(units: u128, decimals: u32) -> String {
    format_up_to(
        &ParsedAmount {
            value: units,
            scale: decimals,
        },
        decimals,
    )
}

/// Result of an exact comparison between an on-chain amount and an expected
/// decimal string. Produced by [`compare_units_to_decimal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitsComparison {
    /// `received` vs `expected`, exact — no tolerance band.
    pub ordering: Ordering,
    /// `|received − expected|` in shortest decimal form.
    pub diff: String,
    /// `expected` re-emitted in shortest decimal form (`"10.00"` → `"10"`).
    pub expected_fmt: String,
    /// `expected` scaled to `scale`. Zero means "no real expectation".
    pub expected_units: u128,
    /// Common scale both sides were compared at.
    pub scale: u32,
}

/// Compare `units` (minor units at `decimals`) with the decimal string
/// `expected`, **exactly**, using integer arithmetic only.
///
/// Both sides are lifted to `max(decimals, fractional digits of expected)` so an
/// `expected` carrying more precision than the token can represent still
/// compares honestly (it simply never equals a representable received amount).
///
/// Errors when `expected` is not a plain non-negative decimal, or when the
/// required scale / magnitude would overflow — callers must then degrade rather
/// than guess.
pub fn compare_units_to_decimal(
    units: u128,
    decimals: u32,
    expected: &str,
) -> Result<UnitsComparison, AmountError> {
    let expected = expected.trim();
    let frac = expected.split_once('.').map(|(_, f)| f.len());
    let scale = decimals.max(frac.unwrap_or(0) as u32);
    if scale > MAX_COMPARE_SCALE {
        return Err(AmountError::Overflow);
    }

    let exp = parse_decimal(expected, scale)?;
    let lift = ten_pow(scale - decimals).ok_or(AmountError::Overflow)?;
    let received = units.checked_mul(lift).ok_or(AmountError::Overflow)?;

    let ordering = received.cmp(&exp.value);
    let diff_units = received.abs_diff(exp.value);

    Ok(UnitsComparison {
        ordering,
        diff: format_minor_units(diff_units, scale),
        expected_fmt: format_minor_units(exp.value, scale),
        expected_units: exp.value,
        scale,
    })
}

/// Rescale a ParsedAmount to a new scale (truncating extra decimals).
fn rescale(amount: &ParsedAmount, new_scale: u32) -> u128 {
    if new_scale == amount.scale {
        return amount.value;
    }
    if new_scale > amount.scale {
        let diff = new_scale - amount.scale;
        amount.value.saturating_mul(ten_pow(diff).unwrap_or(1))
    } else {
        let diff = amount.scale - new_scale;
        amount.value / ten_pow(diff).unwrap_or(1)
    }
}

fn ten_pow(n: u32) -> Option<u128> {
    10u128.checked_pow(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_brl_basic() {
        let a = parse_decimal("150.00", 2).unwrap();
        assert_eq!(a.value, 15000);
        assert_eq!(format_brl(&a), "150.00");
    }

    #[test]
    fn parse_usdc_basic() {
        let a = parse_decimal("27.272727", 6).unwrap();
        assert_eq!(format_usdc(&a), "27.272727");
    }

    #[test]
    fn compare_caps() {
        assert_eq!(compare_amount("100", "100.00", 2).unwrap(), Ordering::Equal);
        assert_eq!(
            compare_amount("100.01", "100", 2).unwrap(),
            Ordering::Greater
        );
        assert!(within_cap("99.99", "100", 2).unwrap());
        assert!(!within_cap("100.01", "100", 2).unwrap());
    }

    #[test]
    fn reject_too_many_decimals() {
        assert!(matches!(
            parse_decimal("1.234", 2),
            Err(AmountError::TooManyDecimals { .. })
        ));
    }

    #[test]
    fn reject_negative() {
        assert_eq!(parse_decimal("-1", 2), Err(AmountError::Negative));
    }

    #[test]
    fn brl_to_usdc_default_rate() {
        // 150 / 5.5 = 27.272727...
        let usdc = brl_to_usdc("150.00", "5.5").unwrap();
        assert_eq!(usdc, "27.272727");
    }

    #[test]
    fn format_usdc_trims_zeros() {
        let a = parse_decimal("10.500000", 6).unwrap();
        assert_eq!(format_usdc(&a), "10.5");
        let b = parse_decimal("10", 6).unwrap();
        assert_eq!(format_usdc(&b), "10");
    }

    #[test]
    fn format_minor_units_shortest_form() {
        // The exact strings the video script depends on: 1 / 10 / 9, not 1.000000.
        assert_eq!(format_minor_units(1_000_000, 6), "1");
        assert_eq!(format_minor_units(10_000_000, 6), "10");
        assert_eq!(format_minor_units(9_000_000, 6), "9");
        assert_eq!(format_minor_units(27_270_000, 6), "27.27");
        assert_eq!(format_minor_units(42_500_000, 6), "42.5");
        assert_eq!(format_minor_units(0, 6), "0");
        assert_eq!(format_minor_units(1, 6), "0.000001");
    }

    #[test]
    fn compare_units_exact_equality_has_no_tolerance() {
        // Exactly the invoiced amount → Equal.
        let c = compare_units_to_decimal(100_000_000, 6, "100").unwrap();
        assert_eq!(c.ordering, Ordering::Equal);
        assert_eq!(c.diff, "0");
        assert_eq!(c.expected_fmt, "100");

        // One millionth short of 100 USDC is *not* paid. The old f64 path
        // accepted anything above 99.5.
        let c = compare_units_to_decimal(99_999_999, 6, "100").unwrap();
        assert_eq!(c.ordering, Ordering::Less);
        assert_eq!(c.diff, "0.000001");

        // 99.6 of 100 — the case the 0.5% tolerance used to call PAID.
        let c = compare_units_to_decimal(99_600_000, 6, "100").unwrap();
        assert_eq!(c.ordering, Ordering::Less);
        assert_eq!(c.diff, "0.4");
    }

    #[test]
    fn compare_units_reports_shortfall_and_excess() {
        let short = compare_units_to_decimal(1_000_000, 6, "10").unwrap();
        assert_eq!(short.ordering, Ordering::Less);
        assert_eq!(short.diff, "9");
        assert_eq!(short.expected_fmt, "10");

        let over = compare_units_to_decimal(120_000_000, 6, "100").unwrap();
        assert_eq!(over.ordering, Ordering::Greater);
        assert_eq!(over.diff, "20");
    }

    #[test]
    fn compare_units_expected_more_precise_than_the_token() {
        // 1.2345678 cannot be represented at 6 decimals. Paying the closest
        // representable amount below it must stay UNDERPAID, never round up.
        let c = compare_units_to_decimal(1_234_567, 6, "1.2345678").unwrap();
        assert_eq!(c.ordering, Ordering::Less);
        assert_eq!(c.scale, 7);
        assert_eq!(c.diff, "0.0000008");

        // Trailing zeros beyond the token's precision are harmless.
        let c = compare_units_to_decimal(10_000_000, 6, "10.0000000").unwrap();
        assert_eq!(c.ordering, Ordering::Equal);
        assert_eq!(c.expected_fmt, "10");
    }

    #[test]
    fn compare_units_rejects_garbage_and_absurd_precision() {
        assert!(compare_units_to_decimal(1, 6, "abc").is_err());
        assert!(compare_units_to_decimal(1, 6, "-5").is_err());
        assert!(compare_units_to_decimal(1, 6, "").is_err());
        let too_precise = format!("1.{}", "0".repeat(30));
        assert_eq!(
            compare_units_to_decimal(1, 6, &too_precise),
            Err(AmountError::Overflow)
        );
    }

    #[test]
    fn compare_units_zero_expected_is_flagged() {
        let c = compare_units_to_decimal(5_000_000, 6, "0").unwrap();
        assert_eq!(c.expected_units, 0);
    }
}
