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
        int_part
            .parse()
            .map_err(|_| AmountError::Overflow)?
    };

    let factor = ten_pow(scale).ok_or(AmountError::Overflow)?;
    int_val = int_val
        .checked_mul(factor)
        .ok_or(AmountError::Overflow)?;

    let mut frac_val: u128 = if frac_part.is_empty() {
        0
    } else {
        frac_part
            .parse()
            .map_err(|_| AmountError::Overflow)?
    };
    // Pad fractional part to full scale: "12.3" with scale 2 → 30
    let pad = scale.saturating_sub(frac_part.len() as u32);
    if pad > 0 {
        let pad_factor = ten_pow(pad).ok_or(AmountError::Overflow)?;
        frac_val = frac_val
            .checked_mul(pad_factor)
            .ok_or(AmountError::Overflow)?;
    }

    let value = int_val
        .checked_add(frac_val)
        .ok_or(AmountError::Overflow)?;

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
        assert_eq!(
            compare_amount("100", "100.00", 2).unwrap(),
            Ordering::Equal
        );
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
}
