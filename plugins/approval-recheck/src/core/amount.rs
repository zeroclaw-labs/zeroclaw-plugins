//! Decimal-string ⇄ base-unit conversion, done in integer arithmetic only.
//!
//! Floating point is banned from money paths: `0.1 + 0.2` style drift in a
//! payment builder is a real loss. Amounts arrive from the LLM as strings and
//! leave as u64 base units, or the conversion fails closed.

/// Convert `"12.5"` with `decimals = 6` into `12_500_000`.
pub fn parse_amount(s: &str, decimals: u8) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("amount is empty".into());
    }
    if s.starts_with('-') || s.starts_with('+') {
        return Err("amount must be a plain positive decimal".into());
    }
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return Err("amount has no digits".into());
    }
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        return Err(format!("amount {s:?} contains non-digit characters"));
    }
    if frac_part.len() > decimals as usize {
        return Err(format!(
            "amount {s:?} has {} fractional digits but the token supports {decimals}",
            frac_part.len()
        ));
    }
    let scale = 10u64
        .checked_pow(decimals as u32)
        .ok_or("token decimals out of range")?;
    let int_val: u64 = if int_part.is_empty() {
        0
    } else {
        int_part
            .parse()
            .map_err(|_| format!("integer part of {s:?} overflows"))?
    };
    let frac_scale = 10u64.pow((decimals as usize - frac_part.len()) as u32);
    let frac_val: u64 = if frac_part.is_empty() {
        0
    } else {
        frac_part.parse::<u64>().expect("digits only") * frac_scale
    };
    int_val
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac_val))
        .ok_or_else(|| format!("amount {s:?} overflows u64 base units"))
}

/// Convert base units back to a human decimal string, trimming trailing zeros.
pub fn format_amount(base_units: u64, decimals: u8) -> String {
    if decimals == 0 {
        return base_units.to_string();
    }
    let scale = 10u64.pow(decimals as u32);
    let int = base_units / scale;
    let frac = base_units % scale;
    if frac == 0 {
        return int.to_string();
    }
    let frac_str = format!("{frac:0width$}", width = decimals as usize);
    format!("{int}.{}", frac_str.trim_end_matches('0'))
}

pub const LAMPORTS_PER_SOL_DECIMALS: u8 = 9;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_amounts() {
        assert_eq!(parse_amount("25", 6).unwrap(), 25_000_000);
        assert_eq!(parse_amount("12.5", 6).unwrap(), 12_500_000);
        assert_eq!(parse_amount("0.000001", 6).unwrap(), 1);
        assert_eq!(parse_amount(".5", 6).unwrap(), 500_000);
        assert_eq!(parse_amount("1", 9).unwrap(), 1_000_000_000);
        assert_eq!(parse_amount("0", 6).unwrap(), 0);
    }

    #[test]
    fn rejects_malformed_amounts() {
        for bad in ["", ".", "-1", "+1", "1e5", "1,5", "abc", "1.2.3", "1 000"] {
            assert!(parse_amount(bad, 6).is_err(), "should reject {bad:?}");
        }
        // Too many fractional digits for the mint.
        assert!(parse_amount("0.1234567", 6).is_err());
        // Overflow.
        assert!(parse_amount("18446744073709551616", 0).is_err());
        assert!(parse_amount("99999999999999", 9).is_err());
    }

    #[test]
    fn formats_and_roundtrips() {
        assert_eq!(format_amount(12_500_000, 6), "12.5");
        assert_eq!(format_amount(25_000_000, 6), "25");
        assert_eq!(format_amount(1, 6), "0.000001");
        assert_eq!(format_amount(0, 6), "0");
        assert_eq!(format_amount(42, 0), "42");
        for (s, d) in [("12.5", 6u8), ("0.000001", 6), ("7", 0), ("1.5", 9)] {
            let parsed = parse_amount(s, d).unwrap();
            assert_eq!(parse_amount(&format_amount(parsed, d), d).unwrap(), parsed);
        }
    }
}
