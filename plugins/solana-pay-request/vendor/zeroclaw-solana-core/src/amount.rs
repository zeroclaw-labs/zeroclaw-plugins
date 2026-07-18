//! Exact decimal-string ↔ base-unit conversion. Token amounts never touch a
//! float: "0.1" with 6 decimals is exactly 100_000, and anything the mint
//! cannot represent ("0.0000001" USDC) is an error, not a rounding.

/// Parse a human decimal string into base units for a mint with `decimals`.
pub fn parse_decimal_amount(s: &str, decimals: u8) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("amount is empty".to_string());
    }
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return Err(format!("invalid amount: {s:?}"));
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("invalid amount: {s:?} (digits and one '.' only)"));
    }
    if frac.len() > decimals as usize {
        return Err(format!(
            "amount {s:?} has {} fractional digits but the mint supports {decimals}",
            frac.len()
        ));
    }

    let scale = 10u64
        .checked_pow(decimals as u32)
        .ok_or("mint decimals too large")?;
    let whole_units = if whole.is_empty() {
        0
    } else {
        whole
            .parse::<u64>()
            .map_err(|_| format!("amount {s:?} is too large"))?
    };
    let frac_units = if frac.is_empty() {
        0
    } else {
        let padded = format!("{frac:0<width$}", width = decimals as usize);
        padded
            .parse::<u64>()
            .map_err(|_| format!("amount {s:?} is too large"))?
    };
    whole_units
        .checked_mul(scale)
        .and_then(|w| w.checked_add(frac_units))
        .ok_or_else(|| format!("amount {s:?} overflows u64 base units"))
}

/// Format base units back into a human decimal string (no trailing zeros).
pub fn format_base_units(amount: u64, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let scale = 10u64.pow(decimals as u32);
    let whole = amount / scale;
    let frac = amount % scale;
    if frac == 0 {
        return whole.to_string();
    }
    let frac_str = format!("{frac:0>width$}", width = decimals as usize);
    format!("{whole}.{}", frac_str.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_amounts() {
        assert_eq!(parse_decimal_amount("25", 6).unwrap(), 25_000_000);
        assert_eq!(parse_decimal_amount("0.1", 6).unwrap(), 100_000);
        assert_eq!(parse_decimal_amount("25.5", 6).unwrap(), 25_500_000);
        assert_eq!(parse_decimal_amount(".5", 9).unwrap(), 500_000_000);
        assert_eq!(parse_decimal_amount("7", 0).unwrap(), 7);
        assert_eq!(parse_decimal_amount(" 1.000001 ", 6).unwrap(), 1_000_001);
    }

    #[test]
    fn rejects_bad_amounts() {
        assert!(parse_decimal_amount("", 6).is_err());
        assert!(parse_decimal_amount(".", 6).is_err());
        assert!(parse_decimal_amount("-5", 6).is_err());
        assert!(parse_decimal_amount("1e6", 6).is_err());
        assert!(parse_decimal_amount("0.0000001", 6).is_err()); // sub-unit
        assert!(parse_decimal_amount("1.23", 0).is_err());
        assert!(parse_decimal_amount("99999999999999999999999", 6).is_err());
    }

    #[test]
    fn formats_base_units() {
        assert_eq!(format_base_units(25_000_000, 6), "25");
        assert_eq!(format_base_units(25_500_000, 6), "25.5");
        assert_eq!(format_base_units(1, 6), "0.000001");
        assert_eq!(format_base_units(7, 0), "7");
    }

    #[test]
    fn round_trips() {
        for s in ["0.000001", "1", "123.456789", "0.5"] {
            let units = parse_decimal_amount(s, 6).unwrap();
            assert_eq!(format_base_units(units, 6), s);
        }
    }
}
