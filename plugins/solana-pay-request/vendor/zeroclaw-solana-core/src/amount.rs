//! Exact decimal-string ↔ base-unit conversion. Token amounts never touch a
//! float: "0.1" with 6 decimals is exactly 100_000, and anything the mint
//! cannot represent ("0.0000001" USDC) is an error, not a rounding.

/// Parse a human decimal string into base units for a mint with `decimals`.
/// Longest a legitimate amount string can be: u64::MAX is 20 digits, plus a
/// dot and a fractional part. Anything longer is a flood attempt (e.g.
/// `"0"×50000+"1"` is numerically valid but must never reach output).
pub const MAX_AMOUNT_CHARS: usize = 40;

pub fn parse_decimal_amount(s: &str, decimals: u8) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("amount is empty".to_string());
    }
    if s.len() > MAX_AMOUNT_CHARS {
        return Err("amount string is too long".to_string());
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
    // `decimals` can come straight from an untrusted mint account (a u8, so up
    // to 255), where `10^decimals` overflows u64. Never panic on hostile data:
    // any u64 amount is entirely fractional once the scale exceeds it, so
    // render "0.<amount>" with the reported precision instead of trapping.
    let scale = match 10u64.checked_pow(decimals as u32) {
        Some(s) => s,
        None => {
            let frac = format!("{amount:0>width$}", width = decimals as usize);
            let frac = frac.trim_end_matches('0');
            return if frac.is_empty() {
                "0".to_string()
            } else {
                format!("0.{frac}")
            };
        }
    };
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
    fn format_never_panics_on_hostile_decimals() {
        // `decimals` from an untrusted mint account can be anything up to 255.
        // 10^decimals overflows u64 for decimals >= 20; formatting must not
        // trap (the exact crash a hostile mint could trigger in
        // token-risk-check). For those, any u64 is wholly fractional.
        for decimals in [20u8, 40, 64, 128, 255] {
            let out = format_base_units(u64::MAX, decimals);
            assert!(out.starts_with("0."), "decimals={decimals} → {out}");
        }
        // decimals=19 does NOT overflow (10^19 < u64::MAX) — real division.
        assert!(format_base_units(u64::MAX, 19).starts_with("1."));
        assert_eq!(format_base_units(0, 255), "0");
    }

    #[test]
    fn round_trips() {
        for s in ["0.000001", "1", "123.456789", "0.5"] {
            let units = parse_decimal_amount(s, 6).unwrap();
            assert_eq!(format_base_units(units, 6), s);
        }
    }
}
