//! Exact decimal amount arithmetic. No floats, ever: a `f64` cannot represent
//! most decimal token amounts and the listing's own spec (Solana Pay) demands
//! exact arithmetic. Amounts travel as decimal strings and convert to base
//! units with the mint's decimals.

/// Errors from amount parsing. All fail closed.
#[derive(Debug, PartialEq, Eq)]
pub enum AmountError {
    Empty,
    BadChar,
    TooManyDots,
    TooManyDecimals { given: usize, allowed: u8 },
    Overflow,
    Zero,
    ScientificNotation,
}

impl std::fmt::Display for AmountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AmountError::Empty => write!(f, "amount is empty"),
            AmountError::BadChar => write!(f, "amount contains a non-digit character"),
            AmountError::TooManyDots => write!(f, "amount has more than one decimal point"),
            AmountError::TooManyDecimals { given, allowed } => {
                write!(
                    f,
                    "amount has {given} decimal places, mint allows {allowed}"
                )
            }
            AmountError::Overflow => write!(f, "amount overflows u64 base units"),
            AmountError::Zero => write!(f, "amount must be greater than zero"),
            AmountError::ScientificNotation => write!(f, "scientific notation is not allowed"),
        }
    }
}

/// Parse a decimal string ("25", "0.5", "1.000001") into base units for a
/// mint with `decimals`. Rejects zero, negatives (by construction: '-' is a
/// bad char), scientific notation, and excess precision.
pub fn to_base_units(amount: &str, decimals: u8) -> Result<u64, AmountError> {
    if amount.is_empty() {
        return Err(AmountError::Empty);
    }
    if amount.contains(['e', 'E']) {
        return Err(AmountError::ScientificNotation);
    }
    let parts: Vec<&str> = amount.split('.').collect();
    if parts.len() > 2 {
        return Err(AmountError::TooManyDots);
    }
    let whole = parts[0];
    let frac = parts.get(1).copied().unwrap_or("");
    if whole.is_empty() && frac.is_empty() {
        return Err(AmountError::Empty);
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(AmountError::BadChar);
    }
    if frac.len() > decimals as usize {
        return Err(AmountError::TooManyDecimals {
            given: frac.len(),
            allowed: decimals,
        });
    }
    let mut units: u64 = 0;
    for c in whole.chars().chain(frac.chars()) {
        units = units
            .checked_mul(10)
            .and_then(|u| u.checked_add(c as u64 - '0' as u64))
            .ok_or(AmountError::Overflow)?;
    }
    for _ in 0..(decimals as usize - frac.len()) {
        units = units.checked_mul(10).ok_or(AmountError::Overflow)?;
    }
    if units == 0 {
        return Err(AmountError::Zero);
    }
    Ok(units)
}

/// Render base units back to a decimal string for display ("25000000", 6 ->
/// "25", "25500000", 6 -> "25.5").
pub fn from_base_units(units: u64, decimals: u8) -> String {
    if decimals == 0 {
        return units.to_string();
    }
    let divisor = 10u64.pow(decimals as u32);
    let whole = units / divisor;
    let frac = units % divisor;
    if frac == 0 {
        whole.to_string()
    } else {
        let s = format!("{frac:0width$}", width = decimals as usize);
        format!("{whole}.{}", s.trim_end_matches('0'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_whole_and_decimal() {
        assert_eq!(to_base_units("25", 6).unwrap(), 25_000_000);
        assert_eq!(to_base_units("0.5", 6).unwrap(), 500_000);
        assert_eq!(to_base_units("1.000001", 6).unwrap(), 1_000_001);
        assert_eq!(to_base_units(".5", 6).unwrap(), 500_000);
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(to_base_units("", 6), Err(AmountError::Empty));
        assert_eq!(to_base_units("-1", 6), Err(AmountError::BadChar));
        assert_eq!(to_base_units("1.2.3", 6), Err(AmountError::TooManyDots));
        assert_eq!(
            to_base_units("1e6", 6),
            Err(AmountError::ScientificNotation)
        );
        assert_eq!(
            to_base_units("0.1234567", 6),
            Err(AmountError::TooManyDecimals {
                given: 7,
                allowed: 6
            })
        );
        assert_eq!(to_base_units("0", 6), Err(AmountError::Zero));
        assert_eq!(to_base_units("0.000000", 6), Err(AmountError::Zero));
        assert_eq!(to_base_units(".", 6), Err(AmountError::Empty));
    }

    #[test]
    fn float_trap_case_is_exact() {
        // 0.1 + 0.2 style: 9007199.254740993 at 9 decimals is not f64-exact;
        // string arithmetic is.
        assert_eq!(
            to_base_units("9007199.254740993", 9).unwrap(),
            9_007_199_254_740_993
        );
    }

    #[test]
    fn overflow_guard() {
        assert_eq!(
            to_base_units("18446744073709551616", 0),
            Err(AmountError::Overflow)
        );
        assert_eq!(
            to_base_units("18446744073709.551616", 6),
            Err(AmountError::Overflow)
        );
    }

    #[test]
    fn renders_back() {
        assert_eq!(from_base_units(25_000_000, 6), "25");
        assert_eq!(from_base_units(25_500_000, 6), "25.5");
        assert_eq!(from_base_units(1, 6), "0.000001");
        assert_eq!(from_base_units(7, 0), "7");
    }
}
