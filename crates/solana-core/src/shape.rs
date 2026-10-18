//! Output-shaping helpers — the answer to the bounty's trap #3 ("do not flood
//! the context window"). Plugins format their result through these so the model
//! sees ~200 tokens of decision-ready text, not 40KB of raw RPC JSON.

use crate::pubkey::Pubkey;

/// Lamports → SOL string, trimmed (1 SOL = 1e9 lamports).
pub fn lamports_to_sol(lamports: u64) -> String {
    ui_amount(lamports as u128, 9)
}

/// Raw base-unit amount → human decimal string, trailing zeros trimmed.
/// Integer math throughout, so no float rounding on large supplies.
pub fn ui_amount(raw: u128, decimals: u8) -> String {
    if decimals == 0 || decimals > 38 {
        return raw.to_string();
    }
    let scale = 10u128.pow(decimals as u32);
    let int = raw / scale;
    let frac = raw % scale;
    if frac == 0 {
        return int.to_string();
    }
    let mut frac_str = format!("{frac:0width$}", width = decimals as usize);
    while frac_str.ends_with('0') {
        frac_str.pop();
    }
    format!("{int}.{frac_str}")
}

/// Abbreviate a large integer: 1_234_567 → "1.23M".
pub fn abbreviate(n: u128) -> String {
    const UNITS: &[(u128, &str)] = &[
        (1_000_000_000_000, "T"),
        (1_000_000_000, "B"),
        (1_000_000, "M"),
        (1_000, "K"),
    ];
    for &(threshold, suffix) in UNITS {
        if n >= threshold {
            let whole = n / threshold;
            let frac = (n % threshold) * 100 / threshold;
            return format!("{whole}.{frac:02}{suffix}");
        }
    }
    n.to_string()
}

/// A pubkey shortened for chat: first 4 … last 4 base58 chars.
pub fn short_pubkey(key: &Pubkey) -> String {
    let s = key.to_base58();
    if s.len() <= 12 {
        return s;
    }
    format!("{}…{}", &s[..4], &s[s.len() - 4..])
}

/// Percentage with one decimal, e.g. 0.4211 → "42.1%".
pub fn percent(fraction: f64) -> String {
    format!("{:.1}%", fraction * 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_amount_trims_and_scales() {
        assert_eq!(ui_amount(1_000_000, 6), "1");
        assert_eq!(ui_amount(1_500_000, 6), "1.5");
        assert_eq!(ui_amount(1_234_500, 6), "1.2345");
        assert_eq!(ui_amount(1, 6), "0.000001");
        assert_eq!(ui_amount(0, 6), "0");
        assert_eq!(ui_amount(42, 0), "42");
    }

    #[test]
    fn lamports_to_sol_works() {
        assert_eq!(lamports_to_sol(1_000_000_000), "1");
        assert_eq!(lamports_to_sol(1_500_000_000), "1.5");
        assert_eq!(lamports_to_sol(5000), "0.000005");
    }

    #[test]
    fn abbreviate_scales() {
        assert_eq!(abbreviate(999), "999");
        assert_eq!(abbreviate(1_234), "1.23K");
        assert_eq!(abbreviate(1_234_567), "1.23M");
        assert_eq!(abbreviate(2_000_000_000), "2.00B");
    }

    #[test]
    fn short_pubkey_ellipsizes() {
        let k = Pubkey::from_base58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        assert_eq!(short_pubkey(&k), "EPjF…Dt1v");
    }

    #[test]
    fn percent_one_decimal() {
        assert_eq!(percent(0.4211), "42.1%");
    }
}
