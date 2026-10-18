//! Output-shaping helpers.
//!
//! Trap #3 from the bounty: a raw RPC response can be 40 KB of JSON that nukes
//! the agent's context window and costs the operator money on every call. A tool
//! should return the ~200 tokens the model actually needs. These helpers convert
//! raw base-unit balances to human amounts, format percentages, abbreviate
//! addresses, and hard-cap output length.

use crate::Pubkey;

/// Convert a raw base-unit amount to its UI value given the mint's decimals.
pub fn ui_amount(raw: u64, decimals: u8) -> f64 {
    raw as f64 / 10f64.powi(decimals as i32)
}

/// Format a raw amount as a compact human string: thousands separators for the
/// integer part, up to `max_frac` fractional digits with trailing zeros trimmed.
pub fn format_amount(raw: u64, decimals: u8, max_frac: usize) -> String {
    let value = ui_amount(raw, decimals);
    format_f64(value, max_frac)
}

/// Format an `f64` with grouped integer digits and trimmed fractional digits.
pub fn format_f64(value: f64, max_frac: usize) -> String {
    let negative = value.is_sign_negative() && value != 0.0;
    let v = value.abs();
    let int_part = v.trunc() as u128;
    let grouped = group_thousands(int_part);

    let mut frac = format!("{:.*}", max_frac, v.fract());
    // frac looks like "0.xxxx"; keep the digits after the dot, trim zeros.
    let frac_digits = frac.split_off(frac.find('.').map(|i| i + 1).unwrap_or(frac.len()));
    let trimmed = frac_digits.trim_end_matches('0');

    let sign = if negative { "-" } else { "" };
    if trimmed.is_empty() {
        format!("{sign}{grouped}")
    } else {
        format!("{sign}{grouped}.{trimmed}")
    }
}

fn group_thousands(mut n: u128) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut parts = Vec::new();
    while n > 0 {
        parts.push(format!("{:03}", n % 1000));
        n /= 1000;
    }
    parts.reverse();
    // Strip the leading zeros of the most-significant group.
    let mut s = parts.join(",");
    while s.starts_with('0') && s.len() > 1 && s.as_bytes()[1] != b',' {
        s.remove(0);
    }
    s
}

/// Percentage of `part` out of `whole`, 0.0 when `whole` is 0.
pub fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64 / whole as f64) * 100.0
    }
}

/// Abbreviate a base58 address as `abcd…wxyz` for compact display.
pub fn abbrev_addr(addr: &str) -> String {
    let chars: Vec<char> = addr.chars().collect();
    if chars.len() <= 9 {
        return addr.to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

/// Abbreviate a raw pubkey for display.
pub fn abbrev_pubkey(key: &Pubkey) -> String {
    abbrev_addr(&crate::base58::encode(key))
}

/// Hard-cap a string to `max_chars`, appending a truncation marker if cut. Use
/// as a last-resort guard so a tool can never return an unbounded blob.
pub fn cap(s: &str, max_chars: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max_chars {
        return s.to_string();
    }
    let keep = max_chars.saturating_sub(1);
    let mut out: String = chars[..keep].iter().collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_ui_amount() {
        assert_eq!(ui_amount(1_500_000, 6), 1.5);
        assert_eq!(ui_amount(0, 9), 0.0);
    }

    #[test]
    fn formats_with_grouping_and_trimming() {
        assert_eq!(format_amount(1_234_567_000_000, 6, 4), "1,234,567");
        assert_eq!(format_amount(1_500_000, 6, 4), "1.5");
        assert_eq!(format_amount(1_050_000, 6, 4), "1.05");
        assert_eq!(format_amount(0, 6, 4), "0");
    }

    #[test]
    fn formats_small_fractions() {
        assert_eq!(format_amount(123, 6, 6), "0.000123");
    }

    #[test]
    fn computes_percentages() {
        assert_eq!(percent(25, 100), 25.0);
        assert_eq!(percent(1, 0), 0.0);
    }

    #[test]
    fn abbreviates_addresses() {
        assert_eq!(
            abbrev_addr("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            "Toke…Q5DA"
        );
        assert_eq!(abbrev_addr("short"), "short");
    }

    #[test]
    fn caps_long_output() {
        assert_eq!(cap("hello world", 5), "hell…");
        assert_eq!(cap("hi", 5), "hi");
    }
}
