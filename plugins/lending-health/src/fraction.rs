//! Kamino's fixed-point "Fraction" scalar.
//!
//! Kamino Lend stores USD values as a `U68F60` fixed-point number packed into a
//! little-endian `u128` (the on-chain fields carry the `_sf` suffix, short for
//! *scaled fraction*). The real value is the raw integer divided by `2^60`.
//!
//! Two decoded fields that share the scale (e.g. a debt value and a liquidation
//! threshold value) can be divided directly as raw integers (the `2^60` factors
//! cancel), which is how [`crate::kamino::health_factor`] stays exact. This
//! module only exists for turning a single field into a human-readable USD
//! number for display.

/// Number of fractional bits in Kamino's `U68F60` fixed-point representation.
pub const FRACTION_SCALE_BITS: i32 = 60;

/// Convert a raw scaled-fraction `u128` (`U68F60`) to an `f64` in whole units
/// (USD). Used for display only; health decisions divide raw integers so no
/// precision is lost where it matters.
pub fn fraction_to_f64(sf: u128) -> f64 {
    sf as f64 / 2f64.powi(FRACTION_SCALE_BITS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_whole_unit_is_two_to_the_sixty() {
        assert_eq!(fraction_to_f64(1u128 << 60), 1.0);
        assert_eq!(fraction_to_f64(0), 0.0);
    }

    #[test]
    fn half_and_quarter() {
        assert_eq!(fraction_to_f64(1u128 << 59), 0.5);
        assert_eq!(fraction_to_f64(1u128 << 58), 0.25);
    }

    #[test]
    fn decodes_a_real_deposited_value() {
        // deposited_value_sf from the embedded mainnet fixture
        // (obligation CmYJ8grTcyqNgLDfi85yGjghvA34ma1BTCN6TtuB6FT4).
        let usd = fraction_to_f64(3_283_415_344_819_750_587_562);
        assert!((usd - 2847.9088).abs() < 0.001, "got {usd}");
    }
}
