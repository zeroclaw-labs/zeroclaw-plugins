//! Property tests: invariants that must hold for ALL inputs, not just the
//! golden vectors. Safety past "tested" toward "proven".

use kiosk_core::pay::TransferRequest;
use kiosk_core::{b58, shortvec};
use proptest::prelude::*;

const MERCHANT: &str = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T";

proptest! {
    /// base58 is a lossless codec: decode ∘ encode == identity for ALL byte strings.
    #[test]
    fn b58_roundtrips(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        let encoded = b58::encode(&data);
        prop_assert_eq!(b58::decode(&encoded).unwrap(), data);
    }

    /// shortvec compact-u16 round-trips for every u16, consuming exactly its bytes.
    #[test]
    fn shortvec_roundtrips(n in any::<u16>()) {
        let e = shortvec::encode_len(n);
        prop_assert_eq!(shortvec::decode_len(&e), Some((n, e.len())));
    }

    /// Any in-range USDC amount (≤6 dp) survives the Pay builder: the URL carries
    /// exactly that value back, to base-unit precision.
    #[test]
    fn pay_amount_roundtrips(units in 1u64..=200_000_000u64) {
        // units are USDC base units (6 dp); render a canonical decimal string.
        let whole = units / 1_000_000;
        let frac = units % 1_000_000;
        let amount = if frac == 0 {
            format!("{whole}")
        } else {
            format!("{whole}.{frac:06}").trim_end_matches('0').to_string()
        };
        let req = TransferRequest::new(
            MERCHANT, &amount, 6, 300.0, None, None, None, None, None,
        ).expect("valid amount must build");
        let url = req.url();
        // Extract the amount= value and confirm it equals `units` base units.
        let amt = url.split("amount=").nth(1).unwrap().split('&').next().unwrap();
        let parsed: f64 = amt.parse().unwrap();
        prop_assert_eq!((parsed * 1_000_000.0).round() as u64, units);
    }
}
