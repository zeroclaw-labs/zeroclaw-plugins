//! Tests for `kamino.rs` against committed, live-captured fixtures.
//! Offline-deterministic: no network access, no writes into the crate.

use liquidation_guard::kamino::{
    decode_snapshot, encode_snapshot, http_date_to_unix, parse_obligations, parse_prices,
    parse_reserves_metrics, price_is_stale, PriceRow, Snapshot,
};

const OBLIGATIONS: &str = include_str!("fixtures/obligations.json");
const PRICES: &str = include_str!("fixtures/prices.json");
const RESERVES_METRICS: &str = include_str!("fixtures/reserves_metrics.json");

const EXPECTED_OWNER: &str = "AcNSmd5CxwLs21TYUmhWt7CW2v159TdYRkvQxb1iBYRj";

#[test]
fn obligations_parse() {
    let obligations = parse_obligations(OBLIGATIONS).expect("obligations parse");
    assert!(!obligations.is_empty());
    let o = &obligations[0];

    assert_eq!(o.owner, EXPECTED_OWNER);
    assert_eq!(o.referrer, None, "all-zero sentinel referrer maps to None");

    // Fixture has 8 fixed deposit slots and 5 fixed borrow slots; only the
    // non-placeholder (non all-zero-reserve) rows should survive.
    assert_eq!(o.deposits.len(), 2, "placeholder deposit rows filtered");
    assert_eq!(o.borrows.len(), 1, "placeholder borrow rows filtered");
    for row in o.deposits.iter().chain(o.borrows.iter()) {
        assert_ne!(row.reserve, "11111111111111111111111111111111");
        assert!(!row.raw_amount.is_empty());
    }

    // Fractions, not percents.
    assert!(o.ltv > 0.0 && o.ltv < 1.0, "ltv = {}", o.ltv);
    assert!(
        o.liq_ltv > 0.0 && o.liq_ltv < 1.0,
        "liq_ltv = {}",
        o.liq_ltv
    );
    assert!(o.borrow_usd > 0.0);
    assert!(o.deposit_usd > 0.0);

    assert!(!o.obligation.is_empty());
    assert!(!o.market.is_empty());
}

/// harden F5: the dust threshold is parsed straight off the fetched
/// payload (`market.state.minFullLiquidationValueThreshold`, a JSON
/// string like every Kamino numeric) — never a hardcoded default.
#[test]
fn dust_threshold_parsed_from_payload() {
    let obligations = parse_obligations(OBLIGATIONS).expect("obligations parse");
    assert_eq!(obligations[0].min_full_liquidation_value_usd, Some(2.0));
}

/// harden F5: a payload missing the field maps to `None` (dust check
/// suppressed), never a hard parse error and never a silent default.
#[test]
fn missing_dust_threshold_is_none_not_error() {
    let mut value: serde_json::Value = serde_json::from_str(OBLIGATIONS).unwrap();
    value[0]["market"]["state"]
        .as_object_mut()
        .unwrap()
        .remove("minFullLiquidationValueThreshold");
    let body = serde_json::to_string(&value).unwrap();

    let obligations =
        parse_obligations(&body).expect("missing dust threshold must not be a hard error");
    assert_eq!(obligations[0].min_full_liquidation_value_usd, None);
}

/// Zero liquidatable deposit with debt still outstanding is the *most*
/// liquidatable state, not the safest.
///
/// It is what an obligation looks like once governance drops a collateral
/// asset's liquidation threshold to zero. Mapping that to `ltv = 0` made the
/// buffer 100% and the tier `OK` — a fabricated healthy verdict on a
/// position past every threshold, and reachable from honest API data.
/// Infinity is the honest ratio; `health::assess` turns it into CRITICAL.
#[test]
fn zero_liquidatable_deposit_with_debt_is_not_healthy() {
    let mut value: serde_json::Value = serde_json::from_str(OBLIGATIONS).unwrap();
    value[0]["refreshedStats"]["userTotalLiquidatableDeposit"] =
        serde_json::Value::String("0".to_string());
    let body = serde_json::to_string(&value).unwrap();

    let o = &parse_obligations(&body).expect("obligations parse")[0];
    assert!(o.borrow_usd > 0.0, "fixture must still carry debt");
    assert!(
        o.ltv.is_infinite(),
        "zero liquidatable deposit against outstanding debt must not report a finite LTV, got {}",
        o.ltv
    );

    // And an empty obligation — no deposit, no debt — is still genuinely 0.
    let mut value: serde_json::Value = serde_json::from_str(OBLIGATIONS).unwrap();
    value[0]["refreshedStats"]["userTotalLiquidatableDeposit"] =
        serde_json::Value::String("0".to_string());
    value[0]["refreshedStats"]["userTotalBorrowBorrowFactorAdjusted"] =
        serde_json::Value::String("0".to_string());
    let body = serde_json::to_string(&value).unwrap();
    assert_eq!(parse_obligations(&body).expect("parse")[0].ltv, 0.0);
}

/// A non-finite field must encode to nothing, not to a snapshot that looks
/// valid but can never be decoded.
///
/// `serde_json` writes a non-finite `f64` as `null` rather than failing, so
/// `encode_snapshot`'s `unwrap_or_default` never fired: the emitted snapshot
/// carried `"ltv":null`, showed that in the tool output, and always decoded
/// back to `None`. Reachable via `map_obligation`'s infinite `ltv` for debt
/// against zero liquidatable deposit.
#[test]
fn non_finite_snapshot_encodes_to_nothing() {
    let base = Snapshot {
        v: 1,
        obligation: "HcrU9nyaBFmhNPrxnwXRjreVxdQTZdq2dpvktjsWiS4J".to_string(),
        ltv: 0.63,
        liq_ltv: 0.8,
        collateral_price: 64_000.0,
        elevation_group: 0,
        taken_unix: 1_785_000_000,
    };
    // The finite case still round-trips.
    let encoded = encode_snapshot(&base);
    assert!(
        decode_snapshot(&encoded).is_some(),
        "a finite snapshot must still round-trip: {encoded:?}"
    );

    for (label, s) in [
        (
            "ltv",
            Snapshot {
                ltv: f64::INFINITY,
                ..base.clone()
            },
        ),
        (
            "liq_ltv",
            Snapshot {
                liq_ltv: f64::NAN,
                ..base.clone()
            },
        ),
        (
            "collateral_price",
            Snapshot {
                collateral_price: f64::NEG_INFINITY,
                ..base.clone()
            },
        ),
    ] {
        let encoded = encode_snapshot(&s);
        assert!(
            encoded.is_empty(),
            "non-finite {label} must encode to an empty string, got {encoded:?}"
        );
        assert!(
            !encoded.contains("null"),
            "non-finite {label} leaked a null into the snapshot: {encoded:?}"
        );
    }
}

/// Rust's `f64::from_str` accepts `"NaN"`, `"inf"` and `"1e400"`, and no
/// health math downstream guards against them. A *negative* or `-inf` borrow
/// total is the dangerous direction: it drives `buffer` above every
/// threshold and reports a maximally unhealthy position as `OK`. No money,
/// ratio, price or APY field here can legitimately be negative or infinite.
#[test]
fn non_finite_and_negative_payload_numbers_are_refused() {
    for bad in ["NaN", "inf", "-inf", "1e400", "-1e400", "-999999", "-0.5"] {
        let mut value: serde_json::Value = serde_json::from_str(OBLIGATIONS).unwrap();
        value[0]["refreshedStats"]["userTotalBorrowBorrowFactorAdjusted"] =
            serde_json::Value::String(bad.to_string());
        let body = serde_json::to_string(&value).unwrap();
        assert!(
            parse_obligations(&body).is_err(),
            "payload borrow total {bad:?} must be refused, not propagated into health math"
        );
    }
}

/// A malformed row fails the WHOLE list rather than being silently dropped.
///
/// Per-entry tolerance was tried and reverted: this endpoint is
/// `/users/{wallet}/obligations`, so every row is one of the user's OWN
/// positions. Dropping one removes a candidate, and removing a candidate is
/// what turns `select_obligation`'s "multiple obligations found; specify
/// 'obligation'" refusal into a silent single pick — a wallet holding a safe
/// position and a leveraged one, where the leveraged row is malformed, would
/// get a confident healthy verdict about the other position.
#[test]
fn one_malformed_row_fails_the_list_rather_than_dropping_a_position() {
    let value: serde_json::Value = serde_json::from_str(OBLIGATIONS).unwrap();
    let good = value[0].clone();
    let mut bad = value[0].clone();
    bad["state"]["deposits"][0]["depositReserve"] =
        serde_json::Value::String("not a pubkey at all".to_string());

    // Good row FIRST, so a lenient implementation would happily return it and
    // hide the malformed one.
    let body = serde_json::to_string(&serde_json::json!([good.clone(), bad.clone()])).unwrap();
    let err = parse_obligations(&body)
        .expect_err("a malformed row must fail the list, not vanish from it");
    assert!(
        err.contains("depositReserve"),
        "error should name the offending field, got {err:?}"
    );

    // Order must not matter.
    let body = serde_json::to_string(&serde_json::json!([bad, good])).unwrap();
    assert!(parse_obligations(&body).is_err());
}

/// harden F4: `market.state.autodeleverageEnabled` (a JSON number, `1` on
/// the committed fixture) parses to `true` — the market payload this
/// pipeline already fetches does carry the flag.
#[test]
fn market_adl_enabled_parsed_from_payload() {
    let obligations = parse_obligations(OBLIGATIONS).expect("obligations parse");
    assert!(obligations[0].market_adl_enabled);
}

#[test]
fn prices_parse() {
    let prices = parse_prices(PRICES).expect("prices parse");
    assert_eq!(prices.len(), 58);
    for row in &prices {
        assert!(!row.mint.is_empty());
        assert!(!row.name.is_empty());
        assert!(row.price > 0.0);
        assert!(row.timestamp > 0);
        assert!(row.max_age_s > 0);
    }
}

#[test]
fn metrics_parse() {
    let metrics = parse_reserves_metrics(RESERVES_METRICS).expect("metrics parse");
    assert_eq!(metrics.len(), 58);
    for m in &metrics {
        assert!(!m.reserve.is_empty());
        assert!(!m.mint.is_empty());
        assert!(!m.symbol.is_empty());
        assert!(m.borrow_apy >= 0.0);
        // utilization is Some for every live row (all have nonzero supply)
        // but the type stays Option — guard the divide-by-zero case exists.
        if let Some(u) = m.utilization {
            assert!(u >= 0.0);
        }
    }
}

#[test]
fn snapshot_round_trip() {
    let s = Snapshot {
        v: 1,
        obligation: "HcrU9nyaBFmhNPrxnwXRjreVxdQTZdq2dpvktjsWiS4J".to_string(),
        ltv: 0.7281521318825485,
        liq_ltv: 0.7992550392596365,
        collateral_price: 151.4,
        elevation_group: 0,
        taken_unix: 1_784_388_667,
    };
    let encoded = encode_snapshot(&s);
    let decoded = decode_snapshot(&encoded).expect("round trip");
    assert_eq!(decoded.v, s.v);
    assert_eq!(decoded.obligation, s.obligation);
    assert_eq!(decoded.ltv, s.ltv);
    assert_eq!(decoded.liq_ltv, s.liq_ltv);
    assert_eq!(decoded.collateral_price, s.collateral_price);
    assert_eq!(decoded.elevation_group, s.elevation_group);
    assert_eq!(decoded.taken_unix, s.taken_unix);
}

/// harden F6: an old-format snapshot (predates the `obligation` field)
/// fails to deserialize — a required field is missing — which already
/// degrades to `None` via `decode_snapshot`'s any-failure-is-None contract;
/// no version bump needed.
#[test]
fn old_format_snapshot_missing_obligation_is_none() {
    let old = serde_json::json!({
        "v": 1,
        "ltv": 0.5,
        "liq_ltv": 0.8,
        "collateral_price": 100.0,
        "elevation_group": 0,
        "taken_unix": 1,
    })
    .to_string();
    assert!(decode_snapshot(&old).is_none());
}

#[test]
fn decode_garbage_snapshot_is_none() {
    assert!(decode_snapshot("garbage").is_none());
    assert!(decode_snapshot("").is_none());
    assert!(
        decode_snapshot("{\"v\":1}").is_none(),
        "missing required fields"
    );
}

#[test]
fn missing_required_field_names_it() {
    let mut value: serde_json::Value = serde_json::from_str(OBLIGATIONS).unwrap();
    value[0]["state"].as_object_mut().unwrap().remove("owner");
    let body = serde_json::to_string(&value).unwrap();

    let err = parse_obligations(&body).expect_err("missing owner must error");
    assert!(err.contains("owner"), "error should name the field: {err}");
}

#[test]
fn http_date_to_unix_known_pair() {
    // Verified independently (Python `calendar.timegm`) against the RFC-1123
    // example from the issue spec.
    assert_eq!(
        http_date_to_unix("Sat, 18 Jul 2026 15:31:07 GMT").unwrap(),
        1_784_388_667
    );
    // Cross-checked against this fixture set's own capture-time Date header.
    assert_eq!(
        http_date_to_unix("Sun, 19 Jul 2026 06:53:34 GMT").unwrap(),
        1_784_444_014
    );
}

#[test]
fn http_date_to_unix_rejects_malformed() {
    assert!(http_date_to_unix("not a date").is_err());
    assert!(http_date_to_unix("Sat, 18 Xyz 2026 15:31:07 GMT").is_err());
    assert!(http_date_to_unix("Sat, 18 Jul 2026 15:31:07 UTC").is_err());
}

fn price(timestamp: i64, max_age_s: i64) -> PriceRow {
    PriceRow {
        mint: "mint".into(),
        name: "TOK".into(),
        price: 1.0,
        timestamp,
        max_age_s,
    }
}

#[test]
fn stale_prices_flagged() {
    // now is well past timestamp + max_age_s.
    let row = price(1_784_000_000, 120);
    let now = 1_784_000_300; // 300s later, max age 120s
    assert!(price_is_stale(now, &row));
}

#[test]
fn fresh_prices_not_flagged() {
    // now - timestamp is within max_age_s.
    let row = price(1_784_000_000, 120);
    let now = 1_784_000_050; // 50s later, max age 120s
    assert!(!price_is_stale(now, &row));

    // Real fixture-derived case: first prices row vs. this fixture set's
    // own capture-time Date header (55s old, 120s max age).
    let prices = parse_prices(PRICES).expect("prices parse");
    let now = http_date_to_unix("Sun, 19 Jul 2026 06:53:34 GMT").unwrap();
    assert!(!price_is_stale(now, &prices[0]));
}

/// EVERY numeric field of the HTTP `Date` header is range-checked.
///
/// Bounding only `year` left four fields feeding unchecked multiplies
/// (`days * 86_400`, `hour * 3600`, `min * 60`, and `doy + d` inside
/// `days_from_civil`). With `overflow-checks = true` in release an overflow is
/// a wasm TRAP, not an error, so a single hostile header broke
/// `guard::run`'s never-panics contract. These are the real RFC-1123 ranges.
#[test]
fn every_http_date_field_is_range_checked() {
    // The good case still parses.
    assert!(http_date_to_unix("Sat, 18 Jul 2026 15:31:07 GMT").is_ok());

    for (header, field) in [
        ("Sat, 200000000000000 Jul 2026 00:00:00 GMT", "day"),
        ("Sat, 9223372036854775807 Jul 2026 00:00:00 GMT", "day"),
        ("Sat, 0 Jul 2026 00:00:00 GMT", "day"),
        ("Sat, 32 Jul 2026 00:00:00 GMT", "day"),
        ("Sat, 18 Jul 2026 9223372036854775807:00:00 GMT", "hour"),
        ("Sat, 18 Jul 2026 24:00:00 GMT", "hour"),
        ("Sat, 18 Jul 2026 00:9223372036854775807:00 GMT", "minute"),
        ("Sat, 18 Jul 2026 00:60:00 GMT", "minute"),
        ("Sat, 18 Jul 2026 00:00:9223372036854775807 GMT", "second"),
        ("Sat, 18 Jul 2026 00:00:61 GMT", "second"),
        ("Sat, 18 Jul 999999999999999 00:00:00 GMT", "year"),
        ("Sat, 18 Jul 1969 00:00:00 GMT", "year"),
    ] {
        let out = http_date_to_unix(header);
        assert!(
            out.is_err(),
            "{field} out of range must be refused, not trapped: {header:?} -> {out:?}"
        );
    }

    // A leap second is legal.
    assert!(http_date_to_unix("Sat, 18 Jul 2026 23:59:60 GMT").is_ok());
}

/// Payload display strings are allowlisted, not merely control-stripped.
///
/// `char::is_control` catches newline and ESC but NOT the zero-width, bidi
/// and line/paragraph separators that also forge report lines or visually
/// reverse the text around them — and these strings are rendered into
/// model-visible output, including the `STALE DATA:` line on the two
/// transaction paths. Anything outside the allowlist becomes '?' so a hostile
/// value is visibly mangled rather than invisible.
#[test]
fn payload_display_strings_are_allowlisted() {
    let hostile = [
        "USDC\u{202E}drawkcab",       // bidi override
        "USDC\u{200B}\u{200B}hidden", // zero-width spaces
        "USDC\u{2028}snapshot: {}",   // line separator
        "USDC\u{FEFF}bom",            // zero-width no-break
        "USDC\nsnapshot: {}",         // plain newline
        "USDC\u{1b}[31mred",          // ANSI escape
    ];
    for raw in hostile {
        let mut prices: serde_json::Value = serde_json::from_str(PRICES).unwrap();
        prices[0]["name"] = serde_json::Value::String(raw.to_string());
        let parsed = parse_prices(&serde_json::to_string(&prices).unwrap()).expect("parse");
        let name = &parsed[0].name;
        for bad in [
            '\u{202E}', '\u{200B}', '\u{2028}', '\u{2029}', '\u{FEFF}', '\n', '\u{1b}',
        ] {
            assert!(
                !name.contains(bad),
                "{raw:?} leaked {bad:?} into model-visible output: {name:?}"
            );
        }
        assert!(
            !name.trim().is_empty(),
            "{raw:?} sanitized to blank, naming no asset at all"
        );
    }

    // A wholly hostile string still yields something visible, never blank.
    let mut prices: serde_json::Value = serde_json::from_str(PRICES).unwrap();
    prices[0]["name"] = serde_json::Value::String("\u{202E}\u{200B}\u{FEFF}".to_string());
    let parsed = parse_prices(&serde_json::to_string(&prices).unwrap()).expect("parse");
    assert!(!parsed[0].name.trim().is_empty());

    // And an ordinary symbol is untouched.
    let metrics = parse_reserves_metrics(RESERVES_METRICS).expect("parse");
    assert!(
        metrics.iter().any(|m| m.symbol == "USDG"),
        "real symbols must survive verbatim"
    );
}
