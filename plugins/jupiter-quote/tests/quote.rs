//! Host-run tests for the `jupiter-quote` pure core, plus a live-API smoke
//! check. These run with a plain `cargo test` on the native target; the wasm
//! component reuses the exact same functions through `lib.rs`, so proving them
//! here proves the behavior the component runs inside the wasmtime host.

use std::collections::HashMap;

use jupiter_quote::quote::{
    amount_from_json, build_quote_url, format_output, parse_quote_response, route_summary,
    validate_amount, validate_mint, QuoteConfig, QuoteParams, DEFAULT_JUPITER_BASE_URL,
};

fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

// ---- config resolution ------------------------------------------------------

#[test]
fn empty_config_falls_back_to_lite() {
    let cfg = QuoteConfig::from_section(&HashMap::new());
    assert_eq!(cfg.jupiter_base_url, DEFAULT_JUPITER_BASE_URL);
}

#[test]
fn config_overrides_base_url() {
    let cfg = QuoteConfig::from_section(&section(&[("jupiter_base_url", "https://api.jup.ag")]));
    assert_eq!(cfg.jupiter_base_url, "https://api.jup.ag");
}

#[test]
fn blank_base_url_falls_back() {
    let cfg = QuoteConfig::from_section(&section(&[("jupiter_base_url", "   ")]));
    assert_eq!(cfg.jupiter_base_url, DEFAULT_JUPITER_BASE_URL);
}

// ---- mint validation --------------------------------------------------------

#[test]
fn validate_accepts_real_mints() {
    assert_eq!(validate_mint(WSOL_MINT).unwrap(), WSOL_MINT);
    assert_eq!(validate_mint(USDC_MINT).unwrap(), USDC_MINT);
}

#[test]
fn validate_rejects_bad_mints() {
    assert!(validate_mint("").is_err());
    assert!(validate_mint("not valid 0OIl").is_err());
    assert!(validate_mint("abc").is_err());
}

// ---- amount validation ------------------------------------------------------

#[test]
fn validate_amount_accepts_positive_integers() {
    assert_eq!(validate_amount("100000000").unwrap(), "100000000");
    // Leading zeros are stripped to canonical form.
    assert_eq!(validate_amount("00123").unwrap(), "123");
    assert_eq!(validate_amount("  42  ").unwrap(), "42");
}

#[test]
fn validate_amount_rejects_bad_values() {
    assert!(validate_amount("").is_err());
    assert!(validate_amount("0").is_err());
    assert!(validate_amount("00").is_err());
    assert!(validate_amount("1.5").is_err()); // no decimal point
    assert!(validate_amount("-5").is_err());
    assert!(validate_amount("1e9").is_err());
    assert!(validate_amount("abc").is_err());
}

#[test]
fn amount_from_json_accepts_string_and_number() {
    assert_eq!(
        amount_from_json(&serde_json::json!("100000000")).unwrap(),
        "100000000"
    );
    assert_eq!(
        amount_from_json(&serde_json::json!(100000000u64)).unwrap(),
        "100000000"
    );
    assert!(amount_from_json(&serde_json::json!(1.5)).is_err());
    assert!(amount_from_json(&serde_json::json!(true)).is_err());
}

// ---- URL construction -------------------------------------------------------

#[test]
fn quote_url_with_slippage() {
    let params = QuoteParams {
        input_mint: WSOL_MINT.into(),
        output_mint: USDC_MINT.into(),
        amount: "100000000".into(),
        slippage_bps: Some(50),
    };
    let url = build_quote_url("https://lite-api.jup.ag/", &params);
    assert_eq!(
        url,
        format!("https://lite-api.jup.ag/swap/v1/quote?inputMint={WSOL_MINT}&outputMint={USDC_MINT}&amount=100000000&restrictIntermediateTokens=true&slippageBps=50")
    );
}

#[test]
fn quote_url_without_slippage_omits_param() {
    let params = QuoteParams {
        input_mint: WSOL_MINT.into(),
        output_mint: USDC_MINT.into(),
        amount: "100000000".into(),
        slippage_bps: None,
    };
    let url = build_quote_url(DEFAULT_JUPITER_BASE_URL, &params);
    assert!(!url.contains("slippageBps"), "url: {url}");
    assert!(url.contains("amount=100000000"));
}

// ---- response parsing -------------------------------------------------------

fn sample_quote_response() -> &'static str {
    // Trimmed but faithful to the live shape (verified against lite-api.jup.ag).
    r#"{
      "inputMint": "So11111111111111111111111111111111111111112",
      "inAmount": "100000000",
      "outputMint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      "outAmount": "7624348",
      "otherAmountThreshold": "7586227",
      "swapMode": "ExactIn",
      "slippageBps": 50,
      "priceImpactPct": "0.0012",
      "swapUsdValue": "7.62308068150690",
      "routePlan": [
        {
          "swapInfo": {
            "ammKey": "9NC4xvsVLEZhpDwxXiGYN5KRi2Q7vtarkgZxUKcV67De",
            "label": "Meteora",
            "inputMint": "So11111111111111111111111111111111111111112",
            "outputMint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "inAmount": "100000000",
            "outAmount": "7624348"
          },
          "percent": 100
        }
      ]
    }"#
}

#[test]
fn parses_quote_fields_and_route() {
    let q = parse_quote_response(sample_quote_response()).unwrap();
    assert_eq!(q.input_mint, WSOL_MINT);
    assert_eq!(q.output_mint, USDC_MINT);
    assert_eq!(q.in_amount, "100000000");
    assert_eq!(q.out_amount, "7624348");
    assert_eq!(q.other_amount_threshold.as_deref(), Some("7586227"));
    assert_eq!(q.swap_mode.as_deref(), Some("ExactIn"));
    assert_eq!(q.slippage_bps, Some(50));
    // "0.0012" fraction -> 0.12%.
    assert!(
        (q.price_impact_pct - 0.12).abs() < 1e-9,
        "got {}",
        q.price_impact_pct
    );
    assert_eq!(q.route.len(), 1);
    assert_eq!(q.route[0].label, "Meteora");
    assert_eq!(q.route[0].percent, 100.0);
}

#[test]
fn route_summary_is_readable() {
    let q = parse_quote_response(sample_quote_response()).unwrap();
    assert_eq!(route_summary(&q.route), "Meteora (100%)");
    assert_eq!(route_summary(&[]), "no route");
}

#[test]
fn surfaces_jupiter_error() {
    let body = r#"{"error":"Could not find any route","errorCode":"NO_ROUTES_FOUND"}"#;
    let err = parse_quote_response(body).unwrap_err();
    assert!(err.contains("Could not find any route"), "got: {err}");
}

#[test]
fn rejects_garbage_response() {
    assert!(parse_quote_response("not json").is_err());
    assert!(parse_quote_response("{}").is_err()); // missing required fields
}

#[test]
fn output_is_machine_readable_json() {
    let q = parse_quote_response(sample_quote_response()).unwrap();
    let out = format_output(&q, DEFAULT_JUPITER_BASE_URL);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["input_mint"], WSOL_MINT);
    assert_eq!(v["out_amount"], "7624348");
    assert_eq!(v["hops"], 1);
    assert_eq!(v["route_summary"], "Meteora (100%)");
    assert_eq!(v["route"][0]["label"], "Meteora");
    assert_eq!(v["swap_usd_value"], "7.62308068150690");
}

// ---- live smoke test against Jupiter -----------------------------------------

/// End-to-end check against Jupiter's key-free quote API: quote 0.1 SOL -> USDC
/// and prove the response parses into a positive out amount and a non-empty
/// route, using the same URL builder and parser the wasm component runs.
/// Transport/rate-limit failures are a soft skip so offline and CI builds still
/// pass.
///
/// Run with `cargo test -- --nocapture` to see the live quote printed.
#[test]
fn live_jupiter_quote_smoke() {
    let cfg = QuoteConfig::from_section(&HashMap::new());
    let params = QuoteParams {
        input_mint: validate_mint(WSOL_MINT).unwrap(),
        output_mint: validate_mint(USDC_MINT).unwrap(),
        amount: validate_amount("100000000").unwrap(), // 0.1 SOL
        slippage_bps: Some(50),
    };
    let url = build_quote_url(&cfg.jupiter_base_url, &params);

    let resp = match ureq::get(&url)
        .timeout(std::time::Duration::from_secs(20))
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("live_jupiter_quote_smoke: SKIPPED (transport/API error: {e})");
            return;
        }
    };

    let text = resp.into_string().expect("read response body");
    let q = parse_quote_response(&text).expect("live quote response should parse");
    let out: u128 = q.out_amount.parse().expect("out amount is an integer");
    assert!(out > 0, "0.1 SOL should quote to a positive USDC amount");
    assert!(!q.route.is_empty(), "a real quote has at least one hop");
    println!(
        "live_jupiter_quote_smoke: 0.1 SOL -> {} USDC base units ({} USD), impact {}%, route: {}",
        q.out_amount,
        q.swap_usd_value.as_deref().unwrap_or("?"),
        q.price_impact_pct,
        route_summary(&q.route),
    );
}
