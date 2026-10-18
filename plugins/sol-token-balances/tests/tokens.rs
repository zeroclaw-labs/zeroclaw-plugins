//! Host-run tests for the `sol-token-balances` pure core, plus live smoke
//! checks against mainnet-beta and Jupiter's price API. These run with a plain
//! `cargo test` on the native target; the wasm component reuses the exact same
//! functions through `lib.rs`, so proving them here proves the behavior the
//! component runs inside the wasmtime host.

use std::collections::HashMap;

use sol_token_balances::tokens::{
    build_price_url, build_request_body, distinct_mints, format_output, mint_batches,
    parse_price_response, parse_token_accounts, ui_from_raw, validate_pubkey, TokenBalance,
    TokenConfig, DEFAULT_JUPITER_BASE_URL, DEFAULT_RPC_URL, TOKEN_PROGRAM_ID,
};

fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// Well-known mainnet constants used across the tests.
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";
// Binance hot wallet: a long-lived, always-populated SPL token owner, used only
// by the live smoke test.
const BINANCE_HOT_WALLET: &str = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";

// ---- config resolution (the `__config` jail) --------------------------------

#[test]
fn empty_config_falls_back_to_defaults() {
    let cfg = TokenConfig::from_section(&HashMap::new());
    assert_eq!(cfg.rpc_url, DEFAULT_RPC_URL);
    assert_eq!(cfg.jupiter_base_url, DEFAULT_JUPITER_BASE_URL);
}

#[test]
fn config_overrides_both_urls() {
    let cfg = TokenConfig::from_section(&section(&[
        ("rpc_url", "https://example.test/rpc"),
        ("jupiter_base_url", "https://jup.test"),
    ]));
    assert_eq!(cfg.rpc_url, "https://example.test/rpc");
    assert_eq!(cfg.jupiter_base_url, "https://jup.test");
}

#[test]
fn blank_values_fall_back_to_defaults() {
    let cfg = TokenConfig::from_section(&section(&[("rpc_url", "  "), ("jupiter_base_url", "")]));
    assert_eq!(cfg.rpc_url, DEFAULT_RPC_URL);
    assert_eq!(cfg.jupiter_base_url, DEFAULT_JUPITER_BASE_URL);
}

// ---- base58 pubkey validation -----------------------------------------------

#[test]
fn validate_accepts_real_pubkeys() {
    assert_eq!(validate_pubkey(USDC_MINT).unwrap(), USDC_MINT);
    assert_eq!(
        validate_pubkey(BINANCE_HOT_WALLET).unwrap(),
        BINANCE_HOT_WALLET
    );
}

#[test]
fn validate_rejects_bad_input() {
    assert!(validate_pubkey("").is_err());
    assert!(validate_pubkey("   ").is_err());
    assert!(validate_pubkey("not valid 0OIl").is_err());
    assert!(validate_pubkey("abc").is_err());
}

// ---- JSON-RPC request construction ------------------------------------------

#[test]
fn request_body_is_well_formed_jsonrpc() {
    let body = build_request_body(BINANCE_HOT_WALLET);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["method"], "getTokenAccountsByOwner");
    assert_eq!(v["params"][0], BINANCE_HOT_WALLET);
    assert_eq!(v["params"][1]["programId"], TOKEN_PROGRAM_ID);
    assert_eq!(v["params"][2]["encoding"], "jsonParsed");
}

// ---- getTokenAccountsByOwner response parsing -------------------------------

fn sample_accounts_response() -> &'static str {
    // Three accounts: a real USDC balance, a closed/zero account (must be
    // skipped), and one with a null uiAmount to exercise the fallback path. The
    // nesting mirrors a real `jsonParsed` reply: value[].account.data.parsed.info.
    r#"{
      "jsonrpc": "2.0",
      "id": 1,
      "result": {
        "context": { "slot": 1 },
        "value": [
          {
            "pubkey": "AcctUSDC",
            "account": { "data": { "program": "spl-token", "parsed": {
              "info": {
                "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "owner": "O",
                "tokenAmount": { "amount": "1500000", "decimals": 6, "uiAmount": 1.5, "uiAmountString": "1.5" }
              },
              "type": "account"
            } } }
          },
          {
            "pubkey": "AcctZero",
            "account": { "data": { "program": "spl-token", "parsed": {
              "info": {
                "mint": "So11111111111111111111111111111111111111112",
                "owner": "O",
                "tokenAmount": { "amount": "0", "decimals": 9, "uiAmount": 0.0, "uiAmountString": "0" }
              },
              "type": "account"
            } } }
          },
          {
            "pubkey": "AcctNull",
            "account": { "data": { "program": "spl-token", "parsed": {
              "info": {
                "mint": "MintNull",
                "owner": "O",
                "tokenAmount": { "amount": "250", "decimals": 2, "uiAmount": null, "uiAmountString": "2.5" }
              },
              "type": "account"
            } } }
          }
        ]
      }
    }"#
}

#[test]
fn parses_and_skips_zero_balances() {
    let tokens = parse_token_accounts(sample_accounts_response()).unwrap();
    // Zero-balance account dropped: 3 in -> 2 out.
    assert_eq!(tokens.len(), 2);

    let usdc = &tokens[0];
    assert_eq!(usdc.mint, USDC_MINT);
    assert_eq!(usdc.account, "AcctUSDC");
    assert_eq!(usdc.raw, "1500000");
    assert_eq!(usdc.decimals, 6);
    assert_eq!(usdc.amount, 1.5);

    // Null uiAmount falls back to uiAmountString.
    let null_ui = &tokens[1];
    assert_eq!(null_ui.mint, "MintNull");
    assert_eq!(null_ui.raw, "250");
    assert_eq!(null_ui.amount, 2.5);
}

#[test]
fn surfaces_rpc_error_message() {
    let body =
        r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid param: bad owner"},"id":1}"#;
    let err = parse_token_accounts(body).unwrap_err();
    assert!(err.contains("Invalid param"), "got: {err}");
}

#[test]
fn parses_empty_holdings() {
    let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":[]},"id":1}"#;
    assert_eq!(parse_token_accounts(body).unwrap().len(), 0);
}

#[test]
fn rejects_garbage_response() {
    assert!(parse_token_accounts("not json").is_err());
    assert!(parse_token_accounts("{}").is_err());
}

#[test]
fn ui_from_raw_is_correct() {
    assert_eq!(ui_from_raw("1500000", 6), 1.5);
    assert_eq!(ui_from_raw("0", 9), 0.0);
    assert_eq!(ui_from_raw("250", 2), 2.5);
}

// ---- Jupiter price request/response -----------------------------------------

#[test]
fn distinct_mints_dedupes_in_order() {
    let toks = vec![
        TokenBalance {
            mint: "A".into(),
            account: "a".into(),
            amount: 1.0,
            decimals: 0,
            raw: "1".into(),
        },
        TokenBalance {
            mint: "B".into(),
            account: "b".into(),
            amount: 1.0,
            decimals: 0,
            raw: "1".into(),
        },
        TokenBalance {
            mint: "A".into(),
            account: "c".into(),
            amount: 1.0,
            decimals: 0,
            raw: "1".into(),
        },
    ];
    assert_eq!(
        distinct_mints(&toks),
        vec!["A".to_string(), "B".to_string()]
    );
}

#[test]
fn mint_batches_chunks_by_fifty() {
    let mints: Vec<String> = (0..120).map(|i| format!("m{i}")).collect();
    let batches = mint_batches(&mints);
    assert_eq!(batches.len(), 3);
    assert_eq!(batches[0].len(), 50);
    assert_eq!(batches[1].len(), 50);
    assert_eq!(batches[2].len(), 20);
}

#[test]
fn price_url_is_well_formed() {
    let url = build_price_url(
        "https://lite-api.jup.ag/",
        &[WSOL_MINT.into(), USDC_MINT.into()],
    );
    assert_eq!(
        url,
        format!("https://lite-api.jup.ag/price/v3?ids={WSOL_MINT},{USDC_MINT}")
    );
}

#[test]
fn parses_price_response() {
    let body = r#"{
      "So11111111111111111111111111111111111111112":{"usdPrice":76.23,"decimals":9,"blockId":1},
      "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v":{"usdPrice":0.9998,"decimals":6,"blockId":1}
    }"#;
    let prices = parse_price_response(body).unwrap();
    assert_eq!(prices.get(WSOL_MINT), Some(&76.23));
    assert_eq!(prices.get(USDC_MINT), Some(&0.9998));
}

// ---- output formatting ------------------------------------------------------

#[test]
fn output_without_usd_omits_usd_fields() {
    let tokens = parse_token_accounts(sample_accounts_response()).unwrap();
    let out = format_output("Owner", DEFAULT_RPC_URL, &tokens, None);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["address"], "Owner");
    assert_eq!(v["token_count"], 2);
    assert_eq!(v["tokens"][0]["mint"], USDC_MINT);
    assert_eq!(v["tokens"][0]["raw"], "1500000");
    assert!(v.get("usd_enabled").is_none());
    assert!(v["tokens"][0].get("usd_value").is_none());
}

#[test]
fn output_with_usd_enriches_and_totals() {
    let tokens = parse_token_accounts(sample_accounts_response()).unwrap();
    let mut prices = HashMap::new();
    prices.insert(USDC_MINT.to_string(), 1.0);
    // "MintNull" is intentionally unpriced.
    let out = format_output("Owner", DEFAULT_RPC_URL, &tokens, Some(&prices));
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["usd_enabled"], true);
    assert_eq!(v["priced_token_count"], 1);
    assert_eq!(v["total_usd"], 1.5); // 1.5 USDC * $1
    assert_eq!(v["tokens"][0]["usd_value"], 1.5);
    // Unpriced token has no usd fields.
    assert!(v["tokens"][1].get("usd_value").is_none());
}

// ---- live smoke tests -------------------------------------------------------

/// End-to-end check against the real public RPC: fetch a known, always-populated
/// owner's token accounts and prove they parse into non-zero balances using the
/// same parser the wasm component runs. Transport/rate-limit failures are a soft
/// skip so offline and CI builds still pass.
///
/// Run with `cargo test -- --nocapture` to see the balances printed.
#[test]
fn live_rpc_smoke_token_balances() {
    let cfg = TokenConfig::from_section(&HashMap::new());
    let owner = validate_pubkey(BINANCE_HOT_WALLET).expect("valid owner pubkey");
    let body = build_request_body(&owner);

    let resp = match ureq::post(&cfg.rpc_url)
        .set("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(20))
        .send_string(&body)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("live_rpc_smoke_token_balances: SKIPPED (transport/RPC error: {e})");
            return;
        }
    };

    let text = resp.into_string().expect("read response body");
    let tokens = parse_token_accounts(&text).expect("live response should parse");
    assert!(
        !tokens.is_empty(),
        "the Binance hot wallet reliably holds SPL tokens"
    );
    for t in tokens.iter().take(5) {
        // Every returned balance is non-zero (zeros are filtered) and carries an
        // exact raw amount.
        assert!(t.raw.chars().any(|c| c != '0'));
        println!(
            "live_rpc_smoke_token_balances: {} = {} (raw {}, {} dp)",
            t.mint, t.amount, t.raw, t.decimals
        );
    }
    println!(
        "live_rpc_smoke_token_balances: {} non-zero token accounts via {}",
        tokens.len(),
        cfg.rpc_url
    );
}

/// End-to-end check against Jupiter's key-free price API: SOL and USDC must both
/// come back with a positive USD price, proving the URL builder and parser the
/// wasm component uses work against the live service. Soft-skips on transport
/// errors.
#[test]
fn live_jupiter_price_smoke() {
    let cfg = TokenConfig::from_section(&HashMap::new());
    let url = build_price_url(&cfg.jupiter_base_url, &[WSOL_MINT.into(), USDC_MINT.into()]);

    let resp = match ureq::get(&url)
        .timeout(std::time::Duration::from_secs(20))
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("live_jupiter_price_smoke: SKIPPED (transport/API error: {e})");
            return;
        }
    };

    let text = resp.into_string().expect("read response body");
    let prices = parse_price_response(&text).expect("live price response should parse");
    let sol = *prices.get(WSOL_MINT).expect("SOL should be priced");
    let usdc = *prices.get(USDC_MINT).expect("USDC should be priced");
    assert!(sol > 0.0, "SOL price should be positive");
    assert!(usdc > 0.0, "USDC price should be positive");
    println!("live_jupiter_price_smoke: SOL=${sol}, USDC=${usdc} via {url}");
}
