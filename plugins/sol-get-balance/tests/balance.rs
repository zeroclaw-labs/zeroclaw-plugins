//! Host-run tests for the `sol-get-balance` pure core, plus a live-RPC smoke
//! check. These run with a plain `cargo test` on the native target; the wasm
//! component reuses the exact same functions through `lib.rs`, so proving them
//! here proves the behavior the component runs inside the wasmtime host.

use std::collections::HashMap;

use sol_get_balance::balance::{
    build_request_body, format_output, lamports_to_sol, parse_balance_response, validate_pubkey,
    BalanceConfig, DEFAULT_RPC_URL, LAMPORTS_PER_SOL,
};

fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// Known, always-funded mainnet accounts used across the tests. Program and mint
// accounts are rent-exempt, so they reliably hold lamports.
const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// ---- config resolution (the `__config` jail) --------------------------------

#[test]
fn empty_config_falls_back_to_mainnet() {
    // The unprivileged (no config_read) case: an empty section -> safe default.
    let cfg = BalanceConfig::from_section(&HashMap::new());
    assert_eq!(cfg.rpc_url, DEFAULT_RPC_URL);
}

#[test]
fn config_overrides_rpc_url() {
    let cfg = BalanceConfig::from_section(&section(&[("rpc_url", "https://example.test/rpc")]));
    assert_eq!(cfg.rpc_url, "https://example.test/rpc");
}

#[test]
fn blank_rpc_url_falls_back_to_default() {
    let cfg = BalanceConfig::from_section(&section(&[("rpc_url", "   ")]));
    assert_eq!(cfg.rpc_url, DEFAULT_RPC_URL);
}

// ---- base58 pubkey validation -----------------------------------------------

#[test]
fn validate_accepts_real_pubkeys() {
    assert_eq!(validate_pubkey(WSOL_MINT).unwrap(), WSOL_MINT);
    assert_eq!(validate_pubkey(TOKEN_PROGRAM).unwrap(), TOKEN_PROGRAM);
    // The System Program id (all "1"s -> 32 zero bytes) is still a valid 32-byte key.
    assert!(validate_pubkey("11111111111111111111111111111111").is_ok());
}

#[test]
fn validate_trims_whitespace() {
    let padded = format!("  {WSOL_MINT}  ");
    assert_eq!(validate_pubkey(&padded).unwrap(), WSOL_MINT);
}

#[test]
fn validate_rejects_bad_input() {
    assert!(validate_pubkey("").is_err());
    assert!(validate_pubkey("   ").is_err());
    // '0', 'O', 'I', 'l' and space are not in the base58 alphabet.
    assert!(validate_pubkey("has invalid 0OIl chars").is_err());
    // Valid base58 but far fewer than 32 bytes.
    assert!(validate_pubkey("abc").is_err());
    // Valid base58 that decodes to 33 bytes -> rejected on length.
    let too_long = bs58::encode([7u8; 33]).into_string();
    assert!(validate_pubkey(&too_long).is_err());
}

// ---- JSON-RPC request construction ------------------------------------------

#[test]
fn request_body_is_well_formed_jsonrpc() {
    let body = build_request_body(WSOL_MINT);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["method"], "getBalance");
    assert_eq!(v["params"][0], WSOL_MINT);
    assert!(v["id"].is_number());
}

// ---- JSON-RPC response parsing ----------------------------------------------

#[test]
fn parses_successful_response() {
    let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":2039280},"id":1}"#;
    assert_eq!(parse_balance_response(body).unwrap(), 2_039_280);
}

#[test]
fn parses_zero_balance() {
    let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":0},"id":1}"#;
    assert_eq!(parse_balance_response(body).unwrap(), 0);
}

#[test]
fn surfaces_rpc_error_message() {
    let body =
        r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid param: WrongSize"},"id":1}"#;
    let err = parse_balance_response(body).unwrap_err();
    assert!(err.contains("Invalid param"), "got: {err}");
}

#[test]
fn rejects_garbage_response() {
    assert!(parse_balance_response("not json").is_err());
    assert!(parse_balance_response("{}").is_err());
    assert!(parse_balance_response(r#"{"result":{}}"#).is_err());
}

// ---- lamports -> SOL and output formatting ----------------------------------

#[test]
fn lamports_convert_to_sol() {
    assert_eq!(lamports_to_sol(LAMPORTS_PER_SOL), 1.0);
    assert_eq!(lamports_to_sol(0), 0.0);
    assert_eq!(lamports_to_sol(500_000_000), 0.5);
    assert_eq!(lamports_to_sol(2 * LAMPORTS_PER_SOL + 500_000_000), 2.5);
}

#[test]
fn output_is_machine_readable_json() {
    let out = format_output(WSOL_MINT, 1_500_000_000, DEFAULT_RPC_URL);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["address"], WSOL_MINT);
    assert_eq!(v["lamports"], 1_500_000_000u64);
    assert_eq!(v["sol"], 1.5);
    assert_eq!(v["rpc_url"], DEFAULT_RPC_URL);
}

// ---- live smoke test against mainnet-beta ------------------------------------

/// End-to-end check against the real public RPC: it exercises the same request
/// body builder and response parser the wasm component uses, over the network.
/// Transport or rate-limit failures are a soft skip (printed, not failed) so
/// offline and CI builds still pass; a successful HTTP response, however, must
/// parse and yield a positive balance for a rent-funded program account.
///
/// Run with `cargo test -- --nocapture` to see the live balance printed.
#[test]
fn live_rpc_smoke_get_balance() {
    let cfg = BalanceConfig::from_section(&HashMap::new());
    let address = validate_pubkey(TOKEN_PROGRAM).expect("token program is a valid pubkey");
    let body = build_request_body(&address);

    let resp = match ureq::post(&cfg.rpc_url)
        .set("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(15))
        .send_string(&body)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("live_rpc_smoke_get_balance: SKIPPED (transport/RPC error: {e})");
            return;
        }
    };

    let text = resp.into_string().expect("read response body");
    let lamports = parse_balance_response(&text).expect("live getBalance response should parse");
    assert!(
        lamports > 0,
        "the SPL Token program account is rent-funded and should have a positive balance"
    );
    println!(
        "live_rpc_smoke_get_balance: {address} = {lamports} lamports ({} SOL) via {}",
        lamports_to_sol(lamports),
        cfg.rpc_url
    );
}
