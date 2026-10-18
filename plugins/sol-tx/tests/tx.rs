//! Host-run tests for the `sol-tx` pure core, plus a live-RPC smoke check. These
//! run with a plain `cargo test` on the native target; the wasm component reuses
//! the exact same functions through `lib.rs`, so proving them here proves the
//! behavior the component runs inside the wasmtime host.

use std::collections::HashMap;

use sol_tx::tx::{
    build_request_body, build_signatures_request, format_output, lamports_to_sol,
    parse_first_signature, parse_tx_response, validate_signature, TxConfig, TxLookup,
    DEFAULT_RPC_URL, LAMPORTS_PER_SOL,
};

fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// A stable, extremely active mainnet program used only to discover a fresh
// signature in the live smoke test (rather than hardcoding one that ages out).
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// ---- config resolution (the `__config` jail) --------------------------------

#[test]
fn empty_config_falls_back_to_mainnet() {
    let cfg = TxConfig::from_section(&HashMap::new());
    assert_eq!(cfg.rpc_url, DEFAULT_RPC_URL);
}

#[test]
fn config_overrides_rpc_url() {
    let cfg = TxConfig::from_section(&section(&[("rpc_url", "https://example.test/rpc")]));
    assert_eq!(cfg.rpc_url, "https://example.test/rpc");
}

#[test]
fn blank_rpc_url_falls_back_to_default() {
    let cfg = TxConfig::from_section(&section(&[("rpc_url", "   ")]));
    assert_eq!(cfg.rpc_url, DEFAULT_RPC_URL);
}

// ---- signature validation (64 bytes) ----------------------------------------

#[test]
fn validate_accepts_64_byte_signature() {
    // 64 arbitrary bytes base58-encoded is a valid signature shape.
    let sig = bs58::encode([9u8; 64]).into_string();
    assert_eq!(validate_signature(&sig).unwrap(), sig);
}

#[test]
fn validate_trims_whitespace() {
    let sig = bs58::encode([3u8; 64]).into_string();
    let padded = format!("  {sig}  ");
    assert_eq!(validate_signature(&padded).unwrap(), sig);
}

#[test]
fn validate_rejects_bad_signatures() {
    assert!(validate_signature("").is_err());
    assert!(validate_signature("   ").is_err());
    assert!(validate_signature("has invalid 0OIl chars").is_err());
    // A 32-byte pubkey is not a 64-byte signature.
    assert!(validate_signature(TOKEN_PROGRAM).is_err());
    // Valid base58 but wrong length.
    let too_short = bs58::encode([1u8; 32]).into_string();
    assert!(validate_signature(&too_short).is_err());
}

// ---- request construction ---------------------------------------------------

#[test]
fn request_body_is_well_formed_jsonrpc() {
    let sig = bs58::encode([5u8; 64]).into_string();
    let body = build_request_body(&sig);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["method"], "getTransaction");
    assert_eq!(v["params"][0], sig);
    assert_eq!(v["params"][1]["encoding"], "jsonParsed");
    assert_eq!(v["params"][1]["maxSupportedTransactionVersion"], 0);
}

#[test]
fn signatures_request_is_well_formed() {
    let body = build_signatures_request(TOKEN_PROGRAM, 3);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["method"], "getSignaturesForAddress");
    assert_eq!(v["params"][0], TOKEN_PROGRAM);
    assert_eq!(v["params"][1]["limit"], 3);
}

#[test]
fn parses_first_signature() {
    let body = r#"{"jsonrpc":"2.0","result":[
        {"signature":"SigA","slot":1,"err":null},
        {"signature":"SigB","slot":1,"err":null}
    ],"id":1}"#;
    assert_eq!(
        parse_first_signature(body).unwrap().as_deref(),
        Some("SigA")
    );
    // Empty list -> None.
    let empty = r#"{"jsonrpc":"2.0","result":[],"id":1}"#;
    assert_eq!(parse_first_signature(empty).unwrap(), None);
}

// ---- getTransaction response parsing ----------------------------------------

fn sample_success_response() -> &'static str {
    r#"{
      "jsonrpc": "2.0",
      "id": 1,
      "result": {
        "slot": 433887309,
        "blockTime": 1784460692,
        "version": 0,
        "meta": { "err": null, "fee": 6019, "status": { "Ok": null } },
        "transaction": { "message": { "accountKeys": [
          { "pubkey": "AXmnRBrNtYYyyo82cLBBhnWJ7o1iqNLZbuEVpDB3V666", "signer": true, "writable": true },
          { "pubkey": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "signer": false, "writable": false }
        ] } }
      }
    }"#
}

#[test]
fn parses_successful_transaction() {
    let lookup = parse_tx_response("SigX", sample_success_response()).unwrap();
    match lookup {
        TxLookup::Found(tx) => {
            assert!(tx.success);
            assert_eq!(tx.err, None);
            assert_eq!(tx.slot, 433887309);
            assert_eq!(tx.block_time, Some(1784460692));
            assert_eq!(tx.fee_lamports, 6019);
            assert_eq!(tx.version, Some(0));
            assert_eq!(tx.account_keys.len(), 2);
            assert_eq!(
                tx.account_keys[0],
                "AXmnRBrNtYYyyo82cLBBhnWJ7o1iqNLZbuEVpDB3V666"
            );
        }
        other => panic!("expected Found, got {other:?}"),
    }
}

#[test]
fn parses_failed_transaction() {
    let body = r#"{
      "jsonrpc":"2.0","id":1,
      "result":{
        "slot":100,"blockTime":null,"version":0,
        "meta":{"err":{"InstructionError":[4,{"Custom":6040}]},"fee":5000},
        "transaction":{"message":{"accountKeys":[{"pubkey":"Acc1","signer":true}]}}
      }
    }"#;
    match parse_tx_response("SigF", body).unwrap() {
        TxLookup::Found(tx) => {
            assert!(!tx.success);
            assert!(tx.err.as_deref().unwrap().contains("InstructionError"));
            assert_eq!(tx.block_time, None);
            assert_eq!(tx.fee_lamports, 5000);
        }
        other => panic!("expected Found, got {other:?}"),
    }
}

#[test]
fn parses_legacy_transaction_with_string_account_keys() {
    // Legacy (non-parsed) accountKeys are bare strings; version is absent.
    let body = r#"{
      "jsonrpc":"2.0","id":1,
      "result":{
        "slot":50,"blockTime":123,
        "meta":{"err":null,"fee":5000},
        "transaction":{"message":{"accountKeys":["Acc1","Acc2","Acc3"]}}
      }
    }"#;
    match parse_tx_response("SigL", body).unwrap() {
        TxLookup::Found(tx) => {
            assert_eq!(tx.version, None);
            assert_eq!(tx.account_keys, vec!["Acc1", "Acc2", "Acc3"]);
        }
        other => panic!("expected Found, got {other:?}"),
    }
}

#[test]
fn null_result_is_not_found() {
    let body = r#"{"jsonrpc":"2.0","result":null,"id":1}"#;
    assert_eq!(parse_tx_response("SigN", body).unwrap(), TxLookup::NotFound);
}

#[test]
fn surfaces_rpc_error_message() {
    let body =
        r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid param: WrongSize"},"id":1}"#;
    let err = parse_tx_response("SigE", body).unwrap_err();
    assert!(err.contains("WrongSize"), "got: {err}");
}

#[test]
fn rejects_garbage_response() {
    assert!(parse_tx_response("S", "not json").is_err());
}

// ---- formatting -------------------------------------------------------------

#[test]
fn lamports_convert_to_sol() {
    assert_eq!(lamports_to_sol(LAMPORTS_PER_SOL), 1.0);
    assert_eq!(lamports_to_sol(5000), 0.000005);
}

#[test]
fn not_found_output_is_clean() {
    let out = format_output(&TxLookup::NotFound, "SigN", DEFAULT_RPC_URL);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["found"], false);
    assert_eq!(v["signature"], "SigN");
    assert!(v["message"].as_str().unwrap().contains("not found"));
}

#[test]
fn found_output_is_machine_readable() {
    let lookup = parse_tx_response("SigX", sample_success_response()).unwrap();
    let out = format_output(&lookup, "SigX", DEFAULT_RPC_URL);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["found"], true);
    assert_eq!(v["status"], "success");
    assert_eq!(v["slot"], 433887309u64);
    assert_eq!(v["fee_lamports"], 6019u64);
    assert_eq!(v["fee_sol"], 0.000006019);
    assert_eq!(v["version"], 0);
    assert_eq!(v["account_count"], 2);
}

// ---- live smoke test against mainnet-beta ------------------------------------

/// End-to-end check against the real public RPC: discover a recent finalized
/// signature via `getSignaturesForAddress` (so nothing is hardcoded to age
/// out), then look it up with `getTransaction` and prove it decodes to a Found
/// summary with a real slot and account keys, using the same parsers the wasm
/// component runs. Transport/rate-limit failures are a soft skip so offline and
/// CI builds still pass.
///
/// Run with `cargo test -- --nocapture` to see the transaction printed.
#[test]
fn live_rpc_smoke_get_transaction() {
    let cfg = TxConfig::from_section(&HashMap::new());

    // Step 1: find a fresh signature from a very active program.
    let sig_body = build_signatures_request(TOKEN_PROGRAM, 5);
    let sig_resp = match ureq::post(&cfg.rpc_url)
        .set("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(20))
        .send_string(&sig_body)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("live_rpc_smoke_get_transaction: SKIPPED (transport/RPC error: {e})");
            return;
        }
    };
    let sig_text = sig_resp.into_string().expect("read signatures response");
    let signature = match parse_first_signature(&sig_text).expect("signatures should parse") {
        Some(s) => validate_signature(&s).expect("discovered signature should be valid"),
        None => {
            eprintln!("live_rpc_smoke_get_transaction: SKIPPED (no recent signatures returned)");
            return;
        }
    };

    // Step 2: look the transaction up.
    let body = build_request_body(&signature);
    let resp = match ureq::post(&cfg.rpc_url)
        .set("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(20))
        .send_string(&body)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("live_rpc_smoke_get_transaction: SKIPPED (transport/RPC error: {e})");
            return;
        }
    };
    let text = resp.into_string().expect("read transaction response");

    match parse_tx_response(&signature, &text).expect("live getTransaction should parse") {
        TxLookup::Found(tx) => {
            assert!(tx.slot > 0, "a finalized tx has a real slot");
            assert!(!tx.account_keys.is_empty(), "a real tx touches accounts");
            println!(
                "live_rpc_smoke_get_transaction: {} -> status={} slot={} fee={} lamports ({} SOL), {} accounts via {}",
                signature,
                if tx.success { "success" } else { "failed" },
                tx.slot,
                tx.fee_lamports,
                lamports_to_sol(tx.fee_lamports),
                tx.account_keys.len(),
                cfg.rpc_url,
            );
        }
        // Rare but possible: the freshest signature hasn't finalized on this
        // node yet. Treat as a soft skip rather than a hard failure.
        TxLookup::NotFound => {
            eprintln!("live_rpc_smoke_get_transaction: SKIPPED (freshest sig not yet finalized)");
        }
    }
}
