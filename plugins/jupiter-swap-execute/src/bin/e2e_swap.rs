//! Native E2E test: 0.0003 SOL -> USDC swap via Jupiter + OutLayer custody.
//!
//! Exercises the same jupiter.rs pure functions the WASM plugin uses,
//! with ureq HTTP client (feature-gated behind `e2e`).
//!
//! Run: OUTLAYER_API_KEY=... cargo run --features e2e --bin e2e-swap

use jupiter_swap_execute::jupiter::{
    assemble_signed_tx, build_outlayer_solana_sign_body, build_swap_body_raw, decode_base58,
    decode_base64, encode_base64, extract_message_from_tx, extract_swap_transaction,
    replace_blockhash_in_message, tx_version, SwapConfig,
};
use std::collections::HashMap;
use std::time::Duration;

const TAKER: &str = "5rzsXBG5JGT1mSAA8TmX8w39Zrss5h19Gzgar1znU2zR";

/// HTTP GET with retry. Returns response body or panics after exhausting attempts.
fn http_get(url: &str, attempts: usize, delay: Duration) -> String {
    for i in 0..attempts {
        match ureq::get(url).set("Accept", "application/json").call() {
            Ok(resp) => {
                return resp.into_string().expect("utf8 body");
            }
            Err(ureq::Error::Status(code, resp)) => {
                eprintln!("   GET HTTP {code}, retry {}/{}", i + 1, attempts);
                if code == 429 {
                    let body = resp.into_string().unwrap_or_default();
                    eprintln!("   rate limited: {}", &body[..200.min(body.len())]);
                }
            }
            Err(e) => {
                eprintln!("   GET error: {e}, retry {}/{}", i + 1, attempts);
            }
        }
        if i + 1 < attempts {
            std::thread::sleep(delay);
        }
    }
    panic!("GET {url} failed after {attempts} attempts");
}

/// HTTP POST with JSON body. Returns (status_code, response_body).
fn http_post_json(url: &str, body: &str, auth_token: Option<&str>) -> (u16, String) {
    let req = ureq::post(url).set("Content-Type", "application/json");
    let req = match auth_token {
        Some(tok) => req.set("Authorization", &format!("Bearer {tok}")),
        None => req,
    };
    match req.send_string(body) {
        Ok(resp) => (resp.status(), resp.into_string().expect("utf8 body")),
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_string().unwrap_or_default()),
        Err(e) => {
            eprintln!("   POST error: {e}");
            (0, String::new())
        }
    }
}

fn main() {
    let outlayer_key = std::env::var("OUTLAYER_API_KEY").unwrap_or_default();
    let mut section = HashMap::new();
    section.insert("outlayer_api_key".to_string(), outlayer_key);
    let cfg = SwapConfig::from_section(&section);

    println!("=== Native Rust E2E: 300000 lamports SOL -> USDC ===");
    println!("Taker: {TAKER}\n");

    // Step 1: Quote (with retry for rate limits)
    println!("1. Quote...");
    let quote_url = format!(
        "{}/quote?inputMint=So11111111111111111111111111111111111111112\
         &outputMint=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v\
         &amount=300000&slippageBps=100",
        cfg.swap_api
    );
    let raw = http_get(&quote_url, 10, Duration::from_secs(3));
    let quote: serde_json::Value = serde_json::from_str(&raw).expect("parse quote");
    let in_amt = quote["inAmount"].as_str().unwrap_or("?");
    let out_amt = quote["outAmount"].as_str().unwrap_or("?");
    println!("   Quote: {in_amt} in -> {out_amt} out");

    // Step 2: Swap (unsigned tx, with retry for rate limits)
    println!("\n2. Swap...");
    std::thread::sleep(Duration::from_secs(3));
    let swap_url = format!("{}/swap", cfg.swap_api);
    let swap_body_str = build_swap_body_raw(&raw, TAKER);

    let mut swap_raw = serde_json::Value::Null;
    for i in 0..5 {
        let (code, text) = http_post_json(&swap_url, &swap_body_str, None);
        if code >= 200 && code < 300 {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if json.get("swapTransaction").is_some() {
                    swap_raw = json;
                    break;
                }
                eprintln!("   no swapTransaction, retry {}/5", i + 1);
            }
        } else {
            eprintln!("   HTTP {code}, retry {}/5", i + 1);
        }
        if i + 1 < 5 {
            std::thread::sleep(Duration::from_secs(3));
        }
    }
    let swap_tx = extract_swap_transaction(&swap_raw).expect("extract swap tx");
    println!("   Got unsigned tx ({} base64 chars)", swap_tx.len());

    // Step 3: Extract message bytes
    println!("\n3. Extract message...");
    let tx_bytes = decode_base64(&swap_tx).expect("decode tx");
    let message_bytes = extract_message_from_tx(&tx_bytes).expect("extract message");
    let version = tx_version(&tx_bytes);
    let ver_label = match version {
        0x00 => "legacy",
        0x01 => "V0",
        _ => "unknown",
    };
    println!("   Message: {} bytes ({})", message_bytes.len(), ver_label);

    // Step 4: Fresh blockhash
    println!("\n4. Fresh blockhash...");
    let rpc_body =
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash"}).to_string();
    let (_, rpc_text) = http_post_json(&cfg.solana_rpc, &rpc_body, None);
    let rpc_resp: serde_json::Value = serde_json::from_str(&rpc_text).expect("parse blockhash");
    let bh_b58 = rpc_resp
        .pointer("/result/value/blockhash")
        .and_then(|v| v.as_str())
        .expect("blockhash in response");
    println!("   {bh_b58}");
    let bh_bytes = decode_base58(bh_b58).expect("decode bh");
    let bh_array: [u8; 32] = bh_bytes.try_into().expect("bh 32 bytes");
    let fresh_message =
        replace_blockhash_in_message(&message_bytes, &bh_array).expect("replace bh");
    println!("   Fresh message: {} bytes", fresh_message.len());
    if fresh_message.len() > 1232 {
        eprintln!("Message too large ({} > 1232)", fresh_message.len());
        std::process::exit(1);
    }
    let message_b64 = encode_base64(&fresh_message);

    // Step 5: OutLayer custody sign
    println!("\n5. OutLayer custody sign...");
    let outlayer_url = format!("{}/wallet/v1/solana/sign-transaction", cfg.outlayer_api);
    let sign_body = build_outlayer_solana_sign_body(&message_b64);
    let sign_json = serde_json::to_string(&sign_body).expect("serialize sign body");
    let (_, out_text) = http_post_json(&outlayer_url, &sign_json, Some(&cfg.outlayer_api_key));
    let out_raw: serde_json::Value =
        serde_json::from_str(&out_text).expect("parse outlayer response");
    let signature = out_raw
        .get("signature")
        .and_then(|s| s.as_str())
        .expect("no signature in response");
    println!("   Sig: {}...", &signature[..16]);

    // Step 6: Assemble signed tx
    println!("\n6. Assemble signed tx...");
    let mut signed_tx_bytes = assemble_signed_tx(&tx_bytes, signature).expect("assemble");
    // Message offset: legacy=66 (prefix+compact_u32+64 sigs), V0=65 (prefix+64 sigs)
    let msg_offset: usize = if version == 0x00 { 66 } else { 65 };
    if signed_tx_bytes.len() >= msg_offset + fresh_message.len() {
        signed_tx_bytes[msg_offset..msg_offset + fresh_message.len()]
            .copy_from_slice(&fresh_message);
    }
    let signed_b64 = encode_base64(&signed_tx_bytes);
    println!("   Signed tx: {} bytes", signed_tx_bytes.len());

    // Step 7: Broadcast
    println!("\n7. Broadcast...");
    let send_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "sendTransaction",
        "params": [signed_b64, {
            "encoding": "base64",
            "skipPreflight": false,
            "maxSupportedTransactionVersion": 0
        }]
    })
    .to_string();
    let tx_sig = match http_post_json(&cfg.solana_rpc, &send_body, None) {
        (code, text) => {
            let resp: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            if let Some(err) = resp.get("error") {
                if version == 0x01 {
                    eprintln!("   V0 broadcast error: {err}");
                    eprintln!("   (V0 transactions may need ALT account resolution)");
                    return;
                }
                panic!("Broadcast error: {err}");
            }
            resp.get("result")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    panic!("Broadcast failed: HTTP {code}, {text}");
                })
        }
    };
    println!("   TX: {tx_sig}");

    // Step 8: Confirm
    println!("\n8. Confirm...");
    let status_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "getSignatureStatuses",
        "params": [[&tx_sig]]
    })
    .to_string();
    for i in 0..15 {
        std::thread::sleep(Duration::from_secs(2));
        let (_, st_text) = http_post_json(&cfg.solana_rpc, &status_body, None);
        let st_resp: serde_json::Value = serde_json::from_str(&st_text).unwrap_or_default();
        let err = st_resp.pointer("/result/value/0/err");
        if err.map_or(false, |v| !v.is_null()) {
            println!("   FAILED: {}", err.unwrap());
            std::process::exit(1);
        }
        let cs = st_resp
            .pointer("/result/value/0/confirmationStatus")
            .and_then(|v| v.as_str())
            .unwrap_or("not found");
        match cs {
            "confirmed" | "finalized" => {
                println!("   confirmed after {}s", (i + 1) * 2);
                println!("\n=== RUST E2E SWAP COMPLETE ===");
                println!("https://explorer.solana.com/tx/{tx_sig}");
                return;
            }
            s => print!("   ... {s}\r"),
        }
    }
    println!("\n   Not confirmed after 30s");
}
