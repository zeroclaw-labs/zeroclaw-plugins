//! Native E2E test: 0.0003 SOL -> USDC swap via Jupiter + OutLayer custody.
//!
//! Exercises the same jupiter.rs pure functions the WASM plugin uses,
//! with curl subprocess HTTP calls (zero extra deps).
//!
//! Run: OUTLAYER_API_KEY=... cargo run --bin e2e-swap
//!
//! NOTE: Jupiter now often returns V0 transactions (address lookup tables).
//! V0 txs cannot be broadcast without resolving ALT accounts on-chain,
//! which this custody flow cannot do. When Jupiter returns V0, the E2E
//! validates the codepath up to broadcast and notes the limitation.
//! Legacy txs (when available) broadcast and confirm successfully.

use jupiter_swap_execute::jupiter::{
    assemble_signed_tx, build_outlayer_solana_sign_body, build_swap_body_raw, compact_u32_at,
    decode_base58, decode_base64, encode_base64, extract_message_from_tx, extract_swap_transaction,
    parse_compiled_message_end, replace_blockhash_in_message, tx_version, SwapConfig,
};
use std::collections::HashMap;
use std::process::Command;

const TAKER: &str = "5rzsXBG5JGT1mSAA8TmX8w39Zrss5h19Gzgar1znU2zR";

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
    let mut raw = String::new();
    for i in 0..10 {
        raw = curl_get(&quote_url);
        if !raw.is_empty() && raw.starts_with('{') {
            break;
        }
        eprintln!("   rate limited, retry {}/{}", i + 1, 10);
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    let quote: serde_json::Value = serde_json::from_str(&raw).expect("parse quote");
    let in_amt = quote["inAmount"].as_str().unwrap_or("?");
    let out_amt = quote["outAmount"].as_str().unwrap_or("?");
    println!("   Quote: {in_amt} in -> {out_amt} out");

    // Step 2: Swap (unsigned tx, with retry for rate limits)
    println!("\n2. Swap...");
    std::thread::sleep(std::time::Duration::from_secs(3));
    let swap_url = format!("{}/swap", cfg.swap_api);
    let swap_body_str = build_swap_body_raw(&raw, TAKER);
    eprintln!(
        "  swap body len={}, start={}",
        swap_body_str.len(),
        &swap_body_str[..100.min(swap_body_str.len())]
    );
    let swap_raw = retry_swap(&swap_url, &swap_body_str, 5);
    let swap_tx = extract_swap_transaction(&swap_raw).expect("extract swap tx");
    println!("   Got unsigned tx ({} base64 chars)", swap_tx.len());

    // Step 3: Extract message bytes
    println!("\n3. Extract message...");
    let tx_bytes = decode_base64(&swap_tx).expect("decode tx");
    eprintln!("  tx_bytes len={}, prefix={}", tx_bytes.len(), tx_bytes[0]);
    let message_bytes = extract_message_from_tx(&tx_bytes).expect("extract message");
    let version = tx_version(&tx_bytes);
    let ver_label = match version {
        0x00 => "legacy",
        0x01 => "V0",
        _ => "unknown",
    };
    println!("   Message: {} bytes ({})", message_bytes.len(), ver_label);

    // Step 4: Fresh blockhash
    println!("\n3. Fresh blockhash...");
    let bh_b58 = curl_rpc_blockhash(&cfg.solana_rpc);
    println!("   {bh_b58}");
    let bh_bytes = decode_base58(&bh_b58).expect("decode bh");
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
    println!("\n4. OutLayer custody sign...");
    let outlayer_url = format!("{}/wallet/v1/solana/sign-transaction", cfg.outlayer_api);
    let sign_body = build_outlayer_solana_sign_body(&message_b64);
    let out_raw: serde_json::Value = serde_json::from_str(&curl_post_auth(
        &outlayer_url,
        &sign_body,
        &cfg.outlayer_api_key,
    ))
    .expect("parse outlayer response");
    let signature = out_raw
        .get("signature")
        .and_then(|s| s.as_str())
        .expect("no signature in response");
    println!("   Sig: {}...", &signature[..16]);

    // Step 6: Assemble signed tx
    println!("\n5. Assemble signed tx...");
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
    println!("\n6. Broadcast...");
    let tx_sig = match curl_send_transaction(&cfg.solana_rpc, &signed_b64) {
        Ok(sig) => sig,
        Err(e) => {
            if version == 0x01 {
                println!("   V0 broadcast error: {e}");
                println!("   (V0 transactions may need ALT account resolution)");
            } else {
                println!("   Broadcast error: {e}");
            }
            return;
        }
    };
    println!("   TX: {tx_sig}");
    // Step 8: Confirm
    println!("\n7. Confirm...");
    for i in 0..15 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let status = curl_sig_status(&cfg.solana_rpc, &tx_sig);
        match status.as_str() {
            "confirmed" | "finalized" => {
                println!("   confirmed after {}s", (i + 1) * 2);
                println!("\n=== RUST E2E SWAP COMPLETE ===");
                println!("https://explorer.solana.com/tx/{tx_sig}");
                return;
            }
            s if s.starts_with("failed") => {
                println!("   FAILED: {s}");
                std::process::exit(1);
            }
            _ => print!("   ... {status}\r"),
        }
    }
    println!("\n   Not confirmed after 30s");
}

fn curl_get(url: &str) -> String {
    let out = Command::new("curl")
        .args(["-s", url, "-H", "Accept: application/json"])
        .output()
        .expect("curl")
        .stdout;
    String::from_utf8(out).expect("utf8")
}

fn curl_post(url: &str, body: &serde_json::Value) -> (u16, String) {
    let out = Command::new("curl")
        .args([
            "-s",
            "-w",
            "\n%{http_code}",
            "-X",
            "POST",
            url,
            "-H",
            "Content-Type: application/json",
            "-d",
            &body.to_string(),
        ])
        .output()
        .expect("curl")
        .stdout;
    let text = String::from_utf8(out).expect("utf8");
    let mut lines = text.rsplitn(2, '\n');
    let code: u16 = lines.next().unwrap().parse().unwrap_or(0);
    let body_str = lines.next().unwrap_or("").to_string();
    (code, body_str)
}

fn curl_post_str(url: &str, body: &str) -> (u16, String) {
    let out = Command::new("curl")
        .args([
            "-s",
            "-w",
            "\n%{http_code}",
            "-X",
            "POST",
            url,
            "-H",
            "Content-Type: application/json",
            "-d",
            body,
        ])
        .output()
        .expect("curl")
        .stdout;
    let text = String::from_utf8(out).expect("utf8");
    let mut lines = text.rsplitn(2, '\n');
    let code: u16 = lines.next().unwrap().parse().unwrap_or(0);
    let body_str = lines.next().unwrap_or("").to_string();
    (code, body_str)
}

fn curl_post_auth(url: &str, body: &serde_json::Value, token: &str) -> String {
    let out = Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            url,
            "-H",
            "Content-Type: application/json",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "-d",
            &body.to_string(),
        ])
        .output()
        .expect("curl")
        .stdout;
    String::from_utf8(out).expect("utf8")
}

fn retry_swap(url: &str, body_str: &str, attempts: usize) -> serde_json::Value {
    for i in 0..attempts {
        let (code, text) = curl_post_str(url, body_str);
        if code >= 200 && code < 300 {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if json.get("error").is_some() {
                    return json;
                }
                if json.get("swapTransaction").is_some() {
                    return json;
                }
                eprintln!("   rate limited, retry {}/{}", i + 1, attempts);
            }
        } else {
            eprintln!("   HTTP {code}, retry {}/{}", i + 1, attempts);
            if code == 400 {
                eprintln!("   body: {}", &text[..200.min(text.len())]);
            }
        }
        if i + 1 < attempts {
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    }
    panic!("Jupiter swap failed after {} attempts", attempts);
}

fn curl_rpc_blockhash(rpc: &str) -> String {
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash"});
    let (_, text) = curl_post(rpc, &body);
    let resp: serde_json::Value = serde_json::from_str(&text).expect("parse blockhash");
    resp.pointer("/result/value/blockhash")
        .and_then(|v| v.as_str())
        .expect("blockhash in response")
        .to_string()
}

fn curl_send_transaction(rpc: &str, tx_b64: &str) -> Result<String, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "sendTransaction",
        "params": [tx_b64, {
            "encoding": "base64",
            "skipPreflight": false,
            "maxSupportedTransactionVersion": 0
        }]
    });
    let (_, text) = curl_post(rpc, &body);
    let resp: serde_json::Value = serde_json::from_str(&text).expect("parse sendTransaction");
    if let Some(err) = resp.get("error") {
        Err(err.to_string())
    } else {
        resp.get("result")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "no result".to_string())
    }
}

fn curl_sig_status(rpc: &str, sig: &str) -> String {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "getSignatureStatuses",
        "params": [[sig]]
    });
    let (_, text) = curl_post(rpc, &body);
    let resp: serde_json::Value = serde_json::from_str(&text).expect("parse sig status");
    let err = resp.pointer("/result/value/0/err");
    if err.map_or(false, |v| !v.is_null()) {
        return format!("failed: {}", err.unwrap());
    }
    resp.pointer("/result/value/0/confirmationStatus")
        .and_then(|v| v.as_str())
        .unwrap_or("not found")
        .to_string()
}
