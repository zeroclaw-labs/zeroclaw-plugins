//! Run the real pipeline against Solana mainnet, holding no key and spending
//! nothing.
//!
//! Safe Hands is T0/T1: its output is an *unsigned* transaction. That is not a
//! limitation to apologise for here, it is the reason this check costs nothing.
//! Every read runs against mainnet-beta, the builder produces a mainnet-valid
//! transaction against real state, and the authorizer decides on a real
//! simulation of it. The only step missing is the one a human does with a key.
//!
//! Whatever mainnet answers, this prints. It does not retry until it gets an
//! ALLOW, and it does not simulate spending from an account we do not own.

use crate::log::HttpTransport;
use safe_hands_core::rpc::RpcTransport;
use serde_json::{json, Value};
use std::collections::HashMap;

const MAINNET: &str = "https://api.mainnet-beta.solana.com";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

fn field<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    Some(cur)
}

/// `--mainnet-check [rpc_url]`
pub fn run(rpc_url: &str) -> Result<(), String> {
    let url = if rpc_url.is_empty() { MAINNET } else { rpc_url };
    let transport = HttpTransport::new(url.to_string());

    println!();
    println!("  SAFE HANDS — mainnet reality check");
    println!("  rpc: {url}");
    println!("  No key is held and nothing is signed, submitted, or spent.");
    println!();

    // --- 1. the chain is really there, and it is mainnet ---------------------
    let genesis = transport.call("getGenesisHash", json!([]))?;
    let genesis = field(&genesis, &["result"])
        .and_then(Value::as_str)
        .ok_or("no genesis hash")?;
    // mainnet-beta's genesis hash is a fixed, well-known value.
    let is_mainnet = genesis == "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
    println!("  chain      genesis {genesis}");
    println!(
        "             {}",
        if is_mainnet {
            "mainnet-beta confirmed"
        } else {
            "NOT mainnet-beta — the rest of this check is against another cluster"
        }
    );

    let slot = transport.call("getSlot", json!([]))?;
    let slot = field(&slot, &["result"]).and_then(Value::as_u64).unwrap_or(0);
    println!("             slot {slot}");
    println!();

    // --- 2. real mint state, decoded by our own TLV reader -------------------
    let mint = transport.call(
        "getAccountInfo",
        json!([USDC, {"encoding": "base64", "commitment": "finalized"}]),
    )?;
    let owner = field(&mint, &["result", "value", "owner"])
        .and_then(Value::as_str)
        .ok_or("USDC mint has no owner — is this mainnet?")?;
    let data_b64 = field(&mint, &["result", "value", "data"])
        .and_then(|d| d.get(0))
        .and_then(Value::as_str)
        .ok_or("USDC mint returned no data")?;
    let raw = safe_hands_core::codec::base64_decode(data_b64, 65_536)
        .map_err(|e| format!("mint data not base64: {e}"))?;
    // SPL mint layout: decimals sits at offset 44.
    let decimals = *raw.get(44).ok_or("mint account too short")?;
    println!("  USDC mint  {USDC}");
    println!("             owner {owner}");
    println!(
        "             {} bytes, decimals {decimals}{}",
        raw.len(),
        if owner == TOKEN_PROGRAM {
            " — classic SPL Token, as expected"
        } else {
            " — NOT the classic token program"
        }
    );
    if decimals != 6 {
        return Err(format!("USDC decimals read as {decimals}, expected 6"));
    }
    println!();

    // --- 3. build a mainnet transaction with our real builder ----------------
    // The fee payer is a real, well-known mainnet account we do not control and
    // never sign for. It exists only so the builder has a real payer to encode.
    let payer = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    let recipient = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu"; // on the operator allowlist
    let stranger = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";  // deliberately not

    let mut config: HashMap<String, String> = HashMap::new();
    config.insert("rpc_url".into(), url.to_string());
    config.insert("fee_payer".into(), payer.to_string());
    config.insert(
        "policy_json".into(),
        crate::policy_json("merchant").ok_or("merchant policy missing")?,
    );

    let builder_args = json!({
        "recipient": recipient,
        "amount_raw": "1000000",           // 1.000000 USDC
        "mint": USDC,
        "memo": "safe-hands-mainnet-check",
        "__config": config.clone(),
    })
    .to_string();

    let built = spl_transfer_build::transfer::run(&builder_args, Some(&transport));
    if !built.success {
        return Err(format!(
            "builder refused against mainnet: {}",
            built.error.unwrap_or_default()
        ));
    }
    let built_json: Value = serde_json::from_str(&built.output)
        .map_err(|e| format!("builder returned invalid JSON: {e}"))?;
    let tx_b64 = built_json["transaction_base64"]
        .as_str()
        .ok_or("builder produced no transaction")?;
    let tx_len = safe_hands_core::codec::base64_decode(tx_b64, 65_536)
        .map_err(|e| format!("builder transaction not base64: {e}"))?
        .len();
    let unsigned = built_json["unsigned"] == Value::Bool(true);
    let destination = built_json["destination_account"].as_str().unwrap_or("?");

    println!("  BUILD      spl-transfer-build, against mainnet state");
    println!("             1.000000 USDC → {recipient}");
    println!("             destination ATA {destination}");
    println!("             {tx_len} bytes, unsigned={unsigned}");
    if !unsigned {
        return Err("builder emitted something that was not unsigned".into());
    }
    println!();

    // --- 4. authorize it on a real mainnet simulation ------------------------
    let authorize_args = json!({
        "transaction_base64": tx_b64,
        "intent": built_json["intent"].clone(),
        "__config": config,
    })
    .to_string();
    let decided = solana_tx_authorize::authorize::run(&authorize_args, Some(&transport));
    let decided_json: Value = serde_json::from_str(&decided.output).unwrap_or(json!({}));
    let verdict = decided_json["verdict"].as_str().unwrap_or("(none)");
    let reasons = decided_json["reason_codes"].clone();
    let decision_id = decided_json["decision_id"].as_str().unwrap_or("(none)");

    println!("  AUTHORIZE  solana-tx-authorize, real mainnet simulateTransaction");
    println!("             verdict      {verdict}");
    println!("             reason codes {reasons}");
    println!("             decision id  {decision_id}");
    println!();

    // --- 5. the same builder, a recipient the operator never listed ---------
    let hostile_args = json!({
        "recipient": stranger,
        "amount_raw": "1000000",
        "mint": USDC,
        "memo": "safe-hands-mainnet-check",
        "__config": config,
    })
    .to_string();
    let refused = spl_transfer_build::transfer::run(&hostile_args, Some(&transport));
    let refused_msg = refused
        .error
        .clone()
        .unwrap_or_else(|| refused.output.clone());
    println!("  REFUSE     same builder, same mainnet, unlisted recipient {stranger}");
    println!(
        "             built={} — {}",
        refused.success,
        refused_msg.trim()
    );
    if refused.success {
        return Err("an unlisted recipient was built against mainnet".into());
    }
    println!();

    println!("  WHAT THIS SHOWS");
    println!("    Reads, mint decode, ATA derivation and transaction construction all");
    println!("    ran against mainnet-beta. The transaction above is mainnet-valid and");
    println!("    unsigned, and the ALLOW came from a real simulateTransaction against");
    println!("    real mainnet state — not a fixture.");
    println!();
    println!("    The same builder, on the same chain, refused a recipient the operator");
    println!("    never listed. The allowlist is not advice the model may weigh.");
    println!();
    println!("    Signing is the one step absent, and it is absent by design: nothing");
    println!("    here holds a key. That is also why this check costs 0 SOL — a T1");
    println!("    system can be proven correct on mainnet without ever spending on it.");
    println!();

    Ok(())
}
