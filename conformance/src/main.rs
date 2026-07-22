//! prove-safety: the Safe Hands public conformance runner.
//!
//! Loads every YAML fixture in conformance/fixtures/, builds the transaction
//! it describes, runs it through the REAL plugin entry points (authorize /
//! propose) with mocked transports, and asserts the verdict + reason codes.
//! Offline, deterministic, no wasm toolchain required.
//!
//! Exit code 0 = every fixture passed. Judges: `cargo run -p conformance`.

use safe_hands_core::codec::base64_encode;
use safe_hands_core::crypto::parse_pubkey;
use safe_hands_core::ix;
use safe_hands_core::rpc::{DownTransport, MockTransport, RpcTransport};
use safe_hands_core::{bincode, solana_hash::Hash, solana_message::Message, solana_pubkey::Pubkey};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;

// --- key registry (fixed, deterministic) -----------------------------------

const RECIP: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
const PAYER: &str = "5Z6Ay5NEcbg3xhopc522sBCRXQujkTiuDRnHGfQdcnSf";
const ATTACKER: &str = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const CREATE_KEY: &str = "J2xccRtuG43drESLYznHhLhQkLTdfepcKYbiQ9BsJVaf";
const PROPOSER: &str = "5Z6Ay5NEcbg3xhopc522sBCRXQujkTiuDRnHGfQdcnSf";

fn key(name: &str) -> Pubkey {
    let s = match name {
        "RECIP" => RECIP,
        "PAYER" => PAYER,
        "ATTACKER" => ATTACKER,
        "USDC" => USDC,
        "CREATE_KEY" => CREATE_KEY,
        "PROPOSER" => PROPOSER,
        other => other, // raw base58 allowed
    };
    parse_pubkey(s).unwrap_or_else(|e| panic!("bad key {name}: {e}"))
}

// --- fixture schema ---------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    #[serde(default)]
    policy: String, // "merchant" | "empty" | "malformed"
    #[serde(default)]
    intent: Option<Value>,
    #[serde(default)]
    tx: TxSpec,
    #[serde(default)]
    simulation: String, // "ok" | "fail" | "down"
    #[serde(default)]
    decision_record: Option<Value>,
    #[serde(default)]
    via: String, // "authorize" | "propose"
    expect: Expect,
}

#[derive(Debug, Default, Deserialize)]
struct TxSpec {
    #[serde(default)]
    kind: String, // "sol" | "spl" | "raw_base64" | "none"
    #[serde(default)]
    mint: Option<String>,
    #[serde(default)]
    amount: u64,
    #[serde(default)]
    recipient: String,
    #[serde(default)]
    memo: Option<String>,
    #[serde(default)]
    extra_transfer: Option<(String, u64)>, // (recipient_key, amount) hidden 2nd transfer
    #[serde(default)]
    unknown_program: bool,
    #[serde(default)]
    unknown_instruction: bool,
    #[serde(default)]
    authority_op: Option<String>, // "assign" | "approve"
    #[serde(default)]
    durable_nonce: bool,
    #[serde(default)]
    signed: bool,
    #[serde(default)]
    raw_base64: String,
}

#[derive(Debug, Deserialize)]
struct Expect {
    verdict: String, // ALLOW | REVIEW | DENY | UNKNOWN | ERROR
    #[serde(default)]
    reason_codes: Vec<String>, // subset match
}

// --- policy personas --------------------------------------------------------

fn policy_json(name: &str) -> Option<String> {
    match name {
        "merchant" => Some(format!(
            r#"{{"version":"1.0.0","default_action":"deny",
            "assets":{{"SOL":{{"decimals":9,"max_per_tx_raw":"2000000000"}},"{USDC}":{{"decimals":6,"max_per_tx_raw":"25000000"}}}},
            "allowed_recipients":["{RECIP}"],
            "allowed_instructions":{{"system":["transfer","advance_nonce"],"spl_token":["transfer","transfer_checked"],"associated_token":["create_idempotent"],"memo":["memo"],"squads":["squads_ix"]}},
            "unknown_program":"deny","unknown_instruction":"deny","missing_intent":"review","durable_nonce":"review",
            "token_2022":{{"permanent_delegate":"deny","transfer_hook":"review","transfer_fee":"review","default_frozen":"deny"}},
            "simulation":{{"required":true,"max_slot_age":32}}}}"#
        )),
        _ => None,
    }
}

// --- tx construction ---------------------------------------------------------

fn build_tx(spec: &TxSpec) -> Vec<u8> {
    if spec.kind == "raw_base64" {
        return safe_hands_core::codec::base64_decode(&spec.raw_base64, 4096)
            .unwrap_or_else(|e| panic!("fixture raw_base64 invalid: {e}"));
    }
    if spec.kind == "none" {
        return b"not-a-transaction".to_vec();
    }
    let payer = key("PAYER");
    let mut ixs = Vec::new();

    if spec.durable_nonce {
        ixs.push(ix::advance_nonce(&key("RECIP"), &payer));
    }
    match spec.kind.as_str() {
        "sol" => ixs.push(ix::system_transfer(
            &payer,
            &key(&spec.recipient),
            spec.amount,
        )),
        "spl" => {
            let mint = key(spec.mint.as_deref().unwrap_or("USDC"));
            let tp = ix::spl_token_program();
            let dest_ata = safe_hands_core::crypto::ata_address(&key(&spec.recipient), &tp, &mint);
            let src_ata = safe_hands_core::crypto::ata_address(&payer, &tp, &mint);
            ixs.push(ix::ata_create_idempotent(
                &payer,
                &dest_ata,
                &key(&spec.recipient),
                &mint,
                &tp,
            ));
            ixs.push(ix::transfer_checked(
                &tp,
                &src_ata,
                &mint,
                &dest_ata,
                &payer,
                spec.amount,
                6,
            ));
        }
        _ => {}
    }
    if let Some((recip, amt)) = &spec.extra_transfer {
        ixs.push(ix::system_transfer(&payer, &key(recip), *amt));
    }
    if spec.unknown_program {
        ixs.push(safe_hands_core::solana_instruction::Instruction {
            program_id: Pubkey::new_from_array([0xabu8; 32]),
            accounts: vec![],
            data: vec![1, 2, 3],
        });
    }
    if spec.unknown_instruction {
        ixs.push(safe_hands_core::solana_instruction::Instruction {
            program_id: Pubkey::default(), // system program, garbage discriminator
            accounts: vec![],
            data: vec![99, 99, 99, 99],
        });
    }
    match spec.authority_op.as_deref() {
        Some("assign") => ixs.push(ix::system_assign(&payer, &key("ATTACKER").to_string())),
        Some("approve") => ixs.push(ix::token_approve(
            &payer,
            &key("ATTACKER"),
            &payer,
            u64::MAX,
        )),
        _ => {}
    }
    if let Some(memo) = &spec.memo {
        ixs.push(ix::memo(memo));
    }

    let mut msg = Message::new(&ixs, Some(&payer));
    msg.recent_blockhash = Hash::new_from_array([7u8; 32]);
    let mut bytes = bincode::serialize(&msg).expect("serialize");
    if spec.signed {
        let mut wrapped = vec![1u8];
        wrapped.extend_from_slice(&[0xaau8; 64]); // a REAL signature present
        wrapped.extend_from_slice(&bytes);
        bytes = wrapped;
    }
    bytes
}

// --- transports --------------------------------------------------------------

fn transport_for(simulation: &str) -> Box<dyn RpcTransport> {
    match simulation {
        "down" => Box::new(DownTransport),
        // A real node always returns a context.slot even when the tx errors;
        // include it so the mock matches the JSON-RPC shape simulate() parses.
        "fail" => Box::new(MockTransport::new().with(
            "simulateTransaction",
            json!({"result": {"context": {"slot": 100}, "value": {"err": "InstructionError", "logs": []}}}),
        )),
        // Healthy transport: simulation succeeds with a fresh slot. Mirrors the
        // contract asserted by the authorize unit tests — simulateTransaction
        // carries context.slot and getSlot reports the current (equal) slot, so
        // the freshness gate (max_slot_age) passes deterministically offline.
        _ => Box::new(MockTransport::new()
            .with(
                "simulateTransaction",
                json!({"result": {"context": {"slot": 100}, "value": {"err": null, "logs": []}}}),
            )
            .with("getSlot", json!({"result": 100}))
            .with(
                "getAccountInfo",
                json!({"result": {"value": {"owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "data": ["", "base64"]}}}),
            )
            .with(
                "getLatestBlockhash",
                json!({"result": {"value": {"blockhash": "4uQeVj5tqViQh7yWWGStvkEG1RgHJueU8ysKX7pF1i5u"}}}),
            )),
    }
}

// --- execution ----------------------------------------------------------------

/// Resolve symbolic key names (RECIP, ATTACKER, USDC…) inside a JSON value so
/// fixtures can declare intents/readables with names while the engine sees
/// real base58 keys.
fn resolve_keys(v: &Value) -> Value {
    match v {
        Value::String(s) => {
            if matches!(
                s.as_str(),
                "RECIP" | "PAYER" | "ATTACKER" | "USDC" | "CREATE_KEY" | "PROPOSER"
            ) {
                Value::String(key(s).to_string())
            } else {
                v.clone()
            }
        }
        Value::Array(a) => Value::Array(a.iter().map(resolve_keys).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| (k.clone(), resolve_keys(x)))
                .collect(),
        ),
        _ => v.clone(),
    }
}

fn run_fixture(fx: &Fixture) -> Result<(), String> {
    let mut config: HashMap<String, String> = HashMap::new();
    match fx.policy.as_str() {
        "empty" => {}
        "malformed" => {
            config.insert("policy_json".into(), "{not json".into());
        }
        _ => {
            config.insert("rpc_url".into(), "https://rpc.test".into());
            config.insert("policy_json".into(), policy_json(&fx.policy).unwrap());
            if fx.via == "propose" {
                config.insert("squads_create_key".into(), CREATE_KEY.into());
                config.insert("proposer".into(), PROPOSER.into());
            }
        }
    }

    let tx_bytes = build_tx(&fx.tx);
    let tx_b64 = base64_encode(&tx_bytes);
    let transport = transport_for(&fx.simulation);

    let args = json!({
        "transaction_base64": tx_b64,
        "intent": fx.intent.as_ref().map(resolve_keys),
        "decision_record": fx.decision_record,
        "__config": config,
    })
    .to_string();

    let (success, output, error) = if fx.via == "propose" {
        let out = squads_proposal_build::propose::run(&args, Some(transport.as_ref()));
        (out.success, out.output, out.error)
    } else {
        let out = solana_tx_authorize::authorize::run(&args, Some(transport.as_ref()));
        (out.success, out.output, out.error)
    };

    // Map result to a verdict string.
    let verdict = if fx.via == "propose" && !success {
        "ERROR".to_string()
    } else {
        let v: Value = serde_json::from_str(&output)
            .map_err(|e| format!("unparseable output: {e}: {output}"))?;
        v["verdict"].as_str().unwrap_or("").to_string()
    };

    if verdict != fx.expect.verdict {
        return Err(format!(
            "expected {}, got {} (error: {:?})",
            fx.expect.verdict, verdict, error
        ));
    }
    if !fx.expect.reason_codes.is_empty() {
        let v: Value = serde_json::from_str(&output).unwrap_or(json!({}));
        let codes: Vec<String> = v["reason_codes"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        let haystack = format!("{} {}", codes.join(" "), error.unwrap_or_default());
        for want in &fx.expect.reason_codes {
            if !haystack.contains(want.as_str()) {
                return Err(format!("missing reason code {want} in [{haystack}]"));
            }
        }
    }
    Ok(())
}

fn main() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let mut fixtures: Vec<Fixture> = Vec::new();
    let mut paths: Vec<_> = fs::read_dir(&dir)
        .expect("fixtures dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "yaml").unwrap_or(false))
        .collect();
    paths.sort();
    for p in &paths {
        let text = fs::read_to_string(p).expect("read fixture");
        fixtures
            .push(serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("bad yaml {p:?}: {e}")));
    }

    println!(
        "Safe Hands conformance suite — {} fixtures\n",
        fixtures.len()
    );
    let mut passed = 0;
    let mut failed = 0;
    for fx in &fixtures {
        match run_fixture(fx) {
            Ok(()) => {
                println!("  PASS  {}", fx.name);
                passed += 1;
            }
            Err(e) => {
                println!("  FAIL  {} — {e}", fx.name);
                failed += 1;
            }
        }
    }
    println!("\n{passed} passed, {failed} failed");
    if failed > 0 {
        std::process::exit(1);
    }
    println!("All fixtures green — the guard holds.");
}
