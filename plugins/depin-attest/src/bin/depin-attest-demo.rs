//! Palinurus demo driver — attest beat (chunk 6 of the recording guide).
//!
//! `cargo run --features demo --bin depin-attest-demo`
//!
//! Runs the *shipped* `depin-attest` pure core (`execute_t1`) over a real
//! reqwest-backed Rpc against the live devnet durable-nonce account, with a
//! SIMULATED sensor reading. The reading is fake; the Solana side is not:
//! a real `create_attestation` instruction, a real attestation PDA (recomputable
//! by a judge), a real durable nonce as the blockhash, and a real unsigned
//! versioned tx base64 — pastable into the explorer's tx inspector.
//!
//! Config defaults to the devnet artifacts provisioned 2026-07-21 (credential
//! feWL… + nonce 9Kaivz…, authority = shared devnet wallet). All overridable
//! via env. No secrets here — these are devnet pubkeys + a public RPC; the bin
//! does NOT sign (T1 unsigned), so no keypair is needed.
//!
//! Env (all optional — defaults are the recovered devnet config):
//!   RPC_ENDPOINT, RPC_API_KEY, CREDENTIAL_PDA, SCHEMA_PDA, AUTHORITY, PAYER,
//!   NONCE_ACCOUNT, NONCE_AUTHORITY, NETWORK, ATTESTATION_TTL_SECS
//!   SENSOR_ID, SENSOR_VALUE, SENSOR_UNIT  (the simulated reading)
//!
//! The rewards beat (chunks 2-5) is the SEPARATE driver in plugins/depin-rewards
//! (`palinurus-demo`). See the recording guide.

#![cfg(feature = "demo")]

use std::collections::HashMap;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use depin_attest::demo_rpc::ReqwestRpc;
use depin_attest::depin_attest::{execute_t1, AttestConfig, SensorReading};

// ── Recovered devnet config (2026-07-21) — defaults, env-overridable ──
const DEFAULT_RPC_ENDPOINT: &str = "https://api.devnet.solana.com";
const DEFAULT_CREDENTIAL_PDA: &str = "feWLnp6Nb1Gi94jApAK3PQQhK9DkNZqTFjsZfk5sD3t";
const DEFAULT_SCHEMA_PDA: &str = "DKt2LceXM1WLpM36be3FWLSDEFrchvZuxcg2usFMEPnp";
const DEFAULT_AUTHORITY: &str = "FGSkt8MwXH83daNNW8ZkoqhL1KLcLoZLcdGJz84BWWr";
const DEFAULT_PAYER: &str = "FGSkt8MwXH83daNNW8ZkoqhL1KLcLoZLcdGJz84BWWr";
const DEFAULT_NONCE_ACCOUNT: &str = "9Kaivz6TP4u4n6oyat7wA7f48mnRXFBuA1vk79DVDL4u";
const DEFAULT_NONCE_AUTHORITY: &str = "FGSkt8MwXH83daNNW8ZkoqhL1KLcLoZLcdGJz84BWWr";

fn env_or(key: &str, default: &str) -> String {
  env::var(key).unwrap_or_else(|_| default.to_string())
}

fn build_cfg() -> AttestConfig {
  let mut section = HashMap::new();
  section.insert("rpc_endpoint".to_string(), env_or("RPC_ENDPOINT", DEFAULT_RPC_ENDPOINT));
  if let Ok(k) = env::var("RPC_API_KEY") {
    if !k.is_empty() {
      section.insert("rpc_api_key".to_string(), k);
    }
  }
  section.insert("credential_pda".to_string(), env_or("CREDENTIAL_PDA", DEFAULT_CREDENTIAL_PDA));
  section.insert("schema_pda".to_string(), env_or("SCHEMA_PDA", DEFAULT_SCHEMA_PDA));
  section.insert("authority".to_string(), env_or("AUTHORITY", DEFAULT_AUTHORITY));
  section.insert("payer".to_string(), env_or("PAYER", DEFAULT_PAYER));
  section.insert("nonce_account".to_string(), env_or("NONCE_ACCOUNT", DEFAULT_NONCE_ACCOUNT));
  section.insert("nonce_authority".to_string(), env_or("NONCE_AUTHORITY", DEFAULT_NONCE_AUTHORITY));
  section.insert("custody_mode".to_string(), "t1".to_string());
  section.insert("network".to_string(), env_or("NETWORK", "devnet"));
  section.insert("attestation_ttl_secs".to_string(), env_or("ATTESTATION_TTL_SECS", "7776000"));

  AttestConfig::from_section(&section).unwrap_or_else(|e| {
    eprintln!("✗ attest config invalid: {e:?}");
    std::process::exit(2);
  })
}

fn main() {
  let cfg = build_cfg();
  let rpc = ReqwestRpc::new(cfg.rpc_endpoint.clone(), cfg.rpc_api_key.clone());

  // Simulated reading (the demo's only fake part). Defaults mirror the README
  // worked example so the PDA is recognisable; env-overridable for a fresh PDA.
  let reading = SensorReading {
    sensor_id: env_or("SENSOR_ID", "bme280-1"),
    value: env::var("SENSOR_VALUE").ok().and_then(|v| v.parse().ok()).unwrap_or(24.7),
    unit: env_or("SENSOR_UNIT", "celsius"),
    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
  };

  println!("── depin-attest (T1, simulated reading → real Solana tx) ──");
  println!("reading: {} = {} {} @ {}", reading.sensor_id, reading.value, reading.unit, reading.timestamp);
  println!("nonce account: {} (live devnet)", cfg.nonce_account);
  println!();

  match execute_t1(&reading, None, &cfg, &rpc) {
    Ok(out) => {
      println!("{}", out.summary);
      println!();
      println!("attestation PDA : {}", out.attestation_pda);
      println!("explorer        : {}", out.explorer_url);
      println!("tx (unsigned, base64, durable-nonce):");
      // Print the full tx so RECTOR can paste it into the explorer tx inspector.
      println!("  {}", out.tx_b64);
      println!();
      println!("memo fallback used: {}", out.used_memo_fallback);
    }
    Err(e) => {
      eprintln!("✗ execute_t1 failed: {e:?}");
      std::process::exit(1);
    }
  }
}