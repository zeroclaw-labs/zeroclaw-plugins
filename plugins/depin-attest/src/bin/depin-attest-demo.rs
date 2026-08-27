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
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use depin_attest::demo_rpc::{load_session_key_b58, ReqwestRpc};
use depin_attest::depin_attest::{execute_t1, execute_t2, AttestConfig, DailyCapState, SensorReading};

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
  let mode = env_or("ATTEST_MODE", "t1");
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
  section.insert("custody_mode".to_string(), mode.clone());
  section.insert("network".to_string(), env_or("NETWORK", "devnet"));
  section.insert("attestation_ttl_secs".to_string(), env_or("ATTESTATION_TTL_SECS", "7776000"));
  // memo_fallback (T1/T2): use the memo program instead of SAS. The README's
  // documented default path (cheap, high-throughput). SAS needs an on-chain
  // schema (the 0x4 TODO); memo fallback sidesteps it and still lands a real
  // on-chain attestation via the full custody path.
  if env_or("ATTEST_MEMO_FALLBACK", "false") == "true" {
    section.insert("memo_fallback".to_string(), "true".to_string());
  }

  // T2: load the scoped session key from a Solana keypair file (the operator's
  // existing CLI keypair). The identity guard requires verifying_key ==
  // authority == payer == nonce_authority, so for the devnet demo the session
  // key IS the shared devnet wallet (FGSk…BWWr) — that's the one key, wearing
  // all four hats. Real deployments derive a separate scoped session key.
  if mode == "t2" {
    let keyfile = env::var("ATTEST_SESSION_KEYFILE").unwrap_or_else(|_| {
      eprintln!("✗ ATTEST_MODE=t2 requires ATTEST_SESSION_KEYFILE (path to a Solana keypair JSON)");
      std::process::exit(2);
    });
    let session_key_b58 = load_session_key_b58(Path::new(&keyfile)).unwrap_or_else(|e| {
      eprintln!("✗ failed to load session key from {keyfile}: {e}");
      std::process::exit(2);
    });
    section.insert("session_key".to_string(), session_key_b58);
  }

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

  let mode = env_or("ATTEST_MODE", "t1");
  println!("── depin-attest ({mode}, simulated reading → real Solana tx) ──");
  println!("reading: {} = {} {} @ {}", reading.sensor_id, reading.value, reading.unit, reading.timestamp);
  println!("nonce account: {} (live devnet)", cfg.nonce_account);
  if mode == "t2" {
    println!("custody: T2 — session key = authority/payer/nonce_authority (identity guard), program allowlist {{System, SAS, Memo}}, caps enforced");
  }
  println!();

  match mode.as_str() {
    "t1" => match execute_t1(&reading, None, &cfg, &rpc) {
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
    },
    "t2" => {
      // T2: the scoped session key signs + submits. Custody guards (identity,
      // program allowlist, lamport cap, daily cap) are enforced BEFORE signing.
      let mut cap = DailyCapState { last_day: 0, count: 0 };
      match execute_t2(&reading, None, &cfg, &rpc, &mut cap) {
        Ok(out) => {
          println!("{}", out.summary);
          println!();
          println!("attestation PDA : {}", out.attestation_pda);
          println!("signature       : {}", out.signature.as_deref().unwrap_or("?"));
          println!("explorer        : {}", out.explorer_url);
          println!();
          println!("✅ real on-chain attestation — open the explorer link to verify.");
        }
        Err(e) => {
          eprintln!("✗ execute_t2 failed: {e:?}");
          std::process::exit(1);
        }
      }
    }
    other => {
      eprintln!("✗ unknown ATTEST_MODE '{other}' — expected 't1' or 't2'");
      std::process::exit(2);
    }
  }
}