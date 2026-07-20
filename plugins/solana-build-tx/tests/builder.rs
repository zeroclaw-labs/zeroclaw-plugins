//! Integration tests for the `solana-build-tx` builder core, exercised exactly
//! as the wasm `execute` entry point drives it: JSON args, flat config section,
//! and a mockable `RpcClient`. Runs on the host with a plain `cargo test`, no
//! wasm toolchain, no live network.
//!
//! These tests define the public contract the implementer beans satisfy:
//!   j00e (IDL lookup) → 40va (blocked list) → l59k/sj36 (encoding) →
//!   x8rm (unsigned tx) → wa4n (simulate) → mz1r (Layer A + B validation) →
//!   8fhg (summary).
//!
//! Every test currently panics on `todo!()` in `build_transaction`. That is the
//! RED phase. As each implementer bean lands, test groups flip to GREEN.

use std::collections::HashMap;

use base64::Engine;
use serde_json::json;

use solana_build_tx::builder::{
    self, BlockhashInfo, RpcClient, SimulatedAccount, SimulationReport, TokenBalance,
};

// ═══════════════════════════════════════════════════════════════════════════
//  test constants — all addresses are valid base58 decoding to 32 bytes.
//  Generated deterministically from seeds via SHA-256; values are arbitrary.
// ═══════════════════════════════════════════════════════════════════════════

/// The vault / session wallet. Matches `signer_pubkey` in config; is the
/// fee-payer of every unsigned tx build-tx produces.
const SIGNER: &str = "9WZDXwBbmkg8ZTbNMqUxvQRAyrZzDSjDxXfaoFYmBbGX";

const USDC_MINT: &str = "EPjFWcc5VB1U3BdVJU6dQqXxVV7iLPmsZ3jLGqxQzG2d";
const USDT_MINT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
/// A mint NOT in the allowlist — prompt-injection vector 1.
const ATTACKER_MINT: &str = "H337ZMFXsF6BheJtpkhcmqBhswb4sz9gxSqoRDMKNFyc";

const RECIPIENT: &str = "3VQmxaFsFFGnBA1YEHpmSc86EeGZS55hZ2CeHq5Gp4gK";
const ATTACKER: &str = "6cYx9VHGTtreusKzma73oLFATcFdZKTYRLvY4HPRMPak";

const SOURCE_ATA: &str = "6NdciE36apTvhmGNjq6U8BMo7kunnGBpbRVk4hFezWUW";
const DEST_ATA: &str = "5FPWveiYg6HtUkd7eF8fVjQfwHtkMLVWtHJpjB2wTQVu";

const BLOCKHASH: &str = "3pYi6Rdaho6hruTftP9fH798f1wRv332XYzjpboLLTis";
const TRIBUTARY_PROGRAM: &str = "5HaeBhNVwKQyP3wWLnu3riG5QEqMC34hLroSN4hczD8S";
const TRIB_USER_PAYMENT_PDA: &str = "72iPViw8fLospRuzZYWvn567gKuq2T5WwKiCJP2GKTqX";

// ─── minimal IDL JSONs (Anchor 0.30+ shape; discriminator bytes are dummy —
//     the mock RPC returns canned simulation results regardless of encoding) ─

const SPL_TOKEN_IDL: &str = r#"{
  "address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  "name": "spl_token",
  "instructions": [
    { "name": "transfer",
      "discriminator": [3, 1, 2, 3, 4, 5, 6, 7],
      "args": [ {"name": "amount", "type": "u64"} ],
      "accounts": [ {"name": "source"}, {"name": "destination"}, {"name": "authority"} ] },
    { "name": "approve",
      "discriminator": [4, 1, 2, 3, 4, 5, 6, 7],
      "args": [ {"name": "amount", "type": "u64"} ],
      "accounts": [ {"name": "source"}, {"name": "delegate"}, {"name": "owner"} ] },
    { "name": "approve_checked",
      "discriminator": [5, 1, 2, 3, 4, 5, 6, 7],
      "args": [ {"name": "amount", "type": "u64"} ],
      "accounts": [ {"name": "source"}, {"name": "mint"}, {"name": "delegate"}, {"name": "owner"} ] },
    { "name": "set_authority",
      "discriminator": [6, 1, 2, 3, 4, 5, 6, 7],
      "args": [],
      "accounts": [ {"name": "account"}, {"name": "current_authority"} ] },
    { "name": "close_account",
      "discriminator": [7, 1, 2, 3, 4, 5, 6, 7],
      "args": [],
      "accounts": [ {"name": "account"}, {"name": "destination"}, {"name": "owner"} ] }
  ]
}"#;

const SPL_TOKEN_2022_IDL: &str = r#"{
  "address": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
  "name": "spl_token_2022",
  "instructions": [
    { "name": "transfer",
      "discriminator": [3, 1, 2, 3, 4, 5, 6, 7],
      "args": [ {"name": "amount", "type": "u64"} ],
      "accounts": [ {"name": "source"}, {"name": "destination"}, {"name": "owner"} ] },
    { "name": "approve",
      "discriminator": [4, 1, 2, 3, 4, 5, 6, 7],
      "args": [ {"name": "amount", "type": "u64"} ],
      "accounts": [ {"name": "source"}, {"name": "delegate"}, {"name": "owner"} ] },
    { "name": "approve_checked",
      "discriminator": [5, 1, 2, 3, 4, 5, 6, 7],
      "args": [],
      "accounts": [ {"name": "source"}, {"name": "mint"}, {"name": "delegate"}, {"name": "owner"} ] },
    { "name": "set_authority",
      "discriminator": [6, 1, 2, 3, 4, 5, 6, 7],
      "args": [],
      "accounts": [ {"name": "account"}, {"name": "current_authority"} ] },
    { "name": "close_account",
      "discriminator": [7, 1, 2, 3, 4, 5, 6, 7],
      "args": [],
      "accounts": [ {"name": "account"}, {"name": "destination"}, {"name": "owner"} ] }
  ]
}"#;

const TRIBUTARY_IDL: &str = r#"{
  "address": "TriBUtaryProgramAddress11111111111111111111LLLL",
  "name": "tributary",
  "instructions": [
    { "name": "create_subscription",
      "discriminator": [100, 200, 1, 2, 3, 4, 5, 6],
      "args": [
        {"name": "amount", "type": "u64"},
        {"name": "frequency", "type": "u64"}
      ],
      "accounts": [
        {"name": "payer"},
        {"name": "user_payment"}
      ] }
  ]
}"#;

// ═══════════════════════════════════════════════════════════════════════════
//  mock RPC + test helpers
// ═══════════════════════════════════════════════════════════════════════════

/// In-process `RpcClient` that returns a pre-baked `SimulationReport`.
/// No network. Each test constructs the report it needs.
struct MockRpc {
    sim: SimulationReport,
    blockhash: BlockhashInfo,
}

impl RpcClient for MockRpc {
    fn get_latest_blockhash(&self) -> Result<BlockhashInfo, String> {
        Ok(self.blockhash.clone())
    }
    fn simulate_transaction(&self, _tx: &str) -> Result<SimulationReport, String> {
        Ok(self.sim.clone())
    }
}

fn mock(sim: SimulationReport) -> MockRpc {
    MockRpc {
        sim,
        blockhash: BlockhashInfo {
            blockhash: BLOCKHASH.to_string(),
            last_valid_block_height: 200_000,
        },
    }
}

/// Baseline operator config: signer, two mints allowed, 100 USDC cap,
/// registered IDLs. Tests overlay extra pairs as needed.
fn config_with(extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(
        "rpc_url".to_string(),
        "https://api.devnet.solana.com".to_string(),
    );
    m.insert("signer_pubkey".to_string(), SIGNER.to_string());
    m.insert(
        "mint_allowlist".to_string(),
        format!("{USDC_MINT},{USDT_MINT}"),
    );
    m.insert(
        "per_call_outflow_cap".to_string(),
        format!(
            r#"{{"{}":"100000000","{}":"100000000"}}"#,
            USDC_MINT, USDT_MINT
        ),
    );
    m.insert("recipient_allowlist".to_string(), String::new());
    m.insert("expected_delegates_allowlist".to_string(), String::new());
    m.insert("blocked_instructions_extra".to_string(), String::new());
    m.insert(
        format!("idl.{}", builder::SPL_TOKEN_PROGRAM),
        SPL_TOKEN_IDL.to_string(),
    );
    m.insert(
        format!("idl.{}", builder::SPL_TOKEN_2022_PROGRAM),
        SPL_TOKEN_2022_IDL.to_string(),
    );
    for (k, v) in extra {
        m.insert(k.to_string(), v.to_string());
    }
    m
}

/// Compose `parameters_schema`-shaped args JSON.
fn args(program: &str, ix: &str, args_val: serde_json::Value, accts: serde_json::Value) -> String {
    json!({
        "program_id": program,
        "instruction_name": ix,
        "args": args_val,
        "accounts": accts
    })
    .to_string()
}

/// SPL Token transfer accounts (source → destination, authority = signer).
/// Used by every simulation/state-diff test so the encoding step succeeds
/// and the pipeline reaches the simulation where the rejection is exercised.
fn spl_accounts() -> serde_json::Value {
    json!({ "source": SOURCE_ATA, "destination": DEST_ATA, "authority": SIGNER })
}

fn tb(ix: u32, mint: &str, owner: &str, amount: &str) -> TokenBalance {
    TokenBalance {
        account_index: ix,
        mint: mint.to_string(),
        owner: owner.to_string(),
        program_id: builder::SPL_TOKEN_PROGRAM.to_string(),
        amount: amount.to_string(),
    }
}

/// 165-byte SPL Token Account data with optional delegate / close_authority /
/// owner-override set. Tests pass this as `data_base64` in a `SimulatedAccount`.
fn token_account(
    delegate: Option<[u8; 32]>,
    close_authority: Option<[u8; 32]>,
    owner_override: Option<[u8; 32]>,
) -> String {
    let mut data = vec![0u8; 165];
    if let Some(o) = owner_override {
        data[32..64].copy_from_slice(&o);
    }
    if let Some(d) = delegate {
        data[72] = 1; // COption<Pubkey> tag = Some
        data[76..108].copy_from_slice(&d);
    }
    data[108] = 1; // AccountState = Initialized
    if let Some(ca) = close_authority {
        data[129] = 1; // COption<Pubkey> tag = Some
        data[133..165].copy_from_slice(&ca);
    }
    base64::engine::general_purpose::STANDARD.encode(&data)
}

/// A clean, policy-passing simulation: 5 USDC from signer to recipient.
/// USDC outflow = 5_000_000 base units, cap = 100_000_000 → pass.
fn ok_sim_transfer() -> SimulationReport {
    SimulationReport {
        err: None,
        pre_token_balances: vec![
            tb(0, USDC_MINT, SIGNER, "100000000"), // 100 USDC
            tb(1, USDC_MINT, RECIPIENT, "0"),
        ],
        post_token_balances: vec![
            tb(0, USDC_MINT, SIGNER, "95000000"),   // 95 USDC (−5)
            tb(1, USDC_MINT, RECIPIENT, "5000000"), // +5 USDC
        ],
        accounts: vec![],
        units_consumed: 5_000,
        logs: vec!["Program log: Instruction: Transfer".into()],
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  GROUP 1 — happy path
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn spl_transfer_happy_path() {
    let result = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "transfer",
            json!({ "amount": 5_000_000u64 }),
            json!({ "source": SOURCE_ATA, "destination": DEST_ATA, "authority": SIGNER }),
        ),
        &config_with(&[]),
        &mock(ok_sim_transfer()),
    );

    assert!(
        result.success,
        "should succeed: {}",
        result.error.unwrap_or_default()
    );
    assert!(result.error.is_none());

    let out: serde_json::Value = serde_json::from_str(&result.output).unwrap();
    assert!(
        out["instructions_base64"].is_string(),
        "output must carry base64 instructions"
    );
    assert!(
        out["unsigned_tx_base64"].is_string(),
        "output must carry unsigned versioned tx"
    );
    assert!(out["summary"].is_string(), "output must carry summary");
}

#[test]
fn tributary_create_subscription_happy_path() {
    let extra = [(&format!("idl.{}", TRIBUTARY_PROGRAM)[..], TRIBUTARY_IDL)];
    let result = builder::build_transaction(
        &args(
            TRIBUTARY_PROGRAM,
            "create_subscription",
            json!({ "amount": 5_000_000u64, "frequency": 86400u64 }),
            json!({ "payer": SIGNER, "user_payment": TRIB_USER_PAYMENT_PDA }),
        ),
        &config_with(&extra),
        &mock(SimulationReport {
            err: None,
            pre_token_balances: vec![],
            post_token_balances: vec![],
            accounts: vec![],
            units_consumed: 12_000,
            logs: vec!["Program log: Instruction: CreateSubscription".into()],
        }),
    );

    assert!(
        result.success,
        "should succeed: {}",
        result.error.unwrap_or_default()
    );
}

#[test]
fn summary_cites_net_flows_and_amount() {
    let result = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "transfer",
            json!({ "amount": 5_000_000u64 }),
            json!({ "source": SOURCE_ATA, "destination": DEST_ATA, "authority": SIGNER }),
        ),
        &config_with(&[]),
        &mock(ok_sim_transfer()),
    );

    assert!(result.success);
    let out: serde_json::Value = serde_json::from_str(&result.output).unwrap();
    let summary = out["summary"].as_str().unwrap();
    assert!(
        summary.to_ascii_lowercase().contains("transfer"),
        "summary must mention 'transfer': {summary}"
    );
    assert!(
        summary.contains("5") || summary.contains("5.0"),
        "summary must mention the amount: {summary}"
    );
    // ~150-token ceiling: a summary longer than 1200 chars is too verbose.
    assert!(
        summary.chars().count() <= 1200,
        "summary exceeds ~150-token budget: {} chars",
        summary.chars().count()
    );
}

#[test]
fn validation_happy_path_returns_unsigned_tx() {
    let result = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "transfer",
            json!({ "amount": 5_000_000u64 }),
            json!({ "source": SOURCE_ATA, "destination": DEST_ATA, "authority": SIGNER }),
        ),
        &config_with(&[]),
        &mock(ok_sim_transfer()),
    );

    assert!(
        result.success,
        "validation should pass: {}",
        result.error.unwrap_or_default()
    );
    let out: serde_json::Value = serde_json::from_str(&result.output).unwrap();
    let tx_b64 = out["unsigned_tx_base64"].as_str().unwrap();
    // Base64 of a versioned tx is at least 100 chars (message header + accounts
    // + blockhash + instructions). Anything shorter is malformed.
    assert!(
        tx_b64.len() > 100,
        "unsigned_tx_base64 looks malformed: {tx_b64}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  GROUP 2 — IDL lookup
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn idl_lookup_miss_rejects_before_simulation() {
    let unknown = "UnknownProgram1111111111111111111111111111111111";
    let result = builder::build_transaction(
        &args(unknown, "transfer", json!({ "amount": 1u64 }), json!({})),
        &config_with(&[]),
        &mock(ok_sim_transfer()),
    );

    assert!(!result.success);
    let err = result.error.unwrap();
    assert!(
        err.to_ascii_lowercase()
            .contains(builder::err::IDL_NOT_REGISTERED),
        "expected IDL not-registered error, got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  GROUP 3 — HARDCODED blocked-instruction matrix
//
//  Every (program, instruction) in builder::HARDCODED_BLOCKED must be rejected
//  at the IDL stage with `err::BLOCKED_INSTRUCTION`, BEFORE the RPC is touched.
//  The operator cannot remove these via config.
// ═══════════════════════════════════════════════════════════════════════════

/// A sentinel RpcClient that panics on any call — proves the blocked list
/// rejects BEFORE simulation.
struct NoCallRpc;
impl RpcClient for NoCallRpc {
    fn get_latest_blockhash(&self) -> Result<BlockhashInfo, String> {
        panic!("hardcoded-blocked check must fire BEFORE any RPC call")
    }
    fn simulate_transaction(&self, _: &str) -> Result<SimulationReport, String> {
        panic!("hardcoded-blocked check must fire BEFORE any RPC call")
    }
}

#[test]
fn hardcoded_blocked_list_has_eight_entries() {
    // Guard against accidental shrinkage of the baseline.
    assert_eq!(
        builder::HARDCODED_BLOCKED.len(),
        8,
        "baseline must have 4 instructions × 2 programs (see Clarification 1)"
    );
}

#[test]
fn hardcoded_blocked_cannot_be_removed_by_config() {
    // Even with blocked_instructions_extra empty, all 8 must still reject.
    for &(program, ix) in builder::HARDCODED_BLOCKED {
        let result = builder::build_transaction(
            &args(program, ix, json!({ "amount": 1u64 }), json!({})),
            &config_with(&[]),
            &NoCallRpc,
        );
        assert!(!result.success, "{program}:{ix} must be blocked");
        let err = result.error.unwrap();
        assert!(
            err.to_ascii_lowercase()
                .contains(builder::err::BLOCKED_INSTRUCTION),
            "{program}:{ix} should give BLOCKED_INSTRUCTION, got: {err}"
        );
    }
}

#[test]
fn blocked_approve_spl_token() {
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "approve",
            json!({ "amount": 1u64 }),
            json!({}),
        ),
        &config_with(&[]),
        &NoCallRpc,
    );
    assert!(
        !r.success
            && r.error
                .unwrap()
                .to_ascii_lowercase()
                .contains(builder::err::BLOCKED_INSTRUCTION)
    );
}

#[test]
fn blocked_approve_checked_spl_token() {
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "approve_checked",
            json!({ "amount": 1u64 }),
            json!({}),
        ),
        &config_with(&[]),
        &NoCallRpc,
    );
    assert!(
        !r.success
            && r.error
                .unwrap()
                .to_ascii_lowercase()
                .contains(builder::err::BLOCKED_INSTRUCTION)
    );
}

#[test]
fn blocked_set_authority_spl_token() {
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "set_authority",
            json!({}),
            json!({}),
        ),
        &config_with(&[]),
        &NoCallRpc,
    );
    assert!(
        !r.success
            && r.error
                .unwrap()
                .to_ascii_lowercase()
                .contains(builder::err::BLOCKED_INSTRUCTION)
    );
}

#[test]
fn blocked_close_account_spl_token() {
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "close_account",
            json!({}),
            json!({}),
        ),
        &config_with(&[]),
        &NoCallRpc,
    );
    assert!(
        !r.success
            && r.error
                .unwrap()
                .to_ascii_lowercase()
                .contains(builder::err::BLOCKED_INSTRUCTION)
    );
}

#[test]
fn blocked_approve_spl_token_2022() {
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_2022_PROGRAM,
            "approve",
            json!({ "amount": 1u64 }),
            json!({}),
        ),
        &config_with(&[]),
        &NoCallRpc,
    );
    assert!(
        !r.success
            && r.error
                .unwrap()
                .to_ascii_lowercase()
                .contains(builder::err::BLOCKED_INSTRUCTION)
    );
}

#[test]
fn blocked_approve_checked_spl_token_2022() {
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_2022_PROGRAM,
            "approve_checked",
            json!({ "amount": 1u64 }),
            json!({}),
        ),
        &config_with(&[]),
        &NoCallRpc,
    );
    assert!(
        !r.success
            && r.error
                .unwrap()
                .to_ascii_lowercase()
                .contains(builder::err::BLOCKED_INSTRUCTION)
    );
}

#[test]
fn blocked_set_authority_spl_token_2022() {
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_2022_PROGRAM,
            "set_authority",
            json!({}),
            json!({}),
        ),
        &config_with(&[]),
        &NoCallRpc,
    );
    assert!(
        !r.success
            && r.error
                .unwrap()
                .to_ascii_lowercase()
                .contains(builder::err::BLOCKED_INSTRUCTION)
    );
}

#[test]
fn blocked_close_account_spl_token_2022() {
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_2022_PROGRAM,
            "close_account",
            json!({}),
            json!({}),
        ),
        &config_with(&[]),
        &NoCallRpc,
    );
    assert!(
        !r.success
            && r.error
                .unwrap()
                .to_ascii_lowercase()
                .contains(builder::err::BLOCKED_INSTRUCTION)
    );
}

#[test]
fn blocked_instructions_extra_adds_beyond_baseline() {
    // Operator may ADD a program:instruction to the baseline via config.
    let extra = &[(
        "blocked_instructions_extra",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA:transfer",
    )];
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "transfer",
            json!({ "amount": 5_000_000u64 }),
            json!({ "source": SOURCE_ATA, "destination": DEST_ATA, "authority": SIGNER }),
        ),
        &config_with(extra),
        &NoCallRpc,
    );
    assert!(
        !r.success,
        "transfer must reject when operator-added to extra blocklist"
    );
    assert!(r
        .error
        .unwrap()
        .to_ascii_lowercase()
        .contains(builder::err::BLOCKED_INSTRUCTION));
}

// ═══════════════════════════════════════════════════════════════════════════
//  GROUP 4 — simulation-balanced-blocked matrix (Layer A)
// ═══════════════════════════════════════════════════════════════════════════

/// Vector 1 — disallowed mint appears in postTokenBalances.
#[test]
fn simulation_rejects_disallowed_mint() {
    let sim = SimulationReport {
        err: None,
        pre_token_balances: vec![tb(0, ATTACKER_MINT, SIGNER, "1000")],
        post_token_balances: vec![
            tb(0, ATTACKER_MINT, SIGNER, "0"),
            tb(1, ATTACKER_MINT, ATTACKER, "1000"),
        ],
        accounts: vec![],
        units_consumed: 3_000,
        logs: vec![],
    };
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "transfer",
            json!({ "amount": 1000u64 }),
            spl_accounts(),
        ),
        &config_with(&[]),
        &mock(sim),
    );
    assert!(!r.success);
    let err = r.error.unwrap();
    assert!(
        err.to_ascii_lowercase()
            .contains(builder::err::MINT_NOT_ALLOWED),
        "expected MINT_NOT_ALLOWED, got: {err}"
    );
}

/// Vector 2 — signer outflow exceeds per-call cap (1000 USDC vs 100 cap).
#[test]
fn simulation_rejects_cap_exceeded() {
    let sim = SimulationReport {
        err: None,
        pre_token_balances: vec![tb(0, USDC_MINT, SIGNER, "2000000000")],
        post_token_balances: vec![
            tb(0, USDC_MINT, SIGNER, "1000000000"), // −1_000_000_000 = 1000 USDC
            tb(1, USDC_MINT, RECIPIENT, "1000000000"),
        ],
        accounts: vec![],
        units_consumed: 4_000,
        logs: vec![],
    };
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "transfer",
            json!({ "amount": 1000000000u64 }),
            spl_accounts(),
        ),
        &config_with(&[]),
        &mock(sim),
    );
    assert!(!r.success);
    let err = r.error.unwrap();
    assert!(
        err.to_ascii_lowercase()
            .contains(builder::err::OUTFLOW_CAP_EXCEEDED),
        "expected OUTFLOW_CAP_EXCEEDED, got: {err}"
    );
}

/// Vector 3 — inflow to a recipient not in the (non-empty) recipient_allowlist.
#[test]
fn simulation_rejects_disallowed_recipient() {
    let sim = SimulationReport {
        err: None,
        pre_token_balances: vec![tb(0, USDC_MINT, SIGNER, "100000000")],
        post_token_balances: vec![
            tb(0, USDC_MINT, SIGNER, "95000000"),
            tb(1, USDC_MINT, ATTACKER, "5000000"), // ← attacker inflow
        ],
        accounts: vec![],
        units_consumed: 4_000,
        logs: vec![],
    };
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "transfer",
            json!({ "amount": 5000000u64 }),
            spl_accounts(),
        ),
        // restrict recipients to RECIPIENT only
        &config_with(&[("recipient_allowlist", RECIPIENT)]),
        &mock(sim),
    );
    assert!(!r.success);
    let err = r.error.unwrap();
    assert!(
        err.to_ascii_lowercase()
            .contains(builder::err::RECIPIENT_NOT_ALLOWED),
        "expected RECIPIENT_NOT_ALLOWED, got: {err}"
    );
}

/// Vector 4 — simulateTransaction returned an err field → hard reject.
#[test]
fn simulation_rejects_sim_err() {
    let sim = SimulationReport {
        err: Some("InstructionError(0, InsufficientFunds)".into()),
        pre_token_balances: vec![],
        post_token_balances: vec![],
        accounts: vec![],
        units_consumed: 200,
        logs: vec!["Program failed to complete".into()],
    };
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "transfer",
            json!({ "amount": 1u64 }),
            spl_accounts(),
        ),
        &config_with(&[]),
        &mock(sim),
    );
    assert!(!r.success);
    let err = r.error.unwrap();
    assert!(
        err.to_ascii_lowercase()
            .contains(builder::err::SIMULATION_FAILED),
        "expected SIMULATION_FAILED, got: {err}"
    );
}

/// Vector 5 — IDL not registered (same mechanism as idl_lookup_miss but
/// exercised from the simulation-balanced matrix angle).
#[test]
fn simulation_balanced_idl_not_registered() {
    let unknown = "UnknownProgram2222222222222222222222222222222222";
    let r = builder::build_transaction(
        &args(unknown, "transfer", json!({ "amount": 1u64 }), json!({})),
        &config_with(&[]),
        &mock(ok_sim_transfer()),
    );
    assert!(!r.success);
    assert!(r
        .error
        .unwrap()
        .to_ascii_lowercase()
        .contains(builder::err::IDL_NOT_REGISTERED));
}

// ═══════════════════════════════════════════════════════════════════════════
//  GROUP 5 — state-diff-blocked matrix (Layer B)
//
//  Each test constructs a 165-byte SPL Token Account with a specific field
//  mutated, places it as a writable account owned by spl_token in the post-sim
//  accounts list, and asserts the build rejects with the matching error.
// ═══════════════════════════════════════════════════════════════════════════

/// Helper: a writable token account owned by spl_token at SOURCE_ATA with the
/// given delegate / close_authority / owner bytes.
fn writable_token_account(
    pubkey: &str,
    delegate: Option<[u8; 32]>,
    close_authority: Option<[u8; 32]>,
    owner_override: Option<[u8; 32]>,
) -> SimulatedAccount {
    SimulatedAccount {
        pubkey: pubkey.to_string(),
        owner: builder::SPL_TOKEN_PROGRAM.to_string(),
        lamports: 10_000_000,
        data_base64: Some(token_account(delegate, close_authority, owner_override)),
        writable: true,
        executable: false,
        rent_epoch: 0,
    }
}

fn wildcard(a: u8) -> [u8; 32] {
    [a; 32]
}

/// (i) Post-sim token account has unexpected non-null delegate.
#[test]
fn state_diff_rejects_unexpected_delegate() {
    let sim = SimulationReport {
        err: None,
        pre_token_balances: vec![tb(0, USDC_MINT, SIGNER, "95000000")],
        post_token_balances: vec![tb(0, USDC_MINT, SIGNER, "95000000")],
        accounts: vec![writable_token_account(
            SOURCE_ATA,
            Some(wildcard(0xBB)), // ← delegate is non-null
            None,
            None,
        )],
        units_consumed: 4_500,
        logs: vec![],
    };
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "transfer",
            json!({ "amount": 0u64 }),
            spl_accounts(),
        ),
        &config_with(&[]),
        &mock(sim),
    );
    assert!(!r.success);
    let err = r.error.unwrap();
    assert!(
        err.to_ascii_lowercase()
            .contains(builder::err::UNEXPECTED_DELEGATE),
        "expected UNEXPECTED_DELEGATE, got: {err}"
    );
}

/// (ii) Close authority was set on a token account mid-simulation.
#[test]
fn state_diff_rejects_close_authority_change() {
    let sim = SimulationReport {
        err: None,
        pre_token_balances: vec![tb(0, USDC_MINT, SIGNER, "95000000")],
        post_token_balances: vec![tb(0, USDC_MINT, SIGNER, "95000000")],
        accounts: vec![writable_token_account(
            SOURCE_ATA,
            None,
            Some(wildcard(0xCC)), // ← close_authority set
            None,
        )],
        units_consumed: 4_500,
        logs: vec![],
    };
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "transfer",
            json!({ "amount": 0u64 }),
            spl_accounts(),
        ),
        &config_with(&[]),
        &mock(sim),
    );
    assert!(!r.success);
    let err = r.error.unwrap();
    assert!(
        err.to_ascii_lowercase()
            .contains(builder::err::CLOSE_AUTHORITY_CHANGED),
        "expected CLOSE_AUTHORITY_CHANGED, got: {err}"
    );
}

/// (iii) Token account owner (wallet) changed mid-simulation.
#[test]
fn state_diff_rejects_owner_change() {
    let sim = SimulationReport {
        err: None,
        pre_token_balances: vec![tb(0, USDC_MINT, SIGNER, "95000000")],
        post_token_balances: vec![tb(0, USDC_MINT, SIGNER, "95000000")],
        accounts: vec![writable_token_account(
            SOURCE_ATA,
            None,
            None,
            Some(wildcard(0xDD)), // ← owner field overridden
        )],
        units_consumed: 4_500,
        logs: vec![],
    };
    let r = builder::build_transaction(
        &args(
            builder::SPL_TOKEN_PROGRAM,
            "transfer",
            json!({ "amount": 0u64 }),
            spl_accounts(),
        ),
        &config_with(&[]),
        &mock(sim),
    );
    assert!(!r.success);
    let err = r.error.unwrap();
    assert!(
        err.to_ascii_lowercase()
            .contains(builder::err::OWNER_CHANGED),
        "expected OWNER_CHANGED, got: {err}"
    );
}

/// Hidden-CPI-approve scenario from Clarification 1 — the top-level
/// instruction looks valid (tributary::execute_payment), but the simulation
/// reveals a delegate set by a CPI the program did internally. Must reject at
/// Layer B with reason `unexpected delegate: <pubkey>`.
#[test]
fn hidden_cpi_approve_is_caught_at_layer_b() {
    let tributary_idl = [(&format!("idl.{}", TRIBUTARY_PROGRAM)[..], TRIBUTARY_IDL)];
    let delegate_bytes = wildcard(0xEE); // arbitrary attacker-as-delegate
    let sim = SimulationReport {
        err: None,
        pre_token_balances: vec![tb(0, USDC_MINT, SIGNER, "5000000")],
        post_token_balances: vec![tb(0, USDC_MINT, SIGNER, "5000000")],
        accounts: vec![writable_token_account(
            SOURCE_ATA,
            Some(delegate_bytes),
            None,
            None,
        )],
        units_consumed: 20_000,
        logs: vec![
            "Program log: Instruction: ExecutePayment".into(),
            "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]".into(),
            "Program log: Instruction: Approve".into(),
        ],
    };
    let r = builder::build_transaction(
        &args(
            TRIBUTARY_PROGRAM,
            "create_subscription",
            json!({ "amount": 5_000_000u64, "frequency": 86400u64 }),
            json!({ "payer": SIGNER, "user_payment": TRIB_USER_PAYMENT_PDA }),
        ),
        &config_with(&tributary_idl),
        &mock(sim),
    );
    assert!(!r.success, "hidden-CPI approve must be caught");
    let err = r.error.unwrap();
    assert!(
        err.to_ascii_lowercase()
            .contains(builder::err::UNEXPECTED_DELEGATE),
        "expected UNEXPECTED_DELEGATE from hidden CPI, got: {err}"
    );
}
