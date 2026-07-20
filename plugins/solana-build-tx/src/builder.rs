//! Pure transaction-build core. No wit-bindgen or wasm dependency so it
//! compiles and tests on the host with a plain `cargo test`, while the wasm
//! component in `lib.rs` reuses the exact same logic through its shim.
//!
//! # Custody tier
//! T1 — this plugin never sees a private key. It produces an unsigned tx and
//! a human-readable summary; the T2 signer (`solana-keychain-sign`) owns the
//! signature step.
//!
//! # Validation model (see milestone HANDOFF "Rewritten scope")
//! Two layers compose, both must pass before the unsigned tx is returned:
//! - **Layer A — balance diff**: simulateTransaction with
//!   `replaceRecentBlockhash=true`; diff pre/post token balances. Every
//!   touched mint must be in `mint_allowlist`; net outflow per mint from
//!   `signer_pubkey` must be ≤ `per_call_outflow_cap`; any inflow account
//!   not in `recipient_allowlist` (if non-empty) is rejected.
//! - **Layer B — token account state diff**: decode writable SPL/Token-2022
//!   accounts from `sim.accounts`; reject if any `delegate` is set and not
//!   in `expected_delegates_allowlist`, or if `close_authority` / `owner`
//!   changed.
//!
//! # Hardcoded blocked instructions (v0 baseline, see Clarification 1)
//! The `approve` family is blocked at the IDL-lookup stage, before encoding
//! or simulation. Operators may ADD to this list via
//! `blocked_instructions_extra`; they cannot remove entries.
//!
//!   spl_token / spl_token_2022 ×
//!     { approve, approve_checked, set_authority, close_account }
//!
//! Why: a single `transfer` is bounded by the tx amount and the per-call cap.
//! An `approve(attacker, u64::MAX)` hands away transfer authority for the
//! entire token account — every cap the plugin enforces becomes meaningless.

use std::collections::HashMap;

// ─── public types ───────────────────────────────────────────────────────────

/// Result mirroring the WIT `tool-result` shape so the wasm shim can pass it
/// through without reshaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildResult {
    pub success: bool,
    /// JSON-encoded `{ instructions_base64, unsigned_tx_base64, summary }`
    /// on success; empty on failure.
    pub output: String,
    pub error: Option<String>,
}

/// Mockable RPC boundary. Host tests inject an in-process impl that returns
/// canned `simulateTransaction` / `getLatestBlockhash` responses; the wasm
/// shim wires this to `waki` HTTP (bean zeroclaw-solana-bounty-wa4n).
pub trait RpcClient {
    /// `getLatestBlockhash` → `{ value: { blockhash, lastValidBlockHeight } }`
    fn get_latest_blockhash(&self) -> Result<BlockhashInfo, String>;

    /// `simulateTransaction` with `replaceRecentBlockhash=true`,
    /// `accounts.encoding=base64`. The implementer of bean wa4n maps the raw
    /// JSON-RPC response into this struct.
    fn simulate_transaction(&self, unsigned_tx_base64: &str) -> Result<SimulationReport, String>;

    /// `getTokenAccountsByOwner` — pre-build delegate check. Default returns
    /// empty vec (no pre-check); the wasm waki impl overrides this.
    fn get_token_accounts_by_owner(
        &self,
        _pubkey: &str,
        _program_id: &str,
    ) -> Result<Vec<crate::rpc::TokenAccountInfo>, String> {
        Ok(Vec::new())
    }
}

/// Fresh blockhash + its validity window.
#[derive(Debug, Clone)]
pub struct BlockhashInfo {
    /// Base58 blockhash.
    pub blockhash: String,
    pub last_valid_block_height: u64,
}

/// Normalized simulateTransaction output. Implementer of bean mz1r reads this.
#[derive(Debug, Clone, Default)]
pub struct SimulationReport {
    /// Hard-reject if non-empty (Layer A precondition).
    pub err: Option<String>,
    pub pre_token_balances: Vec<TokenBalance>,
    pub post_token_balances: Vec<TokenBalance>,
    /// Writable accounts from `value.accounts`, base64 data for SPL-owned.
    pub accounts: Vec<SimulatedAccount>,
    pub units_consumed: u64,
    pub logs: Vec<String>,
}

/// One row of `preTokenBalances` / `postTokenBalances`.
#[derive(Debug, Clone)]
pub struct TokenBalance {
    /// Index into `message.accountKeys`.
    pub account_index: u32,
    pub mint: String,
    pub owner: String,
    /// Token program that owns the account (spl_token / spl_token_2022).
    pub program_id: String,
    /// Raw u128 amount as a decimal string (JSON-RPC delivers string).
    pub amount: String,
}

/// One writable account from `value.accounts`.
#[derive(Debug, Clone)]
pub struct SimulatedAccount {
    pub pubkey: String,
    /// Owning program (e.g. spl_token, spl_token_2022, system).
    pub owner: String,
    pub lamports: u64,
    /// Base64-encoded account data; `None` if not requested or empty.
    pub data_base64: Option<String>,
    pub writable: bool,
    pub executable: bool,
    pub rent_epoch: u64,
}

// ─── re-exports from policy (constants live in their proper home) ──────────

pub use crate::policy::{HARDCODED_BLOCKED, SPL_TOKEN_2022_PROGRAM, SPL_TOKEN_PROGRAM};

/// Stable error strings the tests and the README transcript rely on. Keep
/// these literals exactly — the prompt-injection transcript quotes them.
pub mod err {
    pub const IDL_NOT_REGISTERED: &str = "program id not registered";
    pub const BLOCKED_INSTRUCTION: &str = "blocked instruction";
    pub const SIMULATION_FAILED: &str = "simulation failed";
    pub const MINT_NOT_ALLOWED: &str = "mint not in allowlist";
    pub const OUTFLOW_CAP_EXCEEDED: &str = "outflow exceeds per-call cap";
    pub const RECIPIENT_NOT_ALLOWED: &str = "recipient not in allowlist";
    pub const UNEXPECTED_DELEGATE: &str = "unexpected delegate";
    pub const CLOSE_AUTHORITY_CHANGED: &str = "close_authority changed";
    pub const OWNER_CHANGED: &str = "owner changed";
}

// ─── entry point ────────────────────────────────────────────────────────────

/// Build an unsigned Solana transaction from Anchor IDL metadata and enforce
/// operator policy via simulation.
///
/// `args_json` matches the tool `parameters_schema`: `{"program_id",
/// "instruction_name", "args", "accounts", "lookup_tables"?}`.
/// `config` is this plugin's flat `__config` section — see `BuildConfig`
/// keys in the milestone HANDOFF.
///
/// Implementer beans (in execution order):
/// 1. `j00e` — IDL lookup by `program_id`; miss → `err::IDL_NOT_REGISTERED`.
/// 2. `40va` — hardcoded blocked list + `blocked_instructions_extra`; hit →
///    `err::BLOCKED_INSTRUCTION`.
/// 3. `l59k` / `sj36` — encode Anchor discriminator + borsh args.
/// 4. `x8rm` — fetch fresh blockhash via `rpc`, assemble unsigned versioned tx.
/// 5. `wa4n` — `simulateTransaction` via `rpc`; `err` → `err::SIMULATION_FAILED`.
/// 6. `mz1r` — Layer A (balance diff) + Layer B (token-account state diff).
/// 7. `8fhg` — ~150-token summary citing net flows + CU.
pub fn build_transaction(
    args_json: &str,
    config: &HashMap<String, String>,
    rpc: &dyn RpcClient,
) -> BuildResult {
    // 1. Parse args.
    let args: serde_json::Value = match serde_json::from_str(args_json) {
        Ok(v) => v,
        Err(e) => return reject(&format!("invalid args: {e}")),
    };
    let program_id = match args.get("program_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return reject("missing program_id"),
    };
    let instruction_name = match args.get("instruction_name").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return reject("missing instruction_name"),
    };
    let ix_args = args.get("args").cloned().unwrap_or(serde_json::Value::Null);
    let ix_accounts = args
        .get("accounts")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // 2. Parse config → policy + IDL registry.
    let policy = crate::policy::PolicyConfig::from_section(config);
    let registry = crate::idl::IdlRegistry::from_section(config);

    // 3. IDL lookup + blocked-list check.
    let ix_ref = match registry.lookup(program_id, instruction_name, &policy) {
        Ok(ix) => ix,
        Err(crate::idl::IdlError::ProgramNotRegistered) => {
            return reject(&format!(
                "{}: program {program_id}",
                err::IDL_NOT_REGISTERED
            ));
        }
        Err(crate::idl::IdlError::InstructionBlocked) => {
            return reject(&format!(
                "{}: {program_id}:{instruction_name}",
                err::BLOCKED_INSTRUCTION
            ));
        }
        Err(crate::idl::IdlError::InstructionNotFound) => {
            return reject(&format!(
                "{}: {program_id}:{instruction_name}",
                err::BLOCKED_INSTRUCTION
            ));
        }
    };

    // 4. Encode instruction (borsh args + account resolution).
    let encoded_ix = match crate::encoding::encode_instruction(&ix_ref, &ix_args, &ix_accounts) {
        Ok(ix) => ix,
        Err(e) => return reject(&format!("encoding error: {e}")),
    };

    // 5. Fetch fresh blockhash.
    let blockhash = match rpc.get_latest_blockhash() {
        Ok(bh) => bh,
        Err(e) => return reject(&format!("blockhash fetch failed: {e}")),
    };

    // 6. Assemble unsigned V0 versioned tx.
    let unsigned_tx_b64 = match crate::encoding::assemble_unsigned_tx_b64(
        std::slice::from_ref(&encoded_ix),
        &policy.signer_pubkey,
        &blockhash.blockhash,
    ) {
        Ok(tx) => tx,
        Err(e) => return reject(&format!("tx assembly failed: {e}")),
    };

    // 7. Simulate.
    let sim = match rpc.simulate_transaction(&unsigned_tx_b64) {
        Ok(r) => r,
        Err(e) => return reject(&format!("simulation rpc error: {e}")),
    };

    // 8. Layer A + Layer B validation.
    let vr = crate::validation::validate(&sim, &policy);
    if !vr.passed {
        return BuildResult {
            success: false,
            output: String::new(),
            error: vr.error,
        };
    }

    // 9. Render summary.
    let summary = crate::summary::render_summary(&sim, &policy, &ix_ref.name);

    // 10. Return.
    let instructions_b64 = crate::encoding::base64_encode(&encoded_ix.data);
    let output = serde_json::json!({
        "instructions_base64": instructions_b64,
        "unsigned_tx_base64": unsigned_tx_b64,
        "summary": summary,
    })
    .to_string();

    BuildResult {
        success: true,
        output,
        error: None,
    }
}

fn reject(msg: &str) -> BuildResult {
    BuildResult {
        success: false,
        output: String::new(),
        error: Some(msg.to_string()),
    }
}
