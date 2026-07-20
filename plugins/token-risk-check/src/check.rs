//! End-to-end check pipeline, transport-injected and fully host-testable.
//!
//! Everything the wasm shim does besides I/O construction lives here, so
//! `cargo test` can drive the entire pipeline — argument validation included —
//! against a mocked RPC.

use std::collections::HashMap;

use crate::holders;
use crate::mint;
use crate::report::{render, ReportInput};
use crate::risk;
use crate::rpc::{RpcClient, Transport};

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
pub const DEFAULT_COMMITMENT: &str = "confirmed";

/// Operator configuration, resolved from the plugin's jailed `__config`
/// section. An empty map must produce safe, working behavior — that is what
/// an unconfigured install and a `config_read`-less manifest both see.
pub struct CheckConfig {
    pub rpc_url: String,
    pub commitment: String,
}

impl CheckConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let rpc_url = section
            .get("rpc_url")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && s.starts_with("https://"))
            .unwrap_or(DEFAULT_RPC_URL)
            .to_string();
        let commitment = match section.get("commitment").map(String::as_str) {
            Some("processed") => "processed",
            Some("finalized") => "finalized",
            // Anything else — including absent or garbage — pins the default.
            _ => DEFAULT_COMMITMENT,
        }
        .to_string();
        Self {
            rpc_url,
            commitment,
        }
    }
}

/// Validate a claimed mint address. This is the injection choke point: the
/// model controls this string, so nothing that fails base58-to-32-bytes may
/// reach the RPC layer.
pub fn validate_mint(raw: &str) -> Result<String, String> {
    let candidate = raw.trim();
    if candidate.is_empty() {
        return Err("mint address is empty".to_string());
    }
    if candidate.len() > 64 {
        return Err("mint address is too long to be a Solana address".to_string());
    }
    let bytes = bs58::decode(candidate)
        .into_vec()
        .map_err(|_| "not a valid base58 Solana address".to_string())?;
    if bytes.len() != 32 {
        return Err(format!(
            "decoded to {} bytes, a Solana address must be 32",
            bytes.len()
        ));
    }
    Ok(candidate.to_string())
}

/// Run the full check. All failures return `Err(user-facing message)`; the
/// shim maps them to `success: false` tool results (a normal model-visible
/// outcome), never to a plugin fault.
pub fn run_check(
    transport: &dyn Transport,
    raw_mint: &str,
    commitment: &str,
) -> Result<String, String> {
    let mint_addr = validate_mint(raw_mint)?;
    let rpc = RpcClient::new(transport);

    let account = rpc
        .get_account_info(&mint_addr, commitment)?
        .ok_or("no account exists at this address on the configured cluster (wrong network, or not created yet)")?;
    let slot = account.slot;
    let facts = mint::mint_facts(&account)?;

    // Concentration is best-effort: several public RPCs disable
    // getTokenLargestAccounts. Degrade to a flagged unknown, never fail.
    let conc = rpc
        .get_token_largest_accounts(&mint_addr, commitment)
        .ok()
        .and_then(|accounts| holders::concentration(&accounts, facts.supply));

    let verdict = risk::assess(&facts, conc.as_ref());
    Ok(render(&ReportInput {
        mint: &mint_addr,
        facts: &facts,
        concentration: conc.as_ref(),
        verdict: &verdict,
        slot,
    }))
}
