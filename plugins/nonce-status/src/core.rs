//! Pure core of the `nonce-status` tool: fetch and explain the operator's
//! durable nonce account. One RPC call, read-only, shaped for a chat window.
//!
//! Why this exists: `spl-transfer-build` in durable-nonce mode depends on a
//! healthy nonce account. When a build fails, the operator's first question
//! is "what state is my nonce account in?", and this tool answers it without
//! leaving the chat: current nonce value, authority, rent balance, and
//! whether transfer-build can use it right now.

use std::collections::BTreeMap;

use serde::Deserialize;
use solana_core_wasi::nonce::{parse_nonce_account, NonceError, NONCE_RENT_LAMPORTS};
use solana_core_wasi::pubkey::Pubkey;
use solana_core_wasi::rpc;

/// Tool arguments. The nonce account comes from operator config by default;
/// an explicit argument may name a different account to inspect (read-only,
/// so this is safe).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Args {
    /// Optional base58 nonce account to inspect. Defaults to the operator's
    /// configured `nonce_account`.
    #[serde(default)]
    pub account: Option<String>,
    /// Host-injected operator config (rpc_url, nonce_account).
    #[serde(rename = "__config", default)]
    pub config: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StatusError {
    BadArgs(String),
    Config(String),
    Rpc(String),
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatusError::BadArgs(e) => write!(f, "bad arguments: {e}"),
            StatusError::Config(e) => write!(f, "config error: {e}"),
            StatusError::Rpc(e) => write!(f, "rpc error: {e}"),
        }
    }
}

const KNOWN_KEYS: &[&str] = &["rpc_url", "nonce_account"];

pub trait Lookups {
    fn rpc(&mut self, body: &str) -> Result<String, String>;
}

/// Run the status check.
pub fn status(args: &Args, lookups: &mut dyn Lookups) -> Result<String, StatusError> {
    for k in args.config.keys() {
        if !KNOWN_KEYS.contains(&k.as_str()) {
            return Err(StatusError::Config(format!(
                "unknown config key '{k}', refusing to guess (fail closed)"
            )));
        }
    }
    let rpc_url = args
        .config
        .get("rpc_url")
        .ok_or_else(|| StatusError::Config("rpc_url is required".into()))?;
    if !rpc_url.starts_with("https://") {
        return Err(StatusError::Config(
            "rpc_url must be an https:// endpoint".into(),
        ));
    }

    let account_str = args
        .account
        .clone()
        .or_else(|| args.config.get("nonce_account").cloned())
        .ok_or_else(|| {
            StatusError::Config(
                "no nonce account: pass `account` or set nonce_account in config. To create one: \
                 solana-keygen new -o nonce.json && solana create-nonce-account nonce.json 0.0015"
                    .into(),
            )
        })?;
    let account = Pubkey::parse(account_str.trim())
        .map_err(|e| StatusError::BadArgs(format!("nonce account: {e}")))?;

    let raw = lookups
        .rpc(&rpc::get_account_info(&account))
        .map_err(StatusError::Rpc)?;
    let (data, owner) = match rpc::parse_account_info(&raw) {
        Ok(x) => x,
        Err(rpc::RpcError::AccountNotFound) => {
            return Ok(format!(
                "MISSING: nonce account {account} does not exist. Create it once with: \
                 solana-keygen new -o nonce.json && solana create-nonce-account nonce.json 0.0015 \
                 (rent {} lamports), then set nonce_account in this plugin's config.",
                NONCE_RENT_LAMPORTS
            ))
        }
        Err(e) => return Err(StatusError::Rpc(e.to_string())),
    };

    if owner.0 != [0u8; 32] {
        return Ok(format!(
            "NOT A NONCE ACCOUNT: {account} is owned by {owner}, not the system program. \
             transfer-build cannot use it."
        ));
    }

    match parse_nonce_account(&data) {
        Ok(state) => Ok(format!(
            "READY: nonce account {account}, authority {}, current nonce {}…, \
             fee {} lamports/sig. transfer-build transactions built against it stay valid \
             until the nonce advances (i.e. until one of them lands).",
            state.authority,
            bs58_short(&state.durable_nonce),
            state.lamports_per_signature
        )),
        Err(NonceError::Uninitialized) => Ok(format!(
            "UNINITIALIZED: {account} exists but was never initialized as a nonce. \
             Run: solana create-nonce-account against a fresh keypair instead."
        )),
        Err(e) => Ok(format!(
            "UNUSABLE: {account}, {e}. transfer-build will refuse it."
        )),
    }
}

fn bs58_short(bytes: &[u8; 32]) -> String {
    let full = Pubkey(*bytes).to_base58();
    full[..full.len().min(12)].to_string()
}

/// Entry point the shim calls.
pub fn run(raw_args: &str, lookups: &mut dyn Lookups) -> Result<String, StatusError> {
    let args: Args =
        serde_json::from_str(raw_args).map_err(|e| StatusError::BadArgs(e.to_string()))?;
    let line = status(&args, lookups)?;
    let ready = line.starts_with("READY");
    Ok(serde_json::json!({ "ready": ready, "summary": line }).to_string())
}
