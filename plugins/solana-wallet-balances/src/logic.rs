//! Pure logic for `solana_wallet_balances` — no wasm, no network.
//!
//! The wasm shim supplies a `fetch` closure (waki-backed in the component);
//! tests supply a mock. Both drive exactly this code path.

use std::collections::HashMap;

use serde_json::Value;
use solana_lens_core::{config::LensConfig, rpc, shape, validate};

/// The tool's answer: `(success, output, error)` mirroring `tool-result`.
pub type Outcome = (bool, String, Option<String>);

pub fn fail(msg: String) -> Outcome {
    (false, String::new(), Some(msg))
}

#[derive(serde::Deserialize)]
struct Args {
    #[serde(default)]
    address: Option<String>,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

pub const NAME: &str = "solana_wallet_balances";
pub const DESCRIPTION: &str = "Look up what a Solana address holds: SOL balance plus all non-zero SPL \
token balances, in one compact answer. Read-only — cannot move funds, sign, \
or spend. Use when the user asks what a wallet owns or how much SOL/tokens \
an address has.";

pub fn parameters_schema() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Base58 Solana address to look up."
            }
        },
        "required": ["address"]
    })
    .to_string()
}

/// Execute against a fetch closure: `fetch(rpc_url, request_body) -> response_json`.
pub fn run(
    args_json: &str,
    fetch: &dyn Fn(&str, &Value) -> Result<Value, String>,
) -> Outcome {
    let args: Args = match serde_json::from_str(args_json) {
        Ok(a) => a,
        Err(e) => return fail(format!("invalid arguments: {e}")),
    };
    let cfg = LensConfig::from_section(&args.config);
    let address = match validate::require_address(args.address.as_deref()) {
        Ok(a) => a.to_string(),
        Err(msg) => return fail(msg),
    };

    let sol = fetch(&cfg.rpc_url, &rpc::get_balance(&address))
        .and_then(|body| rpc::extract_result(&body).map(Value::to_owned))
        .and_then(|result| shape::balance(&address, &result));
    let sol = match sol {
        Ok(s) => s,
        Err(e) => return fail(rpc::sanitize_error(&cfg.rpc_url, &e)),
    };

    let tokens = fetch(&cfg.rpc_url, &rpc::get_token_accounts(&address))
        .and_then(|body| rpc::extract_result(&body).map(Value::to_owned))
        .and_then(|result| shape::token_balances(&address, &result));
    let tokens = match tokens {
        Ok(t) => t,
        Err(e) => return fail(rpc::sanitize_error(&cfg.rpc_url, &e)),
    };

    (true, format!("{sol}\n{tokens}"), None)
}
