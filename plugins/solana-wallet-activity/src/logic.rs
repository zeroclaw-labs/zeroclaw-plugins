//! Pure logic for `solana_wallet_activity` — no wasm, no network.

use std::collections::HashMap;

use serde_json::Value;
use solana_lens_core::{config::LensConfig, rpc, shape, validate};

pub type Outcome = (bool, String, Option<String>);

pub fn fail(msg: String) -> Outcome {
    (false, String::new(), Some(msg))
}

#[derive(serde::Deserialize)]
struct Args {
    #[serde(default)]
    address: Option<String>,
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

fn default_limit() -> u32 {
    50
}

pub const NAME: &str = "solana_wallet_activity";
pub const DESCRIPTION: &str = "Generate a compact activity report for a Solana address from its recent \
transaction history: time window, active days, cadence (tx/day), failure \
rate with a behavioral interpretation, and the latest transactions. One RPC \
call. Read-only — cannot move funds or sign. Use when the user asks what a \
wallet has been doing, whether it looks like a bot, or how active it is.";

pub fn parameters_schema() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Base58 Solana address to analyze."
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 50,
                "description": "How many recent transactions to analyze (default 50 = best signal)."
            }
        },
        "required": ["address"]
    })
    .to_string()
}

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

    let report = fetch(&cfg.rpc_url, &rpc::get_signatures(&address, args.limit))
        .and_then(|body| rpc::extract_result(&body).map(Value::to_owned))
        .and_then(|result| shape::activity_report(&address, &result));

    match report {
        Ok(out) => (true, out, None),
        Err(e) => fail(rpc::sanitize_error(&cfg.rpc_url, &e)),
    }
}
