//! Pure logic for `solana_tx_inspect` — no wasm, no network.

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
    signature: Option<String>,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

pub const NAME: &str = "solana_tx_inspect";
pub const DESCRIPTION: &str = "Inspect one Solana transaction by its base58 signature: slot, block time, \
success/failure status, and fee paid. Read-only — cannot move funds or \
sign. Use when the user pastes a transaction signature or asks whether a \
specific transaction landed.";

pub fn parameters_schema() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {
            "signature": {
                "type": "string",
                "description": "Base58 transaction signature (64-88 chars)."
            }
        },
        "required": ["signature"]
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
    let signature = match validate::require_signature(args.signature.as_deref()) {
        Ok(s) => s.to_string(),
        Err(msg) => return fail(msg),
    };

    let answer = fetch(&cfg.rpc_url, &rpc::get_transaction(&signature))
        .and_then(|body| rpc::extract_result(&body).map(Value::to_owned))
        .and_then(|result| shape::tx_inspect(&signature, &result));

    match answer {
        Ok(out) => (true, out, None),
        Err(e) => fail(rpc::sanitize_error(&cfg.rpc_url, &e)),
    }
}
