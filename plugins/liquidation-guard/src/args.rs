//! Pure parser from the `execute` argument JSON string to a typed
//! [`ParsedCall`]. No I/O, no wasm dependency: compiles and tests on the
//! host.
//!
//! Deny-unknown-fields at the top level. This is also what structurally
//! rejects any model-supplied network-endpoint argument (`rpc_url` or
//! otherwise): the allowed field set never includes one, so it always falls
//! through as an unknown field. RPC endpoints come only from config.

use std::collections::HashMap;

use serde_json::Value;

use crate::config::{validate_base58_32, Config};

/// Which guard operation the tool call requests.
#[derive(Debug)]
pub enum Action {
    Check,
    Portfolio,
    Rescue,
    Deposit,
}

/// A parsed, validated tool call: the seven execute-args fields plus the
/// [`Config`] resolved from `__config`.
#[derive(Debug)]
pub struct ParsedCall {
    pub action: Action,
    pub wallet: Option<String>,
    pub market: Option<String>,
    pub obligation: Option<String>,
    pub repay_ui_amount: Option<f64>,
    pub deposit_ui_amount: Option<f64>,
    pub prev_snapshot: Option<String>,
    pub config: Config,
}

const ALLOWED_FIELDS: [&str; 8] = [
    "action",
    "wallet",
    "market",
    "obligation",
    "repay_ui_amount",
    "deposit_ui_amount",
    "prev_snapshot",
    "__config",
];

/// Parse and validate the execute-args JSON into a [`ParsedCall`].
pub fn parse_call(raw_json: &str) -> Result<ParsedCall, String> {
    let value: Value = serde_json::from_str(raw_json)
        .map_err(|_| "invalid arguments: not valid JSON".to_string())?;
    let obj = value
        .as_object()
        .ok_or_else(|| "invalid arguments: expected a JSON object".to_string())?;

    for key in obj.keys() {
        if !ALLOWED_FIELDS.contains(&key.as_str()) {
            return Err(format!("unknown argument field '{key}'"));
        }
    }

    let action = match obj.get("action").and_then(Value::as_str) {
        Some("check") => Action::Check,
        Some("portfolio") => Action::Portfolio,
        Some("rescue") => Action::Rescue,
        Some("deposit") => Action::Deposit,
        Some(_) => return Err("invalid value for 'action'".to_string()),
        None => return Err("missing required field 'action'".to_string()),
    };

    let wallet = optional_base58(obj, "wallet")?;
    let market = optional_base58(obj, "market")?;
    let obligation = optional_base58(obj, "obligation")?;

    let repay_ui_amount = optional_positive_f64(obj, "repay_ui_amount")?;
    let deposit_ui_amount = optional_positive_f64(obj, "deposit_ui_amount")?;

    let prev_snapshot = match obj.get("prev_snapshot") {
        Some(Value::Null) | None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err("invalid value for 'prev_snapshot'".to_string()),
    };

    let config_map: HashMap<String, String> = match obj.get("__config") {
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|_| "invalid value for '__config'".to_string())?,
        None => HashMap::new(),
    };
    let config = Config::from_map(&config_map)?;

    Ok(ParsedCall {
        action,
        wallet,
        market,
        obligation,
        repay_ui_amount,
        deposit_ui_amount,
        prev_snapshot,
        config,
    })
}

/// Shared validation for `repay_ui_amount`/`deposit_ui_amount`: absent or
/// null -> `None`, else must be a finite positive number.
fn optional_positive_f64(
    obj: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<f64>, String> {
    match obj.get(key) {
        Some(Value::Null) | None => Ok(None),
        Some(v) => {
            let n = v
                .as_f64()
                .ok_or_else(|| format!("invalid value for '{key}'"))?;
            if !(n.is_finite() && n > 0.0) {
                return Err(format!("invalid value for '{key}': must be finite and > 0"));
            }
            Ok(Some(n))
        }
    }
}

fn optional_base58(
    obj: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match obj.get(key) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::String(s)) => {
            validate_base58_32(s).map_err(|()| {
                format!("invalid value for '{key}': not a valid base58 32-byte pubkey")
            })?;
            Ok(Some(s.clone()))
        }
        Some(_) => Err(format!("invalid value for '{key}'")),
    }
}
