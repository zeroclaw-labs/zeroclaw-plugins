//! ZeroClaw WIT tool plugin: `solana_pay_build` (part of the Aval suite).
//!
//! Turns a charge — a label, an amount, a token — into a Solana Pay transfer
//! request and the reference key that ties the eventual on-chain payment back
//! to that order.
//!
//! Custody tier T0. Nothing here holds a key, signs, or submits, and the plugin
//! is granted no network permission at all: a transfer request is a string and
//! a hash. The customer's own wallet builds and signs the transaction.
//!
//! All logic lives in [`pay`] with no wasm dependency; this file is the
//! `#[cfg(target_family = "wasm")]` shim required by the plugin contract.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod base58;
pub mod pay;

/// The JSON contract the model is held to. Note what is absent: the recipient,
/// the ceiling and the allowlist are not arguments. They are read from the
/// operator's config inside the sandbox, so no message arriving in the shop
/// channel can raise a limit or redirect a payment by supplying a field.
pub fn parameters_schema() -> &'static str {
    r#"{
  "type": "object",
  "required": ["label", "amount", "token"],
  "properties": {
    "label":  {"type": "string", "description": "The order or table this charge belongs to, e.g. \"table-4\"."},
    "amount": {"type": "string", "description": "Amount in whole tokens as a decimal string, e.g. \"25\" or \"25.50\". Never a number — floats cannot represent 25.10 exactly."},
    "token":  {"type": "string", "description": "\"SOL\", or the SPL mint address. Must be on the shop's allowlist."}
  },
  "additionalProperties": false
}"#
}

/// `deny_unknown_fields` closes the argument surface: a prompt-injected model
/// cannot smuggle a `recipient` or a raised `max_amount` past this struct,
/// because those are not arguments — they are read from `__config`, which the
/// host fills from the operator's own config section.
///
/// Host-contract assumption: the host injects only `__config`. wit/v0 is
/// unfrozen, so a newly injected key must be added here explicitly or
/// deserialization will start failing closed.
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PayArgs {
    pub label: String,
    pub amount: String,
    pub token: String,
    #[serde(rename = "__config", default)]
    pub config: std::collections::HashMap<String, String>,
}

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "C:/Users/arche/projects/zeroclaw/wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::pay::{build_payment_request, Charge, ShopConfig};
    use crate::{parameters_schema, PayArgs};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaPayBuild;

    const PLUGIN_NAME: &str = "solana-pay-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_pay_build";

    impl PluginInfo for SolanaPayBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    /// Reads one setting from the plugin's own jailed config section, which the
    /// host injects as `__config`. Missing means refuse: there is no default
    /// recipient and no default ceiling, and inventing either would be the
    /// worst possible fallback in a payments path.
    fn cfg_value(
        section: &std::collections::HashMap<String, String>,
        key: &str,
    ) -> Result<String, String> {
        section
            .get(key)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                format!("shop config is missing {key:?}; set it in this plugin's config section")
            })
    }

    /// Uniqueness for the reference key. Two identical orders in one evening
    /// must not share a reference, or the second payment is indistinguishable
    /// from the first.
    fn salt() -> String {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => format!("{}", d.as_nanos()),
            // Refusing is the only safe branch. A fixed fallback would make
            // every charge in the shop derive the same reference.
            Err(_) => String::new(),
        }
    }

    impl Tool for SolanaPayBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Turn a charge into a Solana Pay transfer request the customer can settle \
             from any wallet, together with the reference key that identifies the \
             payment on-chain. Enforces the shop's token allowlist and per-charge \
             ceiling from the operator's own config; holds no keys and contacts no \
             network. Use this instead of composing a solana: URL by hand."
                .to_string()
        }

        fn parameters_schema() -> String {
            parameters_schema().to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: PayArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid arguments");
                    return Ok(fail(format!("invalid arguments: {e}")));
                }
            };

            let section = &parsed.config;
            let cfg = ShopConfig {
                recipient: match cfg_value(section, "recipient") {
                    Ok(v) => v,
                    Err(e) => return Ok(fail(e)),
                },
                allowed_tokens: cfg_value(section, "allowed_tokens")
                    .unwrap_or_default()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                max_amount: match cfg_value(section, "max_amount") {
                    Ok(v) => v,
                    Err(e) => return Ok(fail(e)),
                },
            };

            let s = salt();
            if s.is_empty() {
                emit(PluginAction::Fail, PluginOutcome::Failure, "no clock");
                return Ok(fail(
                    "refusing to build a charge: no usable clock, so the reference key \
                     could not be made unique to this order"
                        .to_string(),
                ));
            }

            let charge = Charge {
                label: parsed.label,
                amount: parsed.amount,
                token: parsed.token,
            };

            match build_payment_request(&cfg, &charge, &s) {
                Ok(r) => {
                    emit(PluginAction::Complete, PluginOutcome::Success, "request built");
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::json!({
                            "url": r.url,
                            "reference": r.reference,
                            "label": r.label,
                            "amount": r.amount,
                            "token": r.token,
                            "summary": format!(
                                "{} — {} {}. Reference {}.",
                                r.label, r.amount, r.token, r.reference
                            ),
                        })
                        .to_string(),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "refused");
                    Ok(fail(e))
                }
            }
        }
    }

    fn fail(error: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_pay_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaPayBuild);
}
