//! A ZeroClaw WIT tool plugin: `sns_resolve`.
//!
//! Resolves a Solana Name Service `.sol` domain to its owner's wallet address:
//! it derives the domain's on-chain name account (a program-derived address over
//! the SPL Name Service program) and reads the owner out of that account. This
//! makes `pay bonfida.sol` human-readable — feed the owner into `solana-pay-request`.
//!
//! Read-only (T0): no key, no signing. Fails closed — an unresolvable or
//! unregistered domain returns an error, never a wrong or blank address.
//!
//! The derivation + parsing core lives in [`sns`] (host-testable, golden-vector
//! verified live on mainnet); the RPC substrate in [`rpc`]. Build:
//!   rustup target add wasm32-wasip2 && cargo build --target wasm32-wasip2 --release

pub mod rpc;
pub mod sns;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::json;

    use crate::rpc;
    use crate::sns::{domain_account, normalize, owner_from_data};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SnsResolve;

    const PLUGIN_NAME: &str = "sns-resolve";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "sns_resolve";
    /// base58 of 32 zero bytes — the "no owner" sentinel.
    const DEFAULT_PUBKEY: &str = "11111111111111111111111111111111";

    #[derive(serde::Deserialize)]
    struct Args {
        domain: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SnsResolve {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SnsResolve {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Resolve a Solana Name Service .sol domain (e.g. \"bonfida.sol\") to its owner's \
             wallet address, by deriving and reading the domain's on-chain name account. \
             Read-only; use it to turn a human name into an address to pay or inspect. Fails \
             closed: an unregistered or unresolvable domain returns an error, never a wrong address."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "A .sol domain, with or without the .sol suffix (e.g. \"bonfida\" or \"bonfida.sol\"). Subdomains are not yet supported."
                    }
                },
                "required": ["domain"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: Args = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let label = match normalize(&parsed.domain) {
                Ok(l) => l,
                Err(e) => return reject(e),
            };
            let account = match domain_account(&label) {
                Ok(a) => a,
                Err(e) => return reject(e),
            };

            let url = rpc::rpc_url(&parsed.config);
            let resp = match rpc::call(
                &url,
                "getAccountInfo",
                json!([account, {"encoding": "base64"}]),
            ) {
                Ok(v) => v,
                Err(e) => return fail_rpc(e),
            };
            let result = match rpc::result(&resp) {
                Ok(r) => r,
                Err(e) => return fail_rpc(e),
            };

            let value = &result["value"];
            if value.is_null() {
                return reject(format!("domain \"{label}.sol\" is not registered"));
            }
            let data_b64 = value
                .pointer("/data/0")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let bytes = match STANDARD.decode(data_b64) {
                Ok(b) => b,
                Err(e) => return fail_rpc(format!("could not decode account data: {e}")),
            };
            let owner = match owner_from_data(&bytes) {
                Ok(o) => o,
                Err(e) => return reject(e),
            };
            if owner == DEFAULT_PUBKEY {
                return reject(format!(
                    "domain \"{label}.sol\" has no owner set (unregistered or expired)"
                ));
            }

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "resolved domain",
            );
            Ok(ToolResult {
                success: true,
                output: json!({
                    "domain": format!("{label}.sol"),
                    "name_account": account,
                    "owner": owner,
                })
                .to_string(),
                error: None,
            })
        }
    }

    fn reject(msg: String) -> Result<ToolResult, String> {
        emit(PluginAction::Reject, PluginOutcome::Failure, "rejected");
        Ok(ToolResult {
            success: false,
            output: msg,
            error: None,
        })
    }

    fn fail_rpc(msg: String) -> Result<ToolResult, String> {
        emit(PluginAction::Fail, PluginOutcome::Failure, "rpc error");
        Ok(ToolResult {
            success: false,
            output: msg,
            error: None,
        })
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "sns_resolve::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SnsResolve);
}
