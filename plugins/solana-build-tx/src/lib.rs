//! A ZeroClaw WIT tool plugin: `solana-build-tx`.
//!
//! T1 custody tier. Builds Solana transactions from an Anchor IDL and validates
//! them via `simulateTransaction` before returning an unsigned versioned tx.
//! No signing, no key material, no network submission — that is the T2 signer's
//! job. The pure build core lives in [`builder`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod builder;
pub mod encoding;
pub mod idl;
pub mod policy;
pub mod rpc;
pub mod summary;
pub mod validation;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::builder::{self, build_transaction, RpcClient};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaBuildTx;

    const PLUGIN_NAME: &str = "solana-build-tx";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana-build-tx";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        #[serde(flatten)]
        build_args: serde_json::Value,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    /// Wasm-side RPC adapter. wired to `waki` HTTP by the RPC-client bean
    /// (zeroclaw-solana-bounty-wa4n). Until then the wasm component cannot
    /// build live; host tests inject a mock `RpcClient` directly.
    struct WasmRpc {
        rpc_url: String,
    }

    impl RpcClient for WasmRpc {
        fn get_latest_blockhash(&self) -> Result<builder::BlockhashInfo, String> {
            todo!(
                "bean wa4n: waki POST getLatestBlockhash -> {}",
                self.rpc_url
            )
        }
        fn simulate_transaction(
            &self,
            unsigned_tx_base64: &str,
        ) -> Result<builder::SimulationReport, String> {
            let _ = unsigned_tx_base64;
            todo!(
                "bean wa4n: waki POST simulateTransaction -> {}",
                self.rpc_url
            )
        }
    }

    impl PluginInfo for SolanaBuildTx {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaBuildTx {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build a Solana transaction from a registered Anchor IDL. Validates the \
             transaction via simulateTransaction before returning it unsigned. No \
             signing — pair with solana-keychain-sign for T2 custody."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "program_id": {
                        "type": "string",
                        "description": "Base58 Solana program ID (must be registered in config IDL list)."
                    },
                    "instruction_name": {
                        "type": "string",
                        "description": "Anchor instruction name, e.g. \"transfer\"."
                    },
                    "args": {
                        "type": "object",
                        "description": "Instruction arguments as JSON matching the IDL."
                    },
                    "accounts": {
                        "type": "object",
                        "description": "Named account addresses matching the IDL."
                    },
                    "lookup_tables": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional address lookup table addresses."
                    }
                },
                "required": ["program_id", "instruction_name", "args", "accounts"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
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

            let args_json = serde_json::to_string(&parsed.build_args).unwrap_or_default();
            let rpc_url = parsed.config.get("rpc_url").cloned().unwrap_or_default();
            let rpc = WasmRpc { rpc_url };
            let result = build_transaction(&args_json, &parsed.config, &rpc);

            let (action, outcome) = if result.success {
                (PluginAction::Complete, PluginOutcome::Success)
            } else {
                (PluginAction::Reject, PluginOutcome::Failure)
            };
            emit(
                action,
                outcome,
                if result.success { "built" } else { "rejected" },
            );

            Ok(ToolResult {
                success: result.success,
                output: result.output,
                error: result.error,
            })
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_build_tx::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaBuildTx);
}
