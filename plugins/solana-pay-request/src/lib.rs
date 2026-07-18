//! ZeroClaw `solana_pay_request` tool plugin.
//!
//! All request construction and validation lives in [`pay_request`] so host
//! tests exercise the same logic as the WASM component. The component shim is
//! deliberately limited to WIT conversion and structured host logging.

#![deny(unsafe_code)]

pub mod pay_request;

#[cfg(target_family = "wasm")]
// `wit-bindgen` emits the canonical ABI's unsafe/export glue. The allowance is
// confined to generated bindings; all handwritten modules remain under the
// crate-level deny.
#[allow(unsafe_code)]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::pay_request::{execute_component_input, parameters_schema};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaPayRequest;

    const PLUGIN_NAME: &str = "solana-pay-request";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_pay_request";

    impl PluginInfo for SolanaPayRequest {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaPayRequest {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Create a deterministic Solana Pay transfer-request URL and QR payload. \
             This tool never sends funds, signs transactions, reads private keys, or \
             uses the network. Operator config can define mint aliases and lock the \
             accepted recipients."
                .to_string()
        }

        fn parameters_schema() -> String {
            parameters_schema()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let result = execute_component_input(&args);
            emit(result.success);
            Ok(ToolResult {
                success: result.success,
                output: result.output,
                error: result.error,
            })
        }
    }

    fn emit(success: bool) {
        let (level, action, outcome, message) = if success {
            (
                LogLevel::Info,
                PluginAction::Complete,
                PluginOutcome::Success,
                "created Solana Pay request",
            )
        } else {
            (
                LogLevel::Warn,
                PluginAction::Reject,
                PluginOutcome::Failure,
                "refused Solana Pay request",
            )
        };
        log_record(
            level,
            &PluginEvent {
                function_name: "solana_pay_request::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: Some("{\"network\":false,\"custody\":false}".to_string()),
                message: message.to_string(),
            },
        );
    }

    export!(SolanaPayRequest);
}
