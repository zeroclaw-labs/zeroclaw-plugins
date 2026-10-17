//! ZeroClaw `solana_pay_confirm` T0 read-only tool plugin.

#![deny(unsafe_code)]

pub mod confirm;
pub mod rpc;

#[cfg(target_family = "wasm")]
// `wit-bindgen` emits canonical ABI unsafe/export glue. This allowance is
// confined to generated bindings; handwritten code remains under deny.
#[allow(unsafe_code)]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::{
        confirm::{execute_component_input_observed, parameters_schema, ExecutionPhase},
        rpc::WakiTransport,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaPayConfirm;

    const PLUGIN_NAME: &str = "solana-pay-confirm";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_pay_confirm";

    impl PluginInfo for SolanaPayConfirm {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaPayConfirm {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Check whether a Solana Pay request was actually paid. The payment reference \
             is re-derived from the recipient, amount, mint, and invoice id, so this tool \
             can only confirm a payment that was requested with these exact terms; it \
             cannot be pointed at an unrelated payment. Verification reads raw transaction \
             bytes and requires the recipient's balance to have increased by the exact \
             amount. This tool is read-only: it never builds, signs, or submits anything."
                .to_string()
        }

        fn parameters_schema() -> String {
            parameters_schema()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            emit(
                LogLevel::Info,
                PluginAction::Start,
                None,
                "execution started",
            );
            let result = execute_component_input_observed(&args, &WakiTransport, emit_phase);
            if result.success {
                emit(
                    LogLevel::Info,
                    PluginAction::Complete,
                    Some(PluginOutcome::Success),
                    "verification completed",
                );
            } else {
                let message = format!(
                    "refusal category: {}",
                    result.category.unwrap_or("internal_failure")
                );
                emit(
                    LogLevel::Warn,
                    PluginAction::Reject,
                    Some(PluginOutcome::Failure),
                    &message,
                );
            }
            Ok(ToolResult {
                success: result.success,
                output: result.output,
                error: result.error,
            })
        }
    }

    fn emit(level: LogLevel, action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            level,
            &PluginEvent {
                function_name: "solana_pay_confirm::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: Some("{\"custody\":\"T0-read-only\"}".to_string()),
                message: message.to_string(),
            },
        );
    }

    fn emit_phase(phase: ExecutionPhase) {
        let (action, message) = match phase {
            ExecutionPhase::ConfigValidated => (PluginAction::Validate, "config validated"),
            ExecutionPhase::MintRpc => (PluginAction::Query, "mint RPC phase"),
            ExecutionPhase::SignatureScanRpc => (PluginAction::Query, "reference scan RPC phase"),
            ExecutionPhase::TransactionRpc => (PluginAction::Query, "transaction RPC phase"),
            ExecutionPhase::VerificationComplete => {
                (PluginAction::Validate, "verification complete")
            }
        };
        emit(
            LogLevel::Info,
            action,
            Some(PluginOutcome::Success),
            message,
        );
    }

    export!(SolanaPayConfirm);
}
