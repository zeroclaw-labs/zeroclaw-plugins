//! ZeroClaw `spl_transfer_build` T1-build tool plugin.

#![deny(unsafe_code)]

pub mod rpc;
pub mod transfer;

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
        rpc::WakiTransport,
        transfer::{execute_component_input_observed, parameters_schema, ExecutionPhase},
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SplTransferBuild;

    const PLUGIN_NAME: &str = "spl-transfer-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "spl_transfer_build";

    impl PluginInfo for SplTransferBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SplTransferBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build, decode, verify, and simulate an unsigned version-0 SPL token transfer. \
             The sender, RPC endpoint, mint allowlist, recipient policy, and amount caps \
             come only from operator configuration. This tool never signs or submits."
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
                    "verification and simulation passed",
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
                function_name: "spl_transfer_build::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: Some("{\"custody\":\"T1-build\"}".to_string()),
                message: message.to_string(),
            },
        );
    }

    fn emit_phase(phase: ExecutionPhase) {
        let (action, message) = match phase {
            ExecutionPhase::ConfigValidated => (PluginAction::Validate, "config validated"),
            ExecutionPhase::MintRpc
            | ExecutionPhase::BlockhashRpc
            | ExecutionPhase::NonceRpc => (PluginAction::Query, "RPC phase"),
            ExecutionPhase::TransactionBuilt => (PluginAction::Complete, "transaction built"),
            ExecutionPhase::VerificationPassed => (PluginAction::Validate, "verification passed"),
            ExecutionPhase::SimulationRpc => (PluginAction::Query, "RPC simulation phase"),
            ExecutionPhase::SimulationPassed => (PluginAction::Validate, "simulation passed"),
        };
        emit(
            LogLevel::Info,
            action,
            Some(PluginOutcome::Success),
            message,
        );
    }

    export!(SplTransferBuild);
}
