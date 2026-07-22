pub mod core;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::core::{build_solana_pay_request, PayRequestArgs, PARAMETERS_SCHEMA};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaPayRequest;

    impl PluginInfo for SolanaPayRequest {
        fn plugin_name() -> String {
            "solana-pay-request".into()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").into()
        }
    }

    impl Tool for SolanaPayRequest {
        fn name() -> String {
            "solana_pay_request".into()
        }
        fn description() -> String {
            "Create a Solana Pay URL and QR-ready payload for an unsigned SPL-token payment. This tool never holds keys, signs, or submits transactions.".into()
        }
        fn parameters_schema() -> String {
            PARAMETERS_SCHEMA.into()
        }
        fn execute(args: String) -> Result<ToolResult, String> {
            log(PluginAction::Start, None, "creating Solana Pay request");
            let request: PayRequestArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return failure(format!("invalid arguments: {error}")),
            };
            let result = match build_solana_pay_request(&request) {
                Ok(value) => value,
                Err(error) => return failure(error.to_string()),
            };
            let output = match serde_json::to_string(&result) {
                Ok(value) => value,
                Err(error) => return failure(format!("failed to serialize request: {error}")),
            };
            log(
                PluginAction::Complete,
                Some(PluginOutcome::Success),
                "created Solana Pay request",
            );
            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn failure(message: String) -> Result<ToolResult, String> {
        log(
            PluginAction::Fail,
            Some(PluginOutcome::Failure),
            "failed to create Solana Pay request",
        );
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        })
    }

    fn log(action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_pay_request::tool::execute".into(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.into(),
            },
        );
    }

    export!(SolanaPayRequest);
}
