pub mod pay;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::pay::{build_pay_request, detect_prompt_injection, PayRequestInput};
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
            "T1: build a Solana Pay transfer URL/QR payload. Agent proposes; human wallet pays. Never signs."
                .into()
        }
        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": { "type": "string" },
                    "amount": { "type": "string" },
                    "spl_token": { "type": "string" },
                    "memo": { "type": "string" },
                    "label": { "type": "string" },
                    "message": { "type": "string" },
                    "locale": { "type": "string", "default": "en" }
                },
                "required": ["recipient", "amount"]
            })
            .to_string()
        }
        fn execute(args: String) -> Result<ToolResult, String> {
            if detect_prompt_injection(&args) {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Refused: adversarial instruction detected (fail-closed).".into()),
                });
            }
            let input: PayRequestInput = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };
            match build_pay_request(&input) {
                Ok(out) => {
                    log_record(
                        LogLevel::Info,
                        &PluginEvent {
                            function_name: "solana_pay_request::execute".into(),
                            action: PluginAction::Complete,
                            outcome: Some(PluginOutcome::Success),
                            duration_ms: None,
                            attrs: None,
                            message: "built".into(),
                        },
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::to_string(&out).unwrap_or(out.human_summary),
                        error: None,
                    })
                }
                Err(e) => Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(e),
                }),
            }
        }
    }

    export!(SolanaPayRequest);
}
