pub mod check;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::check::{analyze_seller_blob, detect_prompt_injection};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde::Deserialize;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct X402SellerCheck;

    #[derive(Deserialize)]
    struct ExecuteArgs {
        /// Seller code snippet, 402 challenge JSON, or handler text.
        blob: String,
        #[serde(default = "default_locale")]
        locale: String,
    }

    fn default_locale() -> String {
        "en".into()
    }

    impl PluginInfo for X402SellerCheck {
        fn plugin_name() -> String {
            "x402-seller-check".into()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").into()
        }
    }

    impl Tool for X402SellerCheck {
        fn name() -> String {
            "x402_seller_check".into()
        }
        fn description() -> String {
            "T0 heuristic x402 seller security scan (GO/NO-GO). Never settles or signs. \
             Fail-closed on prompt injection. Locale-aware summary."
                .into()
        }
        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "blob": { "type": "string" },
                    "locale": { "type": "string", "default": "en" }
                },
                "required": ["blob"]
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
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };
            if detect_prompt_injection(&parsed.blob) {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Refused: adversarial instruction detected (fail-closed).".into()),
                });
            }
            let report = analyze_seller_blob(&parsed.blob, &parsed.locale);
            log_record(
                LogLevel::Info,
                &PluginEvent {
                    function_name: "x402_seller_check::execute".into(),
                    action: PluginAction::Complete,
                    outcome: Some(PluginOutcome::Success),
                    duration_ms: None,
                    attrs: None,
                    message: "scanned".into(),
                },
            );
            Ok(ToolResult {
                success: true,
                output: serde_json::to_string(&report).unwrap_or(report.summary),
                error: None,
            })
        }
    }

    export!(X402SellerCheck);
}
