pub mod narrate;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::narrate::{detect_prompt_injection, narrate, ProofInput};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SettlementProofNarrate;

    impl PluginInfo for SettlementProofNarrate {
        fn plugin_name() -> String {
            "settlement-proof-narrate".into()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").into()
        }
    }

    impl Tool for SettlementProofNarrate {
        fn name() -> String {
            "settlement_proof_narrate".into()
        }
        fn description() -> String {
            "T0: turn settlement/Merkle proof JSON into one short chat sentence (en/fr/pt/es…). Never signs."
                .into()
        }
        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "fixture_id": { "type": "string" },
                    "outcome": { "type": "string" },
                    "valid": { "type": "boolean" },
                    "merkle_root": { "type": "string" },
                    "program_id": { "type": "string" },
                    "locale": { "type": "string", "default": "en" }
                }
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
            let input: ProofInput = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };
            let out = narrate(&input);
            log_record(
                LogLevel::Info,
                &PluginEvent {
                    function_name: "settlement_proof_narrate::execute".into(),
                    action: PluginAction::Complete,
                    outcome: Some(PluginOutcome::Success),
                    duration_ms: None,
                    attrs: None,
                    message: "narrated".into(),
                },
            );
            Ok(ToolResult {
                success: true,
                output: serde_json::to_string(&out).unwrap_or(out.text),
                error: None,
            })
        }
    }

    export!(SettlementProofNarrate);
}
