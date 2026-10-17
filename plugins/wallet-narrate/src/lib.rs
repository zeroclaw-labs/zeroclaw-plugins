pub mod core;

#[cfg(target_family = "wasm")]
mod wasm {
    wit_bindgen::generate!({ path: "../../wit/v0", world: "tool-plugin", features: ["plugins-wit-v0"] });
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};
    use crate::core::{activities_from_rpc, summarize, Activity};
    struct Plugin;
    impl PluginInfo for Plugin {
        fn plugin_name() -> String {
            "wallet-narrate".into()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").into()
        }
    }
    impl Tool for Plugin {
        fn name() -> String {
            "solana-wallet-narrate".into()
        }
        fn description() -> String {
            "Summarize bounded read-only wallet activity with redacted signatures.".into()
        }
        fn parameters_schema() -> String {
            serde_json::json!({"type":"object","additionalProperties":false,"required":["activity"],"properties":{"activity":{"type":"array","maxItems":20}}}).to_string()
        }
        fn execute(args: String) -> Result<ToolResult, String> {
            log_record(LogLevel::Info, &PluginEvent { function_name: "wallet_narrate::tool::execute".into(), action: PluginAction::Start, outcome: None, duration_ms: None, attrs: None, message: "wallet_narrate.request_started".into() });
            let v: serde_json::Value =
                serde_json::from_str(&args).map_err(|_| "Invalid JSON".to_string())?;
            let a: Vec<Activity> = if let Some(rpc) = v.get("rpc_result") {
                activities_from_rpc(rpc).map_err(|e| e.to_string())?
            } else {
                serde_json::from_value(v.get("activity").cloned().ok_or("Missing activity")?)
                    .map_err(|_| "Invalid bounded activity".to_string())?
            };
            let out = summarize(&a, 20);
            log_record(LogLevel::Info, &PluginEvent { function_name: "wallet_narrate::tool::execute".into(), action: PluginAction::Complete, outcome: Some(PluginOutcome::Success), duration_ms: None, attrs: None, message: "wallet_narrate.output_shaped".into() });
            Ok(ToolResult {
                success: true,
                output: serde_json::to_string(&out).unwrap_or_default(),
                error: None,
            })
        }
    }
    export!(Plugin);
}
