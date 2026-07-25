pub mod core;

#[cfg(target_family = "wasm")]
mod wasm {
    wit_bindgen::generate!({ path: "../../wit/v0", world: "tool-plugin", features: ["plugins-wit-v0"] });
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use crate::core::{assess, state_from_rpc, StakeState};
    struct Plugin;
    impl PluginInfo for Plugin {
        fn plugin_name() -> String {
            "stake-monitor".into()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").into()
        }
    }
    impl Tool for Plugin {
        fn name() -> String {
            "solana-stake-monitor".into()
        }
        fn description() -> String {
            "Report read-only stake activation and delegation health.".into()
        }
        fn parameters_schema() -> String {
            serde_json::json!({"type":"object","additionalProperties":false,"required":["stake"],"properties":{"stake":{"type":"object"}}}).to_string()
        }
        fn execute(args: String) -> Result<ToolResult, String> {
            let v: serde_json::Value =
                serde_json::from_str(&args).map_err(|_| "Invalid JSON".to_string())?;
            let s: StakeState = if let Some(rpc) = v.get("rpc_result") {
                state_from_rpc(rpc).map_err(|e| e.to_string())?
            } else {
                serde_json::from_value(v.get("stake").cloned().ok_or("Missing stake")?)
                    .map_err(|_| "Invalid stake state".to_string())?
            };
            Ok(ToolResult {
                success: true,
                output: serde_json::to_string(&assess(&s)).unwrap_or_default(),
                error: None,
            })
        }
    }
    export!(Plugin);
}
