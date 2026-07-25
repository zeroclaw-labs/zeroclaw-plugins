pub mod core;

#[cfg(target_family = "wasm")]
mod wasm {
    wit_bindgen::generate!({ path: "../../wit/v0", world: "tool-plugin", features: ["plugins-wit-v0"] });
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use crate::core::{assess, signals_from_mint_account, TokenSignals};
    struct Plugin;
    impl PluginInfo for Plugin {
        fn plugin_name() -> String {
            "token-risk-check".into()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").into()
        }
    }
    impl Tool for Plugin {
        fn name() -> String {
            "solana-token-risk-check".into()
        }
        fn description() -> String {
            "Assess read-only token risk signals; never signs, transfers, or trades.".into()
        }
        fn parameters_schema() -> String {
            serde_json::json!({"type":"object","additionalProperties":false,"properties":{"signals":{"type":"object"},"account_info":{"type":"object"}}}).to_string()
        }
        fn execute(args: String) -> Result<ToolResult, String> {
            let v: serde_json::Value =
                serde_json::from_str(&args).map_err(|_| "Invalid JSON".to_string())?;
            let s: TokenSignals = if let Some(account) = v.get("account_info") {
                signals_from_mint_account(account).map_err(|e| e.to_string())?
            } else {
                serde_json::from_value(v.get("signals").cloned().ok_or("Missing signals")?)
                    .map_err(|_| "Invalid bounded signals".to_string())?
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
