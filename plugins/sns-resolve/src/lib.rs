//! ZeroClaw WIT tool plugin: `sns-resolve`.
//!
//! Resolves .sol / ANS names to Solana addresses.
//! T0 (read-only) — HTTP API calls only.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod sns_resolve;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use crate::sns_resolve::resolve;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

    struct SnsResolve;

    const PLUGIN_NAME: &str = "sns-resolve";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "sns-resolve";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        name: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SnsResolve {
        fn plugin_name() -> String { PLUGIN_NAME.to_string() }
        fn plugin_version() -> String { PLUGIN_VERSION.to_string() }
    }

    impl Tool for SnsResolve {
        fn name() -> String { TOOL_NAME.to_string() }

        fn description() -> String {
            "Resolve a .sol or ANS domain name to a Solana wallet address. \
             Use this so agents don't hallucinate addresses when users say 'send to alice.sol'. \
             T0: read-only HTTP API call.".to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "The .sol or ANS domain name to resolve (e.g. 'alice.sol' or 'bob')."
                    }
                },
                "required": ["name"]
            }).to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(ToolResult { success: false, output: String::new(), error: Some(format!("invalid arguments: {e}")) }),
            };
            emit(PluginAction::Start, PluginOutcome::Attempting, "resolving domain", None);
            let result = resolve(&parsed.name, "https://api.mainnet-beta.solana.com");
            let output = serde_json::to_string(&result).map_err(|e| format!("JSON serialization failed: {e}"))?;
            emit(PluginAction::Complete, PluginOutcome::Success, "resolution complete", None);
            Ok(ToolResult { success: true, output, error: None })
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, _count: Option<usize>) {
        log_record(LogLevel::Info, &PluginEvent {
            function_name: "sns_resolve::tool::execute".to_string(),
            action, outcome: Some(outcome), duration_ms: None, attrs: None, message: message.to_string(),
        });
    }

    export!(SnsResolve);
}

#[cfg(not(target_family = "wasm"))]
pub use sns_resolve::*;
