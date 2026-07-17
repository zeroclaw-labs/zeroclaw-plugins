pub mod core;

use crate::core::check_token_risk;
use serde::{Deserialize, Serialize};
use serde_json::json;
use base64::{engine::general_purpose, Engine as _};

wit_bindgen::generate!({
    path: "wit",
    world: "tool-plugin",
    exports: {
        "zeroclaw:plugin/plugin-info": PluginInfoImpl,
        "zeroclaw:plugin/tool": ToolImpl,
    },
});

struct PluginInfoImpl;

impl exports::zeroclaw::plugin::plugin_info::Guest for PluginInfoImpl {
    fn plugin_name() -> String {
        "token-risk-check".to_string()
    }

    fn plugin_version() -> String {
        "0.1.0".to_string()
    }
}

struct ToolImpl;

#[derive(Debug, Deserialize, Serialize)]
struct ExecuteArgs {
    token_data: String,
}

impl exports::zeroclaw::plugin::tool::Guest for ToolImpl {
    fn name() -> String {
        "token-risk-check".to_string()
    }

    fn description() -> String {
        "Checks Solana token risks based on zero-trust principles.".to_string()
    }

    fn parameters_schema() -> String {
        let schema = json!({
            "type": "object",
            "properties": {
                "token_data": {
                    "type": "string",
                    "description": "Base64 encoded token data to analyze."
                }
            },
            "required": ["token_data"]
        });
        schema.to_string()
    }

    fn execute(args: String) -> Result<exports::zeroclaw::plugin::tool::ToolResult, String> {
        let parsed_args: ExecuteArgs = serde_json::from_str(&args)
            .map_err(|e| format!("Failed to parse arguments: {}", e))?;

        let token_data_bytes = general_purpose::STANDARD.decode(&parsed_args.token_data)
            .map_err(|e| format!("Failed to decode base64 token data: {}", e))?;

        match check_token_risk(&token_data_bytes) {
            Ok(output) => Ok(exports::zeroclaw::plugin::tool::ToolResult {
                success: true,
                output: output,
                error: None,
            }),
            Err(e) => Ok(exports::zeroclaw::plugin::tool::ToolResult {
                success: false,
                output: String::new(),
                error: Some(e.to_string()),
            }),
        }
    }
}
