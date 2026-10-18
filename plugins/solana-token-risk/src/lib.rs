
pub mod core;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use crate::core::{check_token, shape::format_report, Config};
    use crate::core::rpc::{das_get_asset, get_account_info, get_largest_accounts};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

    struct SolanaTokenRisk;

    #[derive(serde::Deserialize)]
    struct Args {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SolanaTokenRisk {
        fn plugin_name() -> String { "solana-token-risk".to_string() }
        fn plugin_version() -> String { env!("CARGO_PKG_VERSION").to_string() }
    }

    impl Tool for SolanaTokenRisk {
        fn name() -> String { "solana_token_risk".to_string() }

        fn description() -> String {
            "Check if a Solana token is safe. Returns RED/AMBER/GREEN verdict covering              mint authority, freeze authority, Token-2022 extensions (transfer hooks,              permanent delegate, high fees), top-holder concentration, and metadata.              Input: mint (base58 token mint address).".to_string()
        }

        fn parameters_schema() -> String {
            r#"{"type":"object","properties":{"mint":{"type":"string","description":"Solana token mint address (base58)"}},"required":["mint"]}"#.to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: Args = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid args: {e}")),
                    });
                }
            };

            let cfg = Config::from_map(&parsed.config);
            let report = check_token(
                &cfg.rpc_url,
                &cfg.das_url,
                &parsed.mint,
                get_account_info,
                get_largest_accounts,
                das_get_asset,
            );

            let output = format_report(&parsed.mint, &report);

            log_record(LogLevel::Info, &PluginEvent {
                function_name: "solana_token_risk::execute".to_string(),
                action: PluginAction::Complete,
                outcome: Some(PluginOutcome::Success),
                duration_ms: None,
                attrs: Some(format!(r#"{{"mint":"{}","level":"{}"}}"#, parsed.mint, report.level.label())),
                message: "token risk check complete".to_string(),
            });

            Ok(ToolResult { success: true, output, error: None })
        }
    }

    export!(SolanaTokenRisk);
}
