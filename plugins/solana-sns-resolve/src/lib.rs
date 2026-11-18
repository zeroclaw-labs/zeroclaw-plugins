
pub mod core;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::core::resolve::resolve_domain;
    use crate::core::rpc::http_get;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

    struct SolanaSnsResolve;

    impl PluginInfo for SolanaSnsResolve {
        fn plugin_name() -> String { "solana-sns-resolve".to_string() }
        fn plugin_version() -> String { env!("CARGO_PKG_VERSION").to_string() }
    }

    impl Tool for SolanaSnsResolve {
        fn name() -> String { "solana_sns_resolve".to_string() }

        fn description() -> String {
            "Resolve a Solana Name Service (SNS) .sol domain to a wallet address.              Call this first whenever the user provides a .sol name instead of a raw address.              Args: domain (e.g. levrone.sol or levrone).".to_string()
        }

        fn parameters_schema() -> String {
            r#"{"type":"object","properties":{"domain":{"type":"string","description":"SNS domain (e.g. levrone.sol)"}},"required":["domain"]}"#.to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let v: serde_json::Value = match serde_json::from_str(&args) {
                Ok(v) => v,
                Err(e) => return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("invalid args: {e}")),
                }),
            };

            let domain = match v["domain"].as_str() {
                Some(d) => d.to_string(),
                None => return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("missing domain field".to_string()),
                }),
            };

            match resolve_domain(&domain, http_get) {
                Ok(address) => {
                    log_record(LogLevel::Info, &PluginEvent {
                        function_name: "solana_sns_resolve::execute".to_string(),
                        action: PluginAction::Complete,
                        outcome: Some(PluginOutcome::Success),
                        duration_ms: None,
                        attrs: None,
                        message: format!("resolved {}", domain),
                    });
                    Ok(ToolResult {
                        success: true,
                        output: format!("{} -> {}", domain, address),
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

    export!(SolanaSnsResolve);
}
