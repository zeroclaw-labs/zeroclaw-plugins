//! A T0, read-only ZeroClaw tool for resolving top-level Solana Name Service
//! `.sol` domains through the official SNS SDK proxy over host-mediated HTTPS.
pub mod resolve;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({ path: "../../wit/v0", world: "tool-plugin", features: ["plugins-wit-v0"] });
    use crate::resolve::{format, normalize_domain, parse_proxy_response};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde::Deserialize;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "sns-resolve";
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Args {
        domain: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }
    struct SnsResolve;
    impl PluginInfo for SnsResolve {
        fn plugin_name() -> String {
            PLUGIN_NAME.into()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").into()
        }
    }
    fn get(url: &str) -> Result<Value, String> {
        waki::Client::new()
            .get(url)
            .send()
            .map_err(|e| e.to_string())?
            .json()
            .map_err(|e| e.to_string())
    }
    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "sns_resolve::tool::execute".into(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.into(),
            },
        );
    }
    impl Tool for SnsResolve {
        fn name() -> String {
            "sns_resolve".into()
        }
        fn description() -> String {
            "Resolve a top-level Solana Name Service .sol domain to its wallet address. Read-only; use this before passing a resolved address to another tool.".into()
        }
        fn parameters_schema() -> String {
            json!({"type":"object","properties":{"domain":{"type":"string","description":"Top-level .sol domain, e.g. bonk.sol."}},"required":["domain"],"additionalProperties":false}).to_string()
        }
        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: Args =
                serde_json::from_str(&args).map_err(|e| format!("invalid arguments: {e}"))?;
            let domain = match normalize_domain(&parsed.domain) {
                Ok(d) => d,
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    })
                }
            };
            emit(
                PluginAction::Start,
                PluginOutcome::Success,
                "starting read-only SNS lookup",
            );
            let base = parsed
                .config
                .get("sns_api_base_url")
                .map(String::as_str)
                .unwrap_or("https://sdk-proxy.sns.id")
                .trim_end_matches('/');
            let value = get(&format!("{base}/resolve/{domain}"))
                .map_err(|e| format!("SNS request failed: {e}"))?;
            match parse_proxy_response(&value) {
                Ok(address) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "resolved SNS domain",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: format(&domain, &address),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "SNS resolution failed",
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    })
                }
            }
        }
    }
    export!(SnsResolve);
}
