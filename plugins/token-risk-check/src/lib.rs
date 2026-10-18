//! ZeroClaw read-only Solana token-risk tool. The core is host-testable; this
//! wasm-only shim makes host-mediated HTTPS requests and emits structured logs.
pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({ path: "../../wit/v0", world: "tool-plugin", features: ["plugins-wit-v0"] });
    use crate::risk::{assess, format, valid_mint};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde::Deserialize;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "token-risk-check";
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Args {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }
    struct TokenRiskCheck;
    impl PluginInfo for TokenRiskCheck {
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
    fn post(url: &str, body: &Value) -> Result<Value, String> {
        waki::Client::new()
            .post(url)
            .json(body)
            .send()
            .map_err(|e| e.to_string())?
            .json()
            .map_err(|e| e.to_string())
    }
    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".into(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.into(),
            },
        );
    }
    impl Tool for TokenRiskCheck {
        fn name() -> String {
            "token_risk_check".into()
        }
        fn description() -> String {
            "Read-only Solana mint risk check. Returns a concise red/amber/green verdict for authorities, holder concentration, LP status, and Token-2022 extensions.".into()
        }
        fn parameters_schema() -> String {
            json!({"type":"object","properties":{"mint":{"type":"string","description":"Solana token mint address."}},"required":["mint"],"additionalProperties":false}).to_string()
        }
        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: Args =
                serde_json::from_str(&args).map_err(|e| format!("invalid arguments: {e}"))?;
            if !valid_mint(&parsed.mint) {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("invalid Solana mint address".into()),
                });
            }
            emit(
                PluginAction::Start,
                PluginOutcome::Success,
                "starting read-only token risk check",
            );
            let rug_base = parsed
                .config
                .get("rugcheck_url")
                .map(String::as_str)
                .unwrap_or("https://api.rugcheck.xyz")
                .trim_end_matches('/');
            let rug = get(&format!("{rug_base}/v1/tokens/{}/report", parsed.mint))
                .map_err(|e| format!("RugCheck request failed: {e}"))?;
            let helius = match parsed.config.get("helius_api_key").filter(|k| !k.is_empty()) {
                Some(key) => post(&format!("https://mainnet.helius-rpc.com/?api-key={key}"), &json!({"jsonrpc":"2.0","id":"token-risk-check","method":"getAsset","params":{"id":parsed.mint,"displayOptions":{"showFungible":true}}})).ok(),
                None => None,
            };
            let output = format(&assess(&rug, helius.as_ref()), &parsed.mint);
            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "completed read-only token risk check",
            );
            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }
    export!(TokenRiskCheck);
}
