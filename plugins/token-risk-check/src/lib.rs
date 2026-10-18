//! ZeroClaw WIT tool plugin: `token-risk-check` (T0, read-only).
//!
//! Scores a Solana SPL / Token-2022 mint for rug/abuse risk by reading on-chain
//! data over wasi:http (host-owned TLS) and handing it to the pure core in
//! [`risk`]. Holds no keys, never signs — custody tier T0.

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use waki::{Method, Request};
    use crate::risk::{score, RiskReport, Rpc};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};
    use futures::executor::block_on;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token-risk-check";
    const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(default)]
        rpc_url: Option<String>,
        #[serde(rename = "__config", default)]
        config: std::collections::HashMap<String, String>,
    }

    /// wasi:http-backed RPC using waki. Only compiled for the component.
    struct WakiRpc {
        url: String,
    }

    impl Rpc for WakiRpc {
        fn mint_account(&self, mint: &str) -> Option<serde_json::Value> {
            let body = serde_json::json!({
                "jsonrpc":"2.0","id":1,"method":"getAccountInfo",
                "params":[mint, {"encoding":"jsonParsed","commitment":"confirmed"}]
            });
            let resp: Option<serde_json::Value> = waki::Request::builder(Method::Post, &self.url)
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
                .ok()
                .and_then(|r| r.json().ok());
            match resp {
                Some(v) => v.get("result").and_then(|r| r.get("value")).cloned(),
                None => None,
            }
        }

        fn largest_accounts(&self, mint: &str) -> Vec<serde_json::Value> {
            let body = serde_json::json!({
                "jsonrpc":"2.0","id":1,"method":"getTokenLargestAccounts",
                "params":[mint, {"commitment":"confirmed"}]
            });
            let resp: Option<serde_json::Value> = waki::Request::builder(Method::Post, &self.url)
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
                .ok()
                .and_then(|r| r.json().ok());
            match resp {
                Some(v) => v.get("result")
                    .and_then(|r| r.get("value"))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default(),
                None => Vec::new(),
            }
        }
    }

    struct TokenRiskCheck;

    impl PluginInfo for TokenRiskCheck {
        fn plugin_name() -> String { PLUGIN_NAME.to_string() }
        fn plugin_version() -> String { PLUGIN_VERSION.to_string() }
    }

    impl Tool for TokenRiskCheck {
        fn name() -> String { TOOL_NAME.to_string() }

        fn description() -> String {
            "Score a Solana SPL / Token-2022 mint for rug/abuse risk: mint & freeze authority, \
             holder concentration, LP status, and Token-2022 extensions (transfer hooks, transfer \
             fees, permanent delegate). Read-only, zero custody (T0). Returns red/amber/green."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {"type":"string","description":"SPL or Token-2022 mint address to inspect."},
                    "rpc_url": {"type":"string","description":"Optional Solana RPC URL (defaults to mainnet-beta)."}
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(ToolResult {
                    success: false, output: String::new(),
                    error: Some(format!("invalid arguments: {e}")),
                }),
            };
            let rpc_url = parsed.rpc_url
                .or_else(|| parsed.config.get("rpc_url").cloned())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| DEFAULT_RPC.to_string());
            let rpc = WakiRpc { url: rpc_url };
            let supply = rpc.largest_accounts(&parsed.mint)
                .iter().map(|h| h.get("uiAmount").and_then(|a| a.as_f64()).unwrap_or(0.0))
                .sum::<f64>();
            let report: RiskReport = score(&rpc, &parsed.mint, Some(supply));
            let out = serde_json::to_string(&report).unwrap_or_default();
            emit(PluginAction::Complete, PluginOutcome::Success, "scored mint", None);
            Ok(ToolResult { success: true, output: out, error: None })
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, _n: Option<usize>) {
        log_record(LogLevel::Info, &PluginEvent {
            function_name: "token_risk_check::tool::execute".to_string(),
            action, outcome: Some(outcome), duration_ms: None,
            attrs: None, message: message.to_string(),
        });
    }

    export!(TokenRiskCheck);
}
