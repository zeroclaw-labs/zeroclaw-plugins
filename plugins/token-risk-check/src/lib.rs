//! A ZeroClaw WIT tool plugin: `token_risk_check`.
//!
//! Checks an SPL Token-2022 mint for rug-pull risk: mint/freeze authority,
//! dangerous extensions, and holder concentration. Read-only -- this plugin
//! never builds or signs a transaction (custody tier T0; see README.md).
//!
//! The pure risk-assessment core lives in [`token_risk`] with no wasm
//! dependency, so it compiles and tests on the host with a plain
//! `cargo test`; the wasm component reuses the exact same logic through
//! this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod token_risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::token_risk::{self, RiskConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };
    use zeroclaw_solana_core::HttpTransport;

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    /// Real transport for the wasm32-wasip2 component, routed through
    /// `wasi:http/outgoing-handler` via the `waki` crate. Defined here (not
    /// in `zeroclaw-solana-core`) so the shared core crate never depends on
    /// `waki` at all -- only the wasm-gated half of this shim does.
    struct WakiTransport;

    impl HttpTransport for WakiTransport {
        fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
            let resp = waki::Client::new()
                .post(url)
                .header("content-type", "application/json")
                .body(body.as_bytes().to_vec())
                .send()
                .map_err(|e| format!("rpc transport error: {e}"))?;
            let bytes = resp
                .body()
                .map_err(|e| format!("rpc response read error: {e}"))?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }

        fn get_with_headers(
            &self,
            url: &str,
            headers: &[(&'static str, &str)],
        ) -> Result<String, String> {
            let mut req = waki::Client::new().get(url);
            for (name, value) in headers {
                // waki's header() requires `K: IntoHeaderName`, which the
                // underlying `http` crate only implements for `&'static
                // str` -- exactly why the trait pins header *names* to
                // `'static` (see the doc comment on `get_with_headers`).
                req = req.header(*name, value.to_string());
            }
            let resp = req
                .send()
                .map_err(|e| format!("http transport error: {e}"))?;
            let bytes = resp
                .body()
                .map_err(|e| format!("http response read error: {e}"))?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }
    }

    impl PluginInfo for TokenRiskCheck {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for TokenRiskCheck {
        fn name() -> String {
            token_risk::name().to_string()
        }

        fn description() -> String {
            token_risk::description().to_string()
        }

        fn parameters_schema() -> String {
            token_risk::parameters_schema().to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let cfg = match RiskConfig::from_section(&parsed.config) {
                Ok(cfg) => cfg,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid config");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    });
                }
            };

            match token_risk::check(&parsed.mint, &WakiTransport, &cfg) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "risk check complete",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: report,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, &e);
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
