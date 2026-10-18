//! A ZeroClaw WIT tool plugin: `lending-health`.
//!
//! Read-only Solana lending position health (Kamino in v0), built for the cron
//! SOP pattern: morning digest + immediate alert when any position's health
//! factor drops below the configured threshold.
//!
//! The pure core lives in [`health`] with no wasm dependency, so it compiles
//! and tests on the host with a plain `cargo test`; the wasm component reuses
//! the exact same logic through this shim.
//! (Layout mirrors `plugins/redact-text`, the canonical reference plugin.)
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod health;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::health::{self, Config, Http};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde_json::Value;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct LendingHealth;

    const PLUGIN_NAME: &str = "lending-health";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    /// Live HTTP over the host's wasi:http (`http_client` permission).
    struct WakiHttp;

    impl Http for WakiHttp {
        fn get_json(&self, url: &str) -> Result<Value, String> {
            waki::Client::new()
                .get(url)
                .header("Accept", "application/json")
                .send()
                .map_err(|e| format!("http transport error: {e}"))?
                .json::<Value>()
                .map_err(|e| format!("bad json from api: {e}"))
        }
    }

    /// Build the operator config from the host-injected `__config` section
    /// (config_read permission). `wallet` is REQUIRED — this tool refuses to
    /// run unconfigured rather than guess. Nothing here is LLM-controllable.
    fn config_from_args(args: &str) -> Result<Config, String> {
        let cfg = serde_json::from_str::<Value>(args)
            .ok()
            .and_then(|v| v.get("__config").cloned())
            .unwrap_or(Value::Null);
        let get = |key: &str| cfg.get(key).and_then(Value::as_str).map(str::to_string);
        Ok(Config {
            wallet: get("wallet")
                .ok_or("lending-health: `wallet` missing from plugin config section")?,
            api_base: get("api_base")
                .unwrap_or_else(|| "https://api.kamino.finance".to_string()),
            alert_threshold: get("alert_threshold")
                .and_then(|s| s.parse().ok())
                .unwrap_or(1.15),
        })
    }

    impl PluginInfo for LendingHealth {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for LendingHealth {
        fn name() -> String {
            health::NAME.to_string()
        }

        fn description() -> String {
            health::DESCRIPTION.to_string()
        }

        fn parameters_schema() -> String {
            health::parameters_schema()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let result = config_from_args(&args)
                .and_then(|cfg| health::execute(&WakiHttp, &cfg, &args));
            match result {
                Ok(output) => {
                    emit(PluginAction::Complete, PluginOutcome::Success, "health report produced");
                    Ok(ToolResult { success: true, output, error: None })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "health check failed");
                    Ok(ToolResult { success: false, output: String::new(), error: Some(e) })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "lending_health::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(LendingHealth);
}
