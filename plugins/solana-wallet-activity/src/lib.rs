//! A ZeroClaw WIT tool plugin: `solana_wallet_activity`.
//!
//! One-call wallet activity report: window, cadence, active days, failure rate
//! with behavioral interpretation. Read-only (custody tier T0): the tool cannot sign, move funds, or
//! reach anything but the configured RPC.
//!
//! The pure logic lives in [`logic`] with no wasm dependency, so it compiles
//! and tests on the host with a plain `cargo test`; the wasm component reuses
//! the exact same code path through this shim, supplying a waki-backed fetch.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod logic;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::logic;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct Plugin;

    impl PluginInfo for Plugin {
        fn plugin_name() -> String {
            "solana-wallet-activity".to_string()
        }
        fn plugin_version() -> String {
            "0.1.0".to_string()
        }
    }

    fn fetch(rpc_url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        let payload = serde_json::to_vec(body).map_err(|e| format!("encode failed: {e}"))?;
        let resp = waki::Client::new()
            .post(rpc_url)
            .header("Content-Type", "application/json")
            .body(payload)
            .connect_timeout(std::time::Duration::from_secs(10))
            .send()
            .map_err(|e| format!("RPC request failed: {e}"))?;
        let status = resp.status_code();
        let bytes = resp
            .body()
            .map_err(|e| format!("RPC response read failed: {e}"))?;
        if !(200..300).contains(&status) {
            return Err(format!("RPC returned HTTP {status}"));
        }
        serde_json::from_slice(&bytes).map_err(|e| format!("RPC returned invalid JSON: {e}"))
    }

    impl Tool for Plugin {
        fn name() -> String {
            logic::NAME.to_string()
        }
        fn description() -> String {
            logic::DESCRIPTION.to_string()
        }
        fn parameters_schema() -> String {
            logic::parameters_schema()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let (success, output, error) = logic::run(&args, &fetch);
            log_record(
                LogLevel::Info,
                &PluginEvent {
                    function_name: "solana_wallet_activity::tool::execute".into(),
                    action: PluginAction::Complete,
                    outcome: Some(if success {
                        PluginOutcome::Success
                    } else {
                        PluginOutcome::Failure
                    }),
                    duration_ms: None,
                    attrs: None,
                    message: "wallet activity report".into(),
                },
            );
            Ok(ToolResult { success, output, error })
        }
    }

    export!(Plugin);
}
