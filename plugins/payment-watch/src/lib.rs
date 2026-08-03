//! ZeroClaw WIT tool plugin: `payment_watch`.
//!
//! Read-only check: has an expected Solana payment (identified by its Solana
//! Pay reference key) landed? Two bounded RPC calls, one short line back.
//! Pairs with `spl-transfer-build`/`solana-pay-request` flows: they attach
//! the reference, this closes the loop ("Invoice #412 paid, 25 USDC").
//!
//! All logic lives in [`watcher`] with no wasm dependency; this file is the
//! thin `#[cfg(target_family = "wasm")]` component shim plus the waki-backed
//! RPC transport.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod watcher;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::watcher::{run, Lookups};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct PaymentWatch;

    struct WakiRpc {
        rpc_url: String,
    }

    impl Lookups for WakiRpc {
        fn rpc(&mut self, body: &str) -> Result<String, String> {
            let resp = waki::Client::new()
                .post(&self.rpc_url)
                .header("Content-Type", "application/json")
                .body(body.as_bytes().to_vec())
                .send()
                .map_err(|e| format!("rpc transport: {e}"))?;
            let status = resp.status_code();
            let bytes = resp.body().map_err(|e| format!("rpc body: {e}"))?;
            if status != 200 {
                return Err(format!("rpc http status {status}"));
            }
            String::from_utf8(bytes).map_err(|e| format!("rpc utf8: {e}"))
        }
    }

    impl PluginInfo for PaymentWatch {
        fn plugin_name() -> String {
            env!("CARGO_PKG_NAME").to_string()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").to_string()
        }
    }

    impl Tool for PaymentWatch {
        fn name() -> String {
            "payment_watch".to_string()
        }

        fn description() -> String {
            "Check whether an expected Solana payment has arrived, using its Solana Pay \
             reference key. Read-only: reports payer, amount, mint and confirmation in one \
             line; moves nothing and holds no keys. Use after issuing a payment request or \
             invoice to confirm it was settled. Args: the base58 reference key, and \
             optionally the expected amount, mint and recipient to tighten the check."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "reference": { "type": "string", "description": "Base58 32-byte Solana Pay reference key attached to the expected payment." },
                    "expected_amount": { "type": "string", "description": "Optional decimal amount in user units the payment must be at least, e.g. \"25\". Requires mint." },
                    "mint": { "type": "string", "description": "Base58 SPL mint the payment should arrive in (e.g. the USDC mint)." },
                    "recipient": { "type": "string", "description": "Optional base58 wallet the funds must have landed with." }
                },
                "required": ["reference"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            log_record(
                LogLevel::Info,
                &PluginEvent {
                    function_name: "payment_watch::tool::execute".into(),
                    action: PluginAction::Query,
                    outcome: None,
                    duration_ms: None,
                    attrs: None,
                    message: "checking payment reference".into(),
                },
            );
            let rpc_url = serde_json::from_str::<serde_json::Value>(&args)
                .ok()
                .and_then(|v| {
                    v.get("__config")?
                        .get("rpc_url")?
                        .as_str()
                        .map(str::to_string)
                })
                .unwrap_or_default();
            let mut transport = WakiRpc { rpc_url };
            match run(&args, &mut transport) {
                Ok(output) => {
                    log_record(
                        LogLevel::Info,
                        &PluginEvent {
                            function_name: "payment_watch::tool::execute".into(),
                            action: PluginAction::Complete,
                            outcome: Some(PluginOutcome::Success),
                            duration_ms: None,
                            attrs: None,
                            message: "watch complete".into(),
                        },
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    log_record(
                        LogLevel::Warn,
                        &PluginEvent {
                            function_name: "payment_watch::tool::execute".into(),
                            action: PluginAction::Fail,
                            outcome: Some(PluginOutcome::Failure),
                            duration_ms: None,
                            attrs: None,
                            message: format!("watch failed: {e}"),
                        },
                    );
                    Ok(ToolResult {
                        success: false,
                        output: format!("{e}"),
                        error: Some(format!("{e}")),
                    })
                }
            }
        }
    }

    export!(PaymentWatch);
}
