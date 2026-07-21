//! A ZeroClaw WIT tool plugin: `payment_watch`.
//!
//! Closes the loop opened by `solana-pay-request`: it watches the operator's
//! configured receiving wallet for a recent incoming credit (optionally
//! matching an expected amount) and reports the confirming transaction, or
//! that nothing has arrived yet. Watching the wallet — not the Solana Pay
//! `reference`, which many wallets drop — is what makes it detect real
//! payments. Custody tier T0: pure reads, no keys, no state.
//!
//! The pure core lives in [`watch`] with no wasm dependency and is host-tested
//! against a mock RPC with plain `cargo test`; this file is the thin component
//! shim wiring it to the `tool-plugin` WIT world with the blocking `waki`
//! client (TLS is performed host-side).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod watch;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::watch::{check_payment, Status, WatchArgs, WatchConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };
    use zeroclaw_solana_core::rpc::HttpTransport;

    struct WakiTransport;

    impl HttpTransport for WakiTransport {
        fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
            let response = waki::Client::new()
                .post(url)
                .header("content-type", "application/json")
                .connect_timeout(std::time::Duration::from_secs(8))
                .body(body.as_bytes().to_vec())
                .send()
                .map_err(|e| format!("rpc request failed: {e}"))?;
            let bytes = response
                .body()
                .map_err(|e| format!("rpc response read failed: {e}"))?;
            String::from_utf8(bytes).map_err(|_| "rpc response is not UTF-8".to_string())
        }
    }

    struct PaymentWatch;

    const PLUGIN_NAME: &str = "payment-watch";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "payment_watch";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        #[serde(default)]
        amount: Option<String>,
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        label: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for PaymentWatch {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for PaymentWatch {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Check whether the operator's wallet has received a payment. Use it after \
             solana_pay_request to confirm settlement — it watches the operator's configured \
             receiving wallet for a recent incoming payment (optionally matching an expected \
             amount) and reports the on-chain transaction, or that nothing has arrived yet. \
             Read-only; touches no funds and no keys."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "amount": {
                        "type": "string",
                        "description": "Expected amount to match, e.g. \"25\" or \"0.1\". Omit to report the most recent incoming payment."
                    },
                    "token": {
                        "type": "string",
                        "description": "Token symbol from the operator allowlist (default: first, usually USDC)."
                    },
                    "label": {
                        "type": "string",
                        "description": "Optional invoice id or note echoed back for context."
                    }
                },
                "required": []
            })
            .to_string()
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
                    return Ok(fail(format!("invalid arguments: {e}")));
                }
            };
            let cfg = match WatchConfig::from_section(&parsed.config) {
                Ok(c) => c,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "bad config");
                    return Ok(fail(e));
                }
            };
            let watch_args = WatchArgs {
                amount: parsed.amount,
                token: parsed.token,
                label: parsed.label,
            };

            match check_payment(&WakiTransport, &watch_args, &cfg) {
                Ok(res) => {
                    let (action, msg) = match res.status {
                        Status::Paid => (PluginAction::Complete, "payment settled"),
                        Status::Pending => (PluginAction::Note, "payment pending"),
                    };
                    emit(action, PluginOutcome::Success, msg);
                    Ok(clamp(ToolResult {
                        success: true,
                        output: res.text,
                        error: None,
                    }))
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "watch failed");
                    Ok(fail(e))
                }
            }
        }
    }

    /// Final backstop: a settlement report is a status line + one tx link;
    /// bound the WIT-edge output regardless of inputs.
    const MAX_RESULT_CHARS: usize = 1024;

    fn clamp(mut r: ToolResult) -> ToolResult {
        if r.output.len() > MAX_RESULT_CHARS {
            r.output = r.output.chars().take(MAX_RESULT_CHARS).collect::<String>() + "…";
        }
        if let Some(e) = r.error.take() {
            r.error = Some(if e.len() > MAX_RESULT_CHARS {
                e.chars().take(MAX_RESULT_CHARS).collect::<String>() + "…"
            } else {
                e
            });
        }
        r
    }

    fn fail(error: String) -> ToolResult {
        clamp(ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        })
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        // Refusals/failures log at WARN so operators can grep them; successes
        // and notes stay at INFO.
        let level = if matches!(outcome, PluginOutcome::Failure) {
            LogLevel::Warn
        } else {
            LogLevel::Info
        };
        log_record(
            level,
            &PluginEvent {
                function_name: "payment_watch::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(PaymentWatch);
}
