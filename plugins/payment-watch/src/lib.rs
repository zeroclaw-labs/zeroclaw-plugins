//! A ZeroClaw WIT tool plugin: `payment_watch`.
//!
//! Polls Solana JSON-RPC for a payment matching a recipient and/or Solana Pay
//! reference, optional amount/mint/memo. Closes the loop on `solana-pay-request`.
//!
//! Custody tier: **T0 Read** — RPC only; no keys, no signing, no submit.
//!
//! Pure logic in [`watch`]; this file is the thin wasm shim.
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
    use std::time::Duration;

    use crate::watch::{
        report_to_json, watch_payment, HttpPost, WatchConfig, WatchQuery,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct PaymentWatch;

    const PLUGIN_NAME: &str = "payment-watch";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "payment_watch";
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

    /// `waki`-backed HTTP for Solana JSON-RPC.
    struct WakiHttp;

    impl HttpPost for WakiHttp {
        fn post_json(
            &self,
            url: &str,
            body: &str,
            headers: &[(String, String)],
        ) -> Result<String, String> {
            let parsed: serde_json::Value =
                serde_json::from_str(body).map_err(|e| format!("json body: {e}"))?;
            // waki header names require `'static`; map known keys only.
            let mut req = waki::Client::new()
                .post(url)
                .connect_timeout(CONNECT_TIMEOUT)
                .header("Content-Type", "application/json")
                .json(&parsed);
            for (k, v) in headers {
                let key = k.as_str();
                if key.eq_ignore_ascii_case("content-type") {
                    continue;
                }
                if key.eq_ignore_ascii_case("authorization") {
                    req = req.header("Authorization", v.clone());
                } else if key.eq_ignore_ascii_case("x-api-key") {
                    req = req.header("X-Api-Key", v.clone());
                }
                // Other custom headers are ignored in-wasm (document in README).
            }
            let resp = req.send().map_err(|e| format!("http send: {e}"))?;
            let status = resp.status_code();
            let val: serde_json::Value = resp.json().map_err(|e| format!("http body: {e}"))?;
            let text = val.to_string();
            if status >= 400 {
                return Err(format!("HTTP {status}: {text}"));
            }
            Ok(text)
        }
    }

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        #[serde(default)]
        recipient: Option<String>,
        #[serde(default)]
        reference: Option<String>,
        #[serde(default)]
        expected_amount: Option<f64>,
        #[serde(default, alias = "spl_token", alias = "spl-token")]
        mint: Option<String>,
        #[serde(default, alias = "memo")]
        memo_contains: Option<String>,
        #[serde(default)]
        until_signature: Option<String>,
        #[serde(default)]
        amount_tolerance: Option<f64>,
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
            "Check whether an expected Solana payment has landed (custody T0: read-only RPC). \
             Watch by Solana Pay reference and/or recipient, optional expected_amount, mint, memo. \
             Returns paid | pending | no_match with a short summary for chat. \
             Pair with solana_pay_request to close invoices. Never accepts private keys."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Base58 wallet expected to receive funds."
                    },
                    "reference": {
                        "type": "string",
                        "description": "Solana Pay reference pubkey used when creating the invoice."
                    },
                    "expected_amount": {
                        "type": "number",
                        "description": "Expected decimal amount in UI units (e.g. 25 USDC)."
                    },
                    "mint": {
                        "type": "string",
                        "description": "SPL mint; omit for native SOL."
                    },
                    "memo_contains": {
                        "type": "string",
                        "description": "Optional substring that must appear in the on-chain memo."
                    },
                    "until_signature": {
                        "type": "string",
                        "description": "Optional: only consider signatures newer than this one."
                    },
                    "amount_tolerance": {
                        "type": "number",
                        "description": "Allowed absolute delta vs expected_amount (default 0)."
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
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid arguments");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let cfg = WatchConfig::from_section(&parsed.config);
            let query = WatchQuery {
                recipient: parsed.recipient,
                reference: parsed.reference,
                expected_amount: parsed.expected_amount,
                mint: parsed.mint,
                memo_contains: parsed.memo_contains,
                until_signature: parsed.until_signature,
                amount_tolerance: parsed.amount_tolerance.unwrap_or(0.0),
            };

            match watch_payment(&WakiHttp, &cfg, &query) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "payment watch complete",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: report_to_json(&report),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "payment watch refused");
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        // Never log RPC keys or full tx dumps — fixed short message only.
        log_record(
            LogLevel::Info,
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
