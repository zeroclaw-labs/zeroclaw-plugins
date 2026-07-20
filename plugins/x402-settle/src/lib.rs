//! ZeroClaw WIT tool plugin: `x402_settle` (custody **T2**).
//!
//! Settles HTTP 402 / x402 paywalled resources on Solana using a **scoped
//! session key** only. Hard rails (all required or refuse to sign):
//!
//! - `max_amount` per tx
//! - `daily_cap` + `spent_today`
//! - non-empty `allowed_mints`
//! - optional `allowed_payees`
//! - `approval_token` must match tool arg `approval` (approval gate)
//! - never accepts private keys in tool arguments
//!
//! Build: cargo build --target wasm32-wasip2 --release

pub mod codec;
pub mod settle;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::Duration;

    use crate::settle::{
        result_to_json, settle_x402, HttpClient, HttpResponse, SettleConfig, SettleRequest,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct X402Settle;

    const PLUGIN_NAME: &str = "x402-settle";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "x402_settle";
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

    struct WakiHttp;

    impl HttpClient for WakiHttp {
        fn request(
            &self,
            method: &str,
            url: &str,
            headers: &[(String, String)],
            body: Option<&str>,
        ) -> Result<HttpResponse, String> {
            let m = method.to_ascii_uppercase();
            let mut req = match m.as_str() {
                "GET" => waki::Client::new().get(url),
                "POST" => waki::Client::new().post(url),
                other => return Err(format!("unsupported method {other}")),
            };
            req = req.connect_timeout(CONNECT_TIMEOUT);
            for (k, v) in headers {
                if k.eq_ignore_ascii_case("content-type") {
                    req = req.header("Content-Type", v.clone());
                } else if k.eq_ignore_ascii_case("authorization") {
                    req = req.header("Authorization", v.clone());
                } else if k.eq_ignore_ascii_case("x-api-key") {
                    req = req.header("X-Api-Key", v.clone());
                } else if k.eq_ignore_ascii_case("x-payment") {
                    req = req.header("X-PAYMENT", v.clone());
                } else if k.eq_ignore_ascii_case("payment-signature") {
                    req = req.header("PAYMENT-SIGNATURE", v.clone());
                }
            }
            if let Some(b) = body {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(b) {
                    req = req.header("Content-Type", "application/json").json(&val);
                } else {
                    // Non-JSON bodies: send as JSON string value for wasi:http simplicity.
                    req = req
                        .header("Content-Type", "application/json")
                        .json(&serde_json::Value::String(b.to_string()));
                }
            }
            let resp = req.send().map_err(|e| format!("http: {e}"))?;
            let status = resp.status_code();
            let body = resp
                .body()
                .map(|bytes| String::from_utf8(bytes).unwrap_or_default())
                .unwrap_or_default();
            Ok(HttpResponse { status, body })
        }
    }

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        url: String,
        #[serde(default = "default_get")]
        method: String,
        #[serde(default)]
        body: Option<String>,
        /// Must match config approval_token.
        approval: String,
        #[serde(default)]
        max_payment: Option<f64>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    fn default_get() -> String {
        "GET".into()
    }

    impl PluginInfo for X402Settle {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for X402Settle {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Settle an HTTP 402 / x402 paywalled request on Solana (custody T2: session key only). \
             Requires operator approval token matching config. Enforces max_amount, daily_cap, \
             mint allowlist, optional payee allowlist inside the plugin. Never pass private keys \
             as arguments. Use only a funded session wallet — never the main wallet."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Paywalled resource URL (https)."
                    },
                    "method": {
                        "type": "string",
                        "description": "GET or POST (default GET)."
                    },
                    "body": {
                        "type": "string",
                        "description": "Optional POST body."
                    },
                    "approval": {
                        "type": "string",
                        "description": "Must exactly match config approval_token (approval gate)."
                    },
                    "max_payment": {
                        "type": "number",
                        "description": "Optional per-call ceiling (still clamped by config max_amount/daily_cap)."
                    }
                },
                "required": ["url", "approval"]
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

            let cfg = match SettleConfig::from_section(&parsed.config) {
                Ok(c) => c,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "t2 misconfigured");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    });
                }
            };

            let req = SettleRequest {
                url: parsed.url,
                method: parsed.method,
                body: parsed.body,
                approval: parsed.approval,
                max_payment: parsed.max_payment,
            };

            match settle_x402(&WakiHttp, &cfg, &req) {
                Ok(result) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        if result.paid {
                            "x402 settled"
                        } else {
                            "x402 no payment needed"
                        },
                    );
                    Ok(ToolResult {
                        success: true,
                        output: result_to_json(&result),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "x402 refuse");
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
        // Never log session keys, approval tokens, or raw tx material.
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "x402_settle::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(X402Settle);
}
