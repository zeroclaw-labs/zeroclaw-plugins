//! A ZeroClaw WIT tool plugin: `fetch_paid_resource`.
//!
//! Lets an agent consume 402-paywalled APIs: on `HTTP 402 Payment Required`
//! (x402 protocol, exact/SVM scheme) it settles the charge in an SPL token
//! and retries — **only** within an operator-configured leash.
//!
//! Custody tier: **T2 (Sign)** — and the leash is the point:
//! - a scoped SESSION key holding a small allowance (never a main wallet),
//! - origin allowlist (deny-by-default: unlisted hosts are never paid),
//! - mint allowlist, per-request cap, per-day cap — all enforced in-plugin,
//!   invisible to and un-overridable by the LLM.
//!
//! The pure challenge-parsing/policy/tx core lives in [`settle`]; host tests
//! cover the injection paths. Build:
//!     rustup target add wasm32-wasip2
//!     cargo build --target wasm32-wasip2 --release

pub mod settle;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::settle::{
        authorize_challenge, build_payment, paid_summary, PaymentRequired, SettleArgs, SettleConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use solana_wasi_core::rpc;
    use solana_wasi_core::shape::{clamp, ToolOutput};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct X402Settle;

    const PLUGIN_NAME: &str = "x402-settle";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "fetch_paid_resource";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        #[serde(flatten)]
        settle: SettleArgs,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for X402Settle {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    struct HttpResponse {
        status: u16,
        body: Vec<u8>,
    }

    fn http_get(url: &str, payment_b64: Option<&str>) -> Result<HttpResponse, String> {
        let mut req = waki::Client::new()
            .get(url)
            .header("Accept", "application/json");
        if let Some(p) = payment_b64 {
            // x402 v2 transport: base64 PaymentPayload in the X-PAYMENT header.
            req = req.header("X-PAYMENT", p);
        }
        let resp = req.send().map_err(|e| format!("request failed: {e}"))?;
        let status = resp.status_code();
        let body = resp.body().map_err(|e| format!("body read: {e}"))?;
        Ok(HttpResponse { status, body })
    }

    fn rpc_call(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_string().into_bytes())
            .send()
            .map_err(|e| format!("RPC request failed: {e}"))?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(format!("RPC HTTP {status}"));
        }
        let bytes = resp.body().map_err(|e| format!("RPC body read: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("RPC bad JSON: {e}"))
    }

    impl Tool for X402Settle {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Fetch a URL that may require payment (HTTP 402 / x402 protocol). If the \
             resource demands payment, settle it in an SPL token ONLY when the site is \
             on the operator's origin allowlist and the price is within hard caps; \
             otherwise refuse and report the price. Uses a small-allowance session key, \
             never a main wallet."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The https:// resource to fetch. Payment only happens for operator-allowlisted origins."
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method (default GET)."
                    }
                },
                "required": ["url"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid args");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let result = run(&parsed);
            let (outcome, message) = match &result {
                Ok(_) => (PluginOutcome::Success, "done"),
                Err(_) => (PluginOutcome::Failure, "failed"),
            };
            emit(PluginAction::Complete, outcome, message);
            match result {
                Ok(output) => Ok(ToolResult {
                    success: true,
                    output,
                    error: None,
                }),
                Err(e) => Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(e),
                }),
            }
        }
    }

    fn run(parsed: &ExecuteArgs) -> Result<String, String> {
        // 1. Plain fetch first — free resources stay free.
        let first = http_get(&parsed.settle.url, None)?;
        if first.status != 402 {
            let body = clamp(&String::from_utf8_lossy(&first.body), 600);
            return Ok(
                ToolOutput::ok(format!("HTTP {} (no payment required).", first.status))
                    .with_detail(body)
                    .render(),
            );
        }

        // 2. Parse the challenge.
        let challenge: PaymentRequired = serde_json::from_slice(&first.body)
            .map_err(|e| format!("402 received but challenge unparseable: {e}"))?;

        let cfg = SettleConfig::from_section(&parsed.config)
            .map_err(|e| format!("operator config error: {e}"))?;

        // 3. THE GATE. Stateless per-call: per-day tracking is host-side;
        //    per-request cap always binds (documented in README).
        let req = match authorize_challenge(&parsed.settle.url, &challenge, &cfg, 0) {
            Ok(r) => r,
            Err(verdict) => {
                let reason = match verdict {
                    solana_wasi_core::policy::Verdict::Refused { reason } => reason,
                    _ => "refused".into(),
                };
                return Ok(ToolOutput::refused(format!("refused: {reason}"))
                    .with_detail("No payment was made. Caps and allowlists are operator config and cannot be changed from chat.")
                    .render());
            }
        };

        // 4. Fetch blockhash + decimals, build + sign our slot.
        let bh_resp = rpc_call(&cfg.rpc_url, &rpc::get_latest_blockhash())?;
        let blockhash = rpc::parse_latest_blockhash(&bh_resp)?;
        let dec_resp = rpc_call(&cfg.rpc_url, &rpc::get_token_decimals(&req.asset))?;
        let decimals = rpc::parse_decimals(&dec_resp)?;
        let tx_b64 = build_payment(&req, &cfg, blockhash, decimals)?;

        // 5. Retry with X-PAYMENT (v2 payload envelope).
        let payload = serde_json::json!({
            "x402Version": 2,
            "accepted": {
                "scheme": req.scheme,
                "network": req.network,
                "amount": req.amount,
                "asset": req.asset,
                "payTo": req.pay_to,
            },
            "payload": { "transaction": tx_b64 }
        });
        let payment_header = solana_wasi_core::encoding::b64_encode(payload.to_string().as_bytes());
        let second = http_get(&parsed.settle.url, Some(&payment_header))?;

        if (200..300).contains(&second.status) {
            let body = clamp(&String::from_utf8_lossy(&second.body), 500);
            Ok(paid_summary(&req, decimals, &parsed.settle.url)
                .with_detail(body)
                .render())
        } else {
            Ok(ToolOutput::refused(format!(
                "payment submitted but resource returned HTTP {} — treat as NOT delivered",
                second.status
            ))
            .render())
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
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
