//! A ZeroClaw WIT tool plugin: `solana_pay_request`.
//!
//! Turns "charge table 4 for 25 USDC" into a Solana Pay transfer-request URL
//! (QR-ready) — custody tier T1: the tool holds no keys and signs nothing; a
//! customer's wallet does. The operator pins the receiving address, token
//! allowlist, and per-request cap in this plugin's own config section, and
//! those guardrails are enforced in [`pay`], below the LLM.
//!
//! The pure core lives in [`pay`] with no wasm dependency, so it compiles and
//! tests on the host with a plain `cargo test`; the wasm component reuses the
//! exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod pay;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::pay::{build_request, PayArgs, PayConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaPayRequest;

    const PLUGIN_NAME: &str = "solana-pay-request";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_pay_request";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        amount: String,
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        recipient: Option<String>,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        memo: Option<String>,
        #[serde(default)]
        invoice_id: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SolanaPayRequest {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaPayRequest {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Create a Solana Pay payment request (a solana: URL usable as a QR code) for a \
             customer to pay the operator's configured address. Use when someone should PAY \
             the operator — e.g. an invoice or a bill. The receiving address, allowed tokens, \
             and maximum amount are fixed by operator config; requests outside that policy \
             are refused. This tool moves no funds and holds no keys."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "amount": {
                        "type": "string",
                        "description": "Decimal amount in token units, e.g. \"25\" or \"0.5\"."
                    },
                    "token": {
                        "type": "string",
                        "description": "Token symbol from the operator allowlist (default: first allowlisted token, usually USDC)."
                    },
                    "recipient": {
                        "type": "string",
                        "description": "Receiving address (base58). Omit when the operator has pinned one — pinned config always wins."
                    },
                    "label": {
                        "type": "string",
                        "description": "Short display label shown in the payer's wallet (e.g. shop name)."
                    },
                    "message": {
                        "type": "string",
                        "description": "Short display message shown in the payer's wallet (e.g. \"Table 4\")."
                    },
                    "memo": {
                        "type": "string",
                        "description": "On-chain memo to attach to the payment, e.g. an invoice number."
                    },
                    "invoice_id": {
                        "type": "string",
                        "description": "Free-form invoice id folded into the deterministic payment reference."
                    }
                },
                "required": ["amount"]
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

            let cfg = match PayConfig::from_section(&parsed.config) {
                Ok(c) => c,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "bad config");
                    return Ok(fail(e));
                }
            };

            let pay_args = PayArgs {
                amount: parsed.amount,
                token: parsed.token,
                recipient: parsed.recipient,
                label: parsed.label,
                message: parsed.message,
                memo: parsed.memo,
                invoice_id: parsed.invoice_id,
            };

            match build_request(&pay_args, &cfg) {
                Ok(req) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "pay request built",
                    );
                    Ok(clamp(ToolResult {
                        success: true,
                        output: format!("{}\n{}", req.summary, req.url),
                        error: None,
                    }))
                }
                Err(e) => {
                    // Guardrail refusals are reported to the model verbatim so
                    // it can relay them; the request itself never proceeds.
                    emit(
                        PluginAction::Reject,
                        PluginOutcome::Failure,
                        "request refused",
                    );
                    Ok(fail(e))
                }
            }
        }
    }

    /// Final backstop: no ToolResult ever exceeds this, whatever the inputs.
    /// The core already bounds every field; this guarantees it at the WIT edge.
    const MAX_RESULT_CHARS: usize = 4096;

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
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_pay_request::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaPayRequest);
}
