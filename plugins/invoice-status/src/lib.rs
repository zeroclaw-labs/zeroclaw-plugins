//! A ZeroClaw WIT tool plugin: `invoice_status`.
//!
//! Read-only (custody **T0**) check of dual-rail invoice settlement:
//! - **USDC / Solana Pay**: `getSignaturesForAddress` on the invoice reference.
//! - **PIX**: never verified on-chain; only reported paid when the operator
//!   sets `pix_marked_paid` on the tool call.
//!
//! The pure status core lives in [`status_tool`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! reuses the exact same logic through this shim and plugs in `waki` for HTTP.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod status_tool;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde_json::Value;
    use solana_wasm_core::{HttpTransport, RpcError};

    use crate::status_tool::{fetch_and_status, StatusConfig, StatusRequest, DEFAULT_LOOKBACK};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct InvoiceStatus;

    const PLUGIN_NAME: &str = "invoice-status";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "invoice_status";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        #[serde(default)]
        invoice_id: String,
        #[serde(default)]
        reference: Option<String>,
        #[serde(default)]
        expected_usdc: Option<String>,
        #[serde(default)]
        pix_marked_paid: bool,
        #[serde(default)]
        lookback: Option<u64>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    /// Blocking wasi:http transport via `waki` for Solana JSON-RPC POSTs.
    struct WakiTransport;

    impl HttpTransport for WakiTransport {
        fn post_json(&self, url: &str, body: &Value) -> Result<Value, RpcError> {
            waki::Client::new()
                .post(url)
                .json(body)
                .send()
                .map_err(|e| RpcError::new(e.to_string()))?
                .json::<Value>()
                .map_err(|e| RpcError::new(e.to_string()))
        }
    }

    impl PluginInfo for InvoiceStatus {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for InvoiceStatus {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Check dual-rail (PIX + USDC) invoice settlement status by Solana Pay \
             reference. Queries getSignaturesForAddress for the invoice reference \
             (derived from invoice_id + merchant_solana when reference is omitted), \
             then getTransaction on every successful signature it returned (up to \
             the lookback), summing the exact USDC amount actually received by the \
             merchant across them — so partial payments add up and dust \
             transactions within the lookback cannot hide a real one — and stopping \
             early once expected_usdc is reached. The verdict is an exact integer \
             comparison against expected_usdc with no tolerance: PAID only on the \
             exact amount, otherwise UNDERPAID / OVERPAID. expected_usdc must be a \
             plain decimal like \"27.27\" (dot, no currency symbol); anything else \
             is reported as invalid rather than compared. When part of the scan \
             cannot be read, the tool says so instead of claiming a shortfall. \
             Emits a shareable receipt when paid. \
             Read-only T0: cannot move funds. PIX is marked paid only when the \
             operator sets pix_marked_paid (bank SPI is not visible on-chain). \
             Idempotent and side-effect free, so it is safe to run periodically \
             from a cron job to watch an invoice until it settles; when it \
             reports paid with a confirmed amount the output tells you to remove \
             that cron job."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "invoice_id": {
                        "type": "string",
                        "description": "Invoice id used when deriving the Solana Pay reference (with merchant_solana from config). Must be exactly the unique id the invoice was issued under: the reference is a function of it, so two sales sharing an id cannot be told apart on-chain."
                    },
                    "reference": {
                        "type": "string",
                        "description": "Optional explicit Solana Pay reference (base58). When set, skips derivation."
                    },
                    "expected_usdc": {
                        "type": "string",
                        "description": "Optional expected USDC amount as a plain decimal, e.g. \"27.27\" — dot separator, no currency symbol, no thousands separator. When set, the received amount is compared against it exactly, in the token's minor units and with no tolerance (PAID only on the exact amount, UNDERPAID when even one minor unit short, OVERPAID when more). A value that cannot be parsed is reported as invalid and NOT treated as if it were omitted. Omit entirely to just report the amount received."
                    },
                    "pix_marked_paid": {
                        "type": "boolean",
                        "description": "Operator/PSP signal that PIX bank settlement occurred. This tool cannot verify SPI itself."
                    },
                    "lookback": {
                        "type": "integer",
                        "description": "Max signatures to fetch for the reference (default 25). This is also how far back a payment can be found; at most 64 of them are value-checked per call, and a scan that could not read them all says so rather than reporting a shortfall."
                    }
                }
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
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            if parsed.invoice_id.trim().is_empty()
                && parsed
                    .reference
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .is_none()
            {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "missing invoice_id/reference",
                );
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("invoice_status: provide invoice_id and/or reference".to_string()),
                });
            }

            let cfg = StatusConfig::from_map(&parsed.config);
            let req = StatusRequest {
                invoice_id: parsed.invoice_id,
                reference: parsed.reference,
                expected_usdc: parsed.expected_usdc,
                pix_marked_paid: parsed.pix_marked_paid,
                lookback: parsed.lookback.unwrap_or(DEFAULT_LOOKBACK),
            };

            match fetch_and_status(&req, &cfg, WakiTransport) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "status checked",
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "status check failed",
                    );
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
                function_name: "invoice_status::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(InvoiceStatus);
}
