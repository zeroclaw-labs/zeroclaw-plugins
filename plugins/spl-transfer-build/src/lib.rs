//! A ZeroClaw WIT tool plugin: `spl_transfer_build`.
//!
//! Builds an **unsigned** versioned transaction moving SPL tokens or native
//! SOL from the operator's wallet — custody tier T1: the component holds no
//! key material and cannot submit anything; the base64 it returns must be
//! signed by the owner wallet (or a ZeroClaw approval gate + host signer).
//! Mint allowlist, per-transfer cap, optional recipient allowlist, and
//! Token-2022 screening are enforced in the pure [`transfer`] core, below the
//! LLM. An optional durable nonce account removes blockhash expiry so a human
//! can approve from their phone an hour later.
//!
//! The pure core is host-tested against a mock RPC with plain `cargo test`;
//! this file is the thin component shim wiring it to the `tool-plugin` WIT
//! world with the blocking `waki` client (TLS is performed host-side).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod transfer;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::transfer::{build_transfer, TransferArgs, TransferConfig};
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
                .body(body.as_bytes().to_vec())
                .send()
                .map_err(|e| format!("rpc request failed: {e}"))?;
            let bytes = response
                .body()
                .map_err(|e| format!("rpc response read failed: {e}"))?;
            String::from_utf8(bytes).map_err(|_| "rpc response is not UTF-8".to_string())
        }
    }

    struct SplTransferBuild;

    const PLUGIN_NAME: &str = "spl-transfer-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "spl_transfer_build";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        recipient: String,
        amount: String,
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        memo: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SplTransferBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SplTransferBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an UNSIGNED Solana transaction transferring tokens from the operator's \
             wallet to a recipient. Returns base64 for the owner to review and sign — this \
             tool cannot sign or submit anything. The sending wallet, allowed tokens, \
             per-transfer cap, and (optionally) allowed recipients are fixed by operator \
             config; transfers outside that policy are refused. Handles recipient token \
             account creation and an optional on-chain memo."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Recipient wallet address (base58)."
                    },
                    "amount": {
                        "type": "string",
                        "description": "Decimal amount in token units, e.g. \"25\" or \"0.5\"."
                    },
                    "token": {
                        "type": "string",
                        "description": "Token symbol from the operator allowlist (default: first allowlisted token, usually USDC)."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional on-chain memo, e.g. an invoice number for reconciliation."
                    }
                },
                "required": ["recipient", "amount"]
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

            let cfg = match TransferConfig::from_section(&parsed.config) {
                Ok(c) => c,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "bad config");
                    return Ok(fail(e));
                }
            };

            let transfer_args = TransferArgs {
                recipient: parsed.recipient,
                amount: parsed.amount,
                token: parsed.token,
                memo: parsed.memo,
            };

            match build_transfer(&WakiTransport, &transfer_args, &cfg) {
                Ok(built) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "unsigned transfer built",
                    );
                    Ok(clamp(ToolResult {
                        success: true,
                        output: format!(
                            "{}\nunsigned_transaction_base64: {}",
                            built.summary, built.transaction_base64
                        ),
                        error: None,
                    }))
                }
                Err(e) => {
                    // Guardrail refusals and RPC failures both fail closed;
                    // nothing is ever built "approximately".
                    emit(
                        PluginAction::Reject,
                        PluginOutcome::Failure,
                        "transfer build refused",
                    );
                    Ok(fail(e))
                }
            }
        }
    }

    /// Final backstop: no ToolResult exceeds this, whatever the inputs. A
    /// valid transfer is ~1.7 KB base64 + a short summary; the core bounds
    /// every field, and this guarantees it at the WIT edge.
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
                function_name: "spl_transfer_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SplTransferBuild);
}
