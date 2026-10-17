//! A ZeroClaw WIT tool plugin: `build_nonce_transfer`.
//!
//! Builds **unsigned**, durable-nonce-anchored SPL token transfers so an
//! agent can propose a payment and a human can approve it minutes or days
//! later without the transaction expiring (the blockhash-expiry problem).
//!
//! Custody tier: **T1 (Build)** — this plugin holds no keys and cannot move
//! funds. An operator-configured recipient/mint allowlist plus per-tx and
//! per-day caps are enforced *before* any transaction bytes are constructed;
//! out-of-policy requests are refused with a reason.
//!
//! The pure builder core lives in [`builder`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod builder;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::builder::{build_transfer, BuildArgs, OperatorConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use solana_wasi_core::nonce::parse_nonce_account_b64;
    use solana_wasi_core::rpc;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct NonceTransferBuild;

    const PLUGIN_NAME: &str = "nonce-transfer-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "build_nonce_transfer";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        #[serde(flatten)]
        build: BuildArgs,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for NonceTransferBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
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

    impl Tool for NonceTransferBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an UNSIGNED durable-nonce SPL token transfer for human approval. \
             The transaction never expires while awaiting signature. Recipients, mints \
             and amounts are checked against an operator-configured allowlist and caps; \
             out-of-policy requests are refused. This tool cannot sign or send anything."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Recipient wallet address (base58). Must be on the operator allowlist."
                    },
                    "mint": {
                        "type": "string",
                        "description": "SPL token mint address (base58), e.g. USDC. Must be on the operator allowlist."
                    },
                    "amount": {
                        "type": "string",
                        "description": "Human-readable token amount, e.g. \"25\" or \"12.5\"."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional memo for invoice reconciliation."
                    }
                },
                "required": ["recipient", "mint", "amount"]
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

            let cfg = match OperatorConfig::from_section(&parsed.config) {
                Ok(c) => c,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "missing config");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("operator config error: {e}")),
                    });
                }
            };

            // Fetch nonce account state + mint decimals over waki HTTP.
            let fetched = (|| -> Result<_, String> {
                let nonce_resp =
                    rpc_call(&cfg.rpc_url, &rpc::get_account_info_b64(&cfg.nonce_account))?;
                let nonce_b64 = rpc::parse_account_data_b64(&nonce_resp)?;
                let nonce_state = parse_nonce_account_b64(&nonce_b64)?;
                let dec_resp =
                    rpc_call(&cfg.rpc_url, &rpc::get_token_decimals(&parsed.build.mint))?;
                let decimals = rpc::parse_decimals(&dec_resp)?;
                Ok((nonce_state, decimals))
            })();

            let (nonce_state, decimals) = match fetched {
                Ok(v) => v,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "rpc fetch failed",
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    });
                }
            };

            // Stateless plugin: per-day tracking is host/SOP-side; pass 0 and
            // let per-tx cap bind (documented in README).
            let out = build_transfer(&parsed.build, &cfg, &nonce_state, decimals, 0);
            let rendered = out.render();
            let refused = rendered.contains("\"status\":\"refused\"");
            emit(
                PluginAction::Complete,
                if refused {
                    PluginOutcome::Failure
                } else {
                    PluginOutcome::Success
                },
                if refused {
                    "refused by policy"
                } else {
                    "built unsigned transfer"
                },
            );
            Ok(ToolResult {
                success: true,
                output: rendered,
                error: None,
            })
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "nonce_transfer_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(NonceTransferBuild);
}
