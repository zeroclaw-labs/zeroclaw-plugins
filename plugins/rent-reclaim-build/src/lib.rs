//! A ZeroClaw WIT tool plugin: `rent_reclaim_build`.
//!
//! T1 (build, no keys). Builds an **unsigned** transaction that closes empty
//! SPL / Token-2022 token accounts and returns their rent-exempt SOL to the
//! wallet owner. A human (or the host's approval gate) signs and submits.
//!
//! Custody invariant: the rent destination is not a parameter — it is always
//! the account owner, enforced inside the pure core (`tx.rs`). A prompt-
//! injected "destination" argument is rejected as an unknown field; a
//! non-empty or foreign account in the close list fails verification and no
//! transaction is produced (fail closed).
//!
//! The pure core lives in [`build`] / [`tx`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test` (RPC mocked); the
//! wasm component reuses the same logic through this shim over `waki`
//! (blocking `wasi:http`).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod build;
pub mod tx;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::build::{build, render, BuildRequest, Rpc, DEFAULT_MAX_CLOSES};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct RentReclaimBuild;

    const PLUGIN_NAME: &str = "rent-reclaim-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "rent_reclaim_build";
    const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

    /// `deny_unknown_fields`: a prompt-injected extra argument (the classic
    /// smuggled `destination`) is a hard error, never silently ignored.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        owner: String,
        #[serde(default)]
        accounts: Option<Vec<String>>,
        #[serde(default)]
        max_accounts: Option<usize>,
        #[serde(default)]
        priority_fee_micro_lamports: Option<u64>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    /// JSON-RPC over the host's `wasi:http` (TLS terminates host-side).
    struct WasiHttpRpc {
        url: String,
    }

    impl Rpc for WasiHttpRpc {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            });
            let resp: serde_json::Value = waki::Client::new()
                .post(&self.url)
                .json(&body)
                .send()
                .map_err(|e| format!("rpc transport error: {e}"))?
                .json()
                .map_err(|e| format!("rpc response not JSON: {e}"))?;
            if let Some(err) = resp.get("error") {
                return Err(format!("rpc error: {err}"));
            }
            resp.get("result")
                .cloned()
                .ok_or_else(|| "rpc response missing result".to_string())
        }
    }

    impl PluginInfo for RentReclaimBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for RentReclaimBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an UNSIGNED Solana transaction that closes empty SPL / Token-2022 \
             token accounts and returns their rent-exempt SOL to the wallet owner. \
             Never signs, never holds keys; the rent destination is always the owner \
             and cannot be changed. Verifies on-chain that every account is empty, \
             unfrozen, and owner-closeable before building; otherwise it refuses. \
             Use rent_reclaim_scan first to see what is reclaimable."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "owner": {
                        "type": "string",
                        "description": "Base58 wallet address that owns the accounts. Also the fee payer, signer, and rent destination."
                    },
                    "accounts": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional explicit token-account addresses to close (max 12). Omit to auto-select the emptiest accounts."
                    },
                    "max_accounts": {
                        "type": "integer",
                        "description": "When auto-selecting: max accounts to close in one transaction (default 8, cap 12)."
                    },
                    "priority_fee_micro_lamports": {
                        "type": "integer",
                        "description": "Optional priority fee in micro-lamports per compute unit."
                    }
                },
                "required": ["owner"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let started = std::time::Instant::now();
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return fail(started, format!("invalid arguments: {e}")),
            };
            let rpc = WasiHttpRpc {
                url: parsed
                    .config
                    .get("rpc_url")
                    .cloned()
                    .unwrap_or_else(|| DEFAULT_RPC_URL.to_string()),
            };
            let req = BuildRequest {
                owner: parsed.owner.clone(),
                accounts: parsed.accounts,
                max_accounts: parsed.max_accounts.unwrap_or(DEFAULT_MAX_CLOSES),
                priority_fee_micro_lamports: parsed.priority_fee_micro_lamports,
            };
            match build(&rpc, &req) {
                Ok(out) => {
                    emit(
                        LogLevel::Info,
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "unsigned close transaction built",
                        Some(started.elapsed().as_millis() as u64),
                        Some(format!(
                            "{{\"closes\":{},\"lamports\":{}}}",
                            out.closed.len(),
                            out.reclaim_lamports
                        )),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: render(&out, &parsed.owner),
                        error: None,
                    })
                }
                Err(e) => fail(started, e),
            }
        }
    }

    fn fail(started: std::time::Instant, error: String) -> Result<ToolResult, String> {
        emit(
            LogLevel::Warn,
            PluginAction::Reject,
            PluginOutcome::Failure,
            &error,
            Some(started.elapsed().as_millis() as u64),
            None,
        );
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        })
    }

    fn emit(
        level: LogLevel,
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        duration_ms: Option<u64>,
        attrs: Option<String>,
    ) {
        log_record(
            level,
            &PluginEvent {
                function_name: "rent_reclaim_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(RentReclaimBuild);
}
