//! A ZeroClaw WIT tool plugin: `rent_reclaim_scan`.
//!
//! T0 (read-only). Scans a wallet for empty SPL / Token-2022 token accounts
//! and reports how much rent-exempt SOL is locked in them. Companion to
//! `rent-reclaim-build`, which turns the scan into an unsigned close
//! transaction that a human signs.
//!
//! The pure scan core lives in [`scan`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test` (RPC is mocked
//! behind the `Rpc` trait); the wasm component reuses the exact same logic
//! through this shim, with `waki` (blocking `wasi:http`) as the transport.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod scan;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::scan::{render, scan, Rpc, DEFAULT_MAX_LISTED};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct RentReclaimScan;

    const PLUGIN_NAME: &str = "rent-reclaim-scan";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "rent_reclaim_scan";
    const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

    /// `deny_unknown_fields`: a prompt-injected extra argument (e.g. a
    /// smuggled `destination`) is a hard error, never silently ignored.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        owner: String,
        #[serde(default)]
        max_listed: Option<usize>,
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

    impl PluginInfo for RentReclaimScan {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for RentReclaimScan {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Scan a Solana wallet for empty SPL / Token-2022 token accounts and report \
             the rent-exempt SOL locked in them (read-only, no keys, no transactions). \
             Use before rent_reclaim_build, which creates an unsigned transaction that \
             closes the empty accounts and returns the rent to the wallet owner."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "owner": {
                        "type": "string",
                        "description": "Base58 wallet address to scan."
                    },
                    "max_listed": {
                        "type": "integer",
                        "description": "Max accounts to list in the report (default 10, cap 20)."
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
            match scan(&rpc, &parsed.owner) {
                Ok(report) => {
                    let output = render(
                        &report,
                        &parsed.owner,
                        parsed.max_listed.unwrap_or(DEFAULT_MAX_LISTED),
                    );
                    emit(
                        LogLevel::Info,
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "scan complete",
                        Some(started.elapsed().as_millis() as u64),
                        Some(format!(
                            "{{\"empty\":{},\"lamports\":{}}}",
                            report.empty_closeable.len(),
                            report.reclaimable_lamports()
                        )),
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
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
            PluginAction::Fail,
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
                function_name: "rent_reclaim_scan::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(RentReclaimScan);
}
