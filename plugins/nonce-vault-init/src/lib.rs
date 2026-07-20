//! ZeroClaw WIT tool plugin: `nonce_vault_init` (part of the Aval suite).
//!
//! One-time setup: builds the unsigned transaction that creates a durable
//! nonce account ("vault") for the human authority. Custody tier T1 — the
//! plugin never holds a key; the address is seed-derived from the authority
//! so no second keypair ever exists.
//!
//! Pure logic in [`init`]; this file is the wasm shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod core;
pub mod init;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::core::rpc::HttpPost;
    use crate::init::{build_init, parameters_schema, InitArgs};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct NonceVaultInit;

    const PLUGIN_NAME: &str = "nonce-vault-init";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "nonce_vault_init";

    struct WakiHttp;

    impl HttpPost for WakiHttp {
        fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
            let resp = waki::Client::new()
                .post(url)
                .headers([("Content-Type", "application/json")])
                .body(body.as_bytes())
                .send()
                .map_err(|e| format!("rpc request failed: {e}"))?;
            let status = resp.status_code();
            let bytes = resp
                .body()
                .map_err(|e| format!("rpc response unreadable: {e}"))?;
            if !(200..300).contains(&status) {
                return Err(format!("rpc returned HTTP {status}"));
            }
            String::from_utf8(bytes).map_err(|_| "rpc response is not UTF-8".to_string())
        }
    }

    impl PluginInfo for NonceVaultInit {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for NonceVaultInit {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "One-time setup for durable (never-expiring) agent payments: build the unsigned \
             transaction that creates a durable nonce account owned by the human wallet. \
             Holds no keys. Use before the first durable_tx_build call; safe to call again \
             (reports the existing vault instead of rebuilding)."
                .to_string()
        }

        fn parameters_schema() -> String {
            parameters_schema().to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: InitArgs = match serde_json::from_str(&args) {
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

            match build_init(&WakiHttp, &parsed) {
                Ok(outcome) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "vault init handled",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::json!({
                            "summary": outcome.summary,
                            "nonce_account": outcome.nonce_account,
                            "transaction_base64": outcome.transaction_base64,
                        })
                        .to_string(),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "refused or failed",
                    );
                    Ok(fail(e))
                }
            }
        }
    }

    fn fail(error: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "nonce_vault_init::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(NonceVaultInit);
}
