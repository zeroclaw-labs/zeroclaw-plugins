//! ZeroClaw's `spl-transfer-build` WIT tool component.
//!
//! The transaction builder itself lives in [`core`], which has no WASM or host
//! dependencies and is exercised by `cargo test` on the native target. This
//! file contains the thin component adapter that is compiled only for
//! `wasm32-wasip2`.

pub mod core;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde::Deserialize;

    use crate::core::{
        build_transfer, CoreError, Pubkey, RpcClient, TransferArgs, TransferPolicy,
        PARAMETERS_SCHEMA,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "spl-transfer-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "spl_transfer_build";
    // Keep an explicit request path. Some WASI HTTP hosts reject an absolute
    // URL whose path is absent, even though native HTTP clients accept it.
    const DEFAULT_RPC_URL: &str = "https://api.devnet.solana.com/";

    struct SplTransferBuild;

    /// The host injects this plugin's config section as `__config`. Keeping it
    /// in the tool arguments means the component has no ambient config access.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        sender: String,
        recipient: String,
        mint: String,
        amount: String,
        decimals: u8,
        memo: Option<String>,
        #[serde(default)]
        token_2022: bool,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl ExecuteArgs {
        fn transfer_args(&self) -> TransferArgs {
            TransferArgs {
                sender: self.sender.clone(),
                recipient: self.recipient.clone(),
                mint: self.mint.clone(),
                amount: self.amount.clone(),
                decimals: self.decimals,
                memo: self.memo.clone(),
                token_2022: self.token_2022,
            }
        }

        fn rpc_url(&self) -> String {
            self.config
                .get("rpc_url")
                .filter(|url| !url.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC_URL.to_string())
        }

        fn policy(&self) -> Result<TransferPolicy, CoreError> {
            TransferPolicy::from_config(self.config.get("allowed_recipients").map(String::as_str))
        }
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
            "Build an unsigned SPL token transfer transaction. It derives associated token \
             accounts, includes idempotent destination-ATA creation, and returns a base64 \
             transaction and approval-ready summary. This tool never signs or holds keys."
                .to_string()
        }

        fn parameters_schema() -> String {
            PARAMETERS_SCHEMA.to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            emit(
                PluginAction::Start,
                None,
                "building unsigned SPL transfer",
                None,
            );

            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(parsed) => parsed,
                Err(error) => return failure(format!("invalid arguments: {error}")),
            };

            let policy = match parsed.policy() {
                Ok(policy) => policy,
                Err(error) => return failure(error.to_string()),
            };
            let rpc = HostRpcClient::new(parsed.rpc_url());
            let result = match build_transfer(&parsed.transfer_args(), &rpc, &policy) {
                Ok(result) => result,
                Err(error) => return failure(error.to_string()),
            };
            let output = match serde_json::to_string(&result) {
                Ok(output) => output,
                Err(error) => return failure(format!("failed to serialize transfer: {error}")),
            };

            emit(
                PluginAction::Complete,
                Some(PluginOutcome::Success),
                "built unsigned SPL transfer",
                Some(format!(
                    "{{\"destination_ata_will_be_created\":{}}}",
                    result.destination_ata_will_be_created
                )),
            );

            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn failure(message: String) -> Result<ToolResult, String> {
        emit(
            PluginAction::Fail,
            Some(PluginOutcome::Failure),
            "failed to build unsigned SPL transfer",
            Some(format!("{{\"error\":{}}}", json_string(&message))),
        );
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        })
    }

    fn json_string(value: &str) -> String {
        serde_json::to_string(value).unwrap_or_else(|_| "\"serialization error\"".to_string())
    }

    fn emit(
        action: PluginAction,
        outcome: Option<PluginOutcome>,
        message: &str,
        attrs: Option<String>,
    ) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "spl_transfer_build::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    /// RPC adapter implemented with `wasi:http` through `waki`. The core only
    /// sees this as an `RpcClient`, so tests can supply a local mock instead.
    struct HostRpcClient {
        rpc_url: String,
    }

    impl HostRpcClient {
        fn new(rpc_url: String) -> Self {
            Self { rpc_url }
        }

        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, CoreError> {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            });
            let response = waki::Client::new()
                .post(&self.rpc_url)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .map_err(|error| CoreError::Rpc(format!("HTTP request failed: {error}")))?;
            let value = response
                .json::<serde_json::Value>()
                .map_err(|error| CoreError::Rpc(format!("invalid JSON-RPC response: {error}")))?;
            if let Some(error) = value.get("error") {
                return Err(CoreError::Rpc(format!("RPC returned an error: {error}")));
            }
            Ok(value)
        }
    }

    impl RpcClient for HostRpcClient {
        fn get_latest_blockhash(&self) -> Result<[u8; 32], CoreError> {
            let value = self.call(
                "getLatestBlockhash",
                serde_json::json!([{"commitment": "finalized"}]),
            )?;
            let blockhash = value
                .pointer("/result/value/blockhash")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CoreError::Rpc("missing blockhash in RPC response".to_string()))?;
            let bytes = bs58::decode(blockhash)
                .into_vec()
                .map_err(|_| CoreError::Rpc("blockhash is not valid base58".to_string()))?;
            bytes
                .try_into()
                .map_err(|_| CoreError::Rpc("blockhash is not 32 bytes".to_string()))
        }

        fn account_exists(&self, pubkey: &Pubkey) -> Result<bool, CoreError> {
            let value = self.call(
                "getAccountInfo",
                serde_json::json!([pubkey.to_base58(), {"encoding": "base64"}]),
            )?;
            value
                .pointer("/result/value")
                .map(|account| !account.is_null())
                .ok_or_else(|| CoreError::Rpc("missing account value in RPC response".to_string()))
        }
    }

    export!(SplTransferBuild);
}
