//! sol-transfer-build — ZeroClaw tool plugin (custody tier T1, Build).
//!
//! Builds an UNSIGNED SOL transfer transaction (base64 v0) and returns it for a
//! human/wallet/Squads proposal to sign. No key is ever held. All logic is in
//! [`build`], host-tested; this is the thin wasm shim.

pub mod build;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::build::{build_transfer, sol_to_lamports, BuildParams, DurableNonce};
    use solana_core::pubkey::Pubkey;
    use solana_core::rpc::SolanaRpc;
    use solana_core::transport::WakiTransport;

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct Component;

    const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        from: String,
        to: String,
        #[serde(default)]
        amount_sol: Option<serde_json::Value>,
        #[serde(default)]
        nonce_account: Option<String>,
        #[serde(default)]
        nonce_authority: Option<String>,
        #[serde(default)]
        priority_micro_lamports: Option<u64>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for Component {
        fn plugin_name() -> String {
            "sol-transfer-build".to_string()
        }
        fn plugin_version() -> String {
            "0.1.0".to_string()
        }
    }

    impl Tool for Component {
        fn name() -> String {
            "solana_build_sol_transfer".to_string()
        }

        fn description() -> String {
            "Build an UNSIGNED Solana transaction that transfers native SOL from \
             one account to another. Returns base64 the user signs with their own \
             wallet or approval gate — this tool holds no private key and never \
             submits anything. Optionally attach a durable nonce account so the \
             transaction does not expire while it waits for approval. Use when the \
             user wants to prepare (not send) a SOL transfer for review."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "from": {"type": "string", "description": "Sender / fee-payer address (base58). Its owner signs."},
                    "to": {"type": "string", "description": "Recipient address (base58)."},
                    "amount_sol": {"type": "string", "description": "Amount in SOL, e.g. \"1.5\"."},
                    "nonce_account": {"type": "string", "description": "Optional durable nonce account so the tx never expires in an approval queue."},
                    "nonce_authority": {"type": "string", "description": "Optional nonce authority; defaults to `from`."},
                    "priority_micro_lamports": {"type": "integer", "description": "Optional priority fee (micro-lamports per compute unit)."}
                },
                "required": ["from", "to", "amount_sol"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(fail(format!("invalid arguments: {e}"))),
            };

            let from = match Pubkey::from_base58(parsed.from.trim()) {
                Ok(k) => k,
                Err(e) => return Ok(fail(format!("`from` is not a valid address: {e}"))),
            };
            let to = match Pubkey::from_base58(parsed.to.trim()) {
                Ok(k) => k,
                Err(e) => return Ok(fail(format!("`to` is not a valid address: {e}"))),
            };
            let amount_str = match parsed.amount_sol {
                Some(serde_json::Value::String(s)) => s,
                Some(serde_json::Value::Number(n)) => n.to_string(),
                _ => return Ok(fail("`amount_sol` is required".into())),
            };
            let lamports = match sol_to_lamports(&amount_str) {
                Ok(v) => v,
                Err(e) => return Ok(fail(e.to_string())),
            };

            let durable_nonce = match parsed.nonce_account {
                Some(acc) if !acc.trim().is_empty() => {
                    let account = match Pubkey::from_base58(acc.trim()) {
                        Ok(k) => k,
                        Err(e) => return Ok(fail(format!("`nonce_account` invalid: {e}"))),
                    };
                    let authority = match parsed.nonce_authority.as_deref().map(str::trim) {
                        Some(a) if !a.is_empty() => match Pubkey::from_base58(a) {
                            Ok(k) => Some(k),
                            Err(e) => return Ok(fail(format!("`nonce_authority` invalid: {e}"))),
                        },
                        _ => None,
                    };
                    Some(DurableNonce { account, authority })
                }
                _ => None,
            };

            let rpc_url = parsed
                .config
                .get("rpc_url")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC.to_string());
            let rpc = SolanaRpc::new(WakiTransport::new(rpc_url));

            let params = BuildParams {
                from,
                to,
                lamports,
                durable_nonce,
                priority_micro_lamports: parsed.priority_micro_lamports,
            };

            match build_transfer(&rpc, &params) {
                Ok(out) => {
                    log(
                        LogLevel::Info,
                        PluginAction::Complete,
                        Some(PluginOutcome::Success),
                        "built unsigned SOL transfer",
                    );
                    let output = format!(
                        "{}\n\nUnsigned transaction (base64):\n{}",
                        out.summary, out.transaction_base64
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => Ok(fail(e.to_string())),
            }
        }
    }

    fn fail(msg: String) -> ToolResult {
        log(
            LogLevel::Warn,
            PluginAction::Validate,
            Some(PluginOutcome::Failure),
            &msg,
        );
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(msg),
        }
    }

    fn log(level: LogLevel, action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            level,
            &PluginEvent {
                function_name: "sol_transfer_build::tool::execute".into(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.into(),
            },
        );
    }

    export!(Component);
}
