//! A ZeroClaw WIT tool plugin: `solana_build_transfer`.
//!
//! Turns "pay Marta 25 USDC for invoice 412" into an unsigned, simulated,
//! base64 transaction plus a summary a human can read on a phone — and refuses,
//! in the plugin, anything outside the operator's spend caps.
//!
//! Custody tier **T1**. It holds no key and cannot sign. The output is inert
//! until a wallet, a hardware device, or a Squads multisig signs it. The
//! sender's address in config is a public key.
//!
//! The security boundary is `config.toml`, not the conversation. A per-mint
//! spend cap doubles as the allowlist, so a mint with no cap cannot be sent at
//! all; there is no tool argument that raises a cap, adds a mint, changes the
//! sender, or disables the simulation. An agent that has been talked into
//! anything can still only ask for a transfer that policy already allows.
//!
//! The pure core lives in [`build`] with no wasm dependency, so it compiles and
//! tests on the host with a plain `cargo test`; the component reuses the exact
//! same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod build;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    // Imported by name, not via the prelude: a glob would pull in the crate's
    // `Result` alias and shadow the `Result<ToolResult, String>` this WIT
    // export has to return.
    use solana_wasi::pubkey::Pubkey;
    use solana_wasi::rpc::RpcClient;
    use solana_wasi::transport::WakiTransport;

    use crate::build::{build, Outcome, TransferConfig, TransferRequest};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SplTransferBuild;

    const PLUGIN_NAME: &str = "spl-transfer-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_build_transfer";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        recipient: String,
        amount: String,
        #[serde(default)]
        mint: Option<String>,
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
            "Build an UNSIGNED Solana transfer of SOL or an SPL token for a human to \
             approve. Nothing is signed and nothing is sent: this returns a base64 \
             transaction and a summary. Per-mint spend caps are enforced inside the \
             plugin from the operator's config file and cannot be raised, bypassed, or \
             disabled by anything in this conversation. Send to the recipient's WALLET \
             address, never to a token account."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "The recipient's wallet address, base58. Not a token account."
                    },
                    "amount": {
                        "type": "string",
                        "description": "Amount in whole tokens, as a plain decimal string, e.g. \"25.5\"."
                    },
                    "mint": {
                        "type": "string",
                        "description": "The SPL mint address. Omit for native SOL."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional short reference written permanently to the public ledger, e.g. an invoice number."
                    }
                },
                "required": ["recipient", "amount"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(fail(format!("invalid arguments: {e}"), "invalid arguments")),
            };

            let cfg = TransferConfig::from_section(&parsed.config);

            let recipient = match Pubkey::from_base58(parsed.recipient.trim()) {
                Ok(r) => r,
                Err(e) => return Ok(fail(e.to_string(), "recipient is not an address")),
            };
            let mint = match parsed.mint.as_deref().map(str::trim).filter(|m| !m.is_empty()) {
                Some(m) => match Pubkey::from_base58(m) {
                    Ok(k) => Some(k),
                    Err(e) => return Ok(fail(e.to_string(), "mint is not an address")),
                },
                None => None,
            };

            let request = TransferRequest {
                recipient,
                amount: parsed.amount.clone(),
                mint,
                memo: parsed.memo.clone(),
            };

            let rpc = RpcClient::new(cfg.rpc_url.clone(), WakiTransport::new());

            match build(&rpc, &request, &cfg) {
                Ok(Outcome::Built(built)) => {
                    emit(
                        LogLevel::Info,
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "built an unsigned transfer",
                        Some(format!(
                            "{{\"to\":\"{}\",\"digest\":\"{}\",\"durable\":{}}}",
                            recipient.abbreviated(),
                            built.digest,
                            built.durable
                        )),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: format!(
                            "{}\n\nbase64 transaction (unsigned):\n{}",
                            built.summary, built.transaction_base64
                        ),
                        error: None,
                    })
                }
                // A refusal is a policy decision, and it is logged as `reject`
                // so an operator can see what their caps actually stopped.
                Ok(Outcome::Refused(refusal)) => {
                    emit(
                        LogLevel::Warn,
                        PluginAction::Reject,
                        PluginOutcome::Failure,
                        "refused by policy",
                        Some(format!("{{\"code\":\"{}\"}}", refusal.code)),
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("refused ({}): {}", refusal.code, refusal.reason)),
                    })
                }
                // The endpoint may carry an API key, so report the failure
                // without it. `safe_endpoint` is the only form allowed out.
                Err(e) => Ok(fail(
                    format!("{e} (endpoint {})", rpc.safe_endpoint()),
                    "build failed",
                )),
            }
        }
    }

    fn fail(error: String, message: &str) -> ToolResult {
        emit(
            LogLevel::Warn,
            PluginAction::Fail,
            PluginOutcome::Failure,
            message,
            None,
        );
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    fn emit(
        level: LogLevel,
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        attrs: Option<String>,
    ) {
        log_record(
            level,
            &PluginEvent {
                function_name: "spl_transfer_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(SplTransferBuild);
}
