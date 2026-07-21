//! A ZeroClaw WIT tool plugin: `squads-proposal-build`.
//!
//! The final stage of the Safe Hands path: independently re-authorizes a
//! transaction against the operator's policy (never trusting caller-supplied
//! verdicts), then builds an unsigned Squads v4 proposal. The agent proposes;
//! multisig members dispose from their own wallets. The plugin holds no keys
//! and signs nothing (T1).
//!
//! The pure proposer core lives in [`propose`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod propose;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::propose;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use safe_hands_core::rpc::{RpcTransport, WakiTransport};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SquadsProposalBuild;

    const PLUGIN_NAME: &str = "squads-proposal-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "squads-proposal-build";

    impl PluginInfo for SquadsProposalBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SquadsProposalBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an unsigned Squads v4 multisig proposal for a transaction that needs human approval. \
             Use when solana-tx-authorize returns REVIEW, or when the operator's policy routes actions \
             to the multisig. This tool independently re-authorizes the transaction against the operator \
             policy before proposing — a caller-supplied ALLOW is never trusted. The agent proposes; \
             multisig members approve from their own wallets. This tool never signs or submits."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "transaction_base64": {
                        "type": "string",
                        "description": "The unsigned transaction (base64) to propose to the multisig. Required."
                    },
                    "intent": {
                        "type": "object",
                        "description": "Declared intent the transaction must match (same contract as solana-tx-authorize).",
                        "properties": {
                            "action": {"type": "string"},
                            "mint": {"type": "string"},
                            "amount_raw": {"type": "string"},
                            "recipient": {"type": "string"},
                            "memo": {"type": "string"}
                        },
                        "required": ["action", "amount_raw", "recipient"]
                    },
                    "decision_record": {
                        "type": "object",
                        "description": "Optional prior verdict object from solana-tx-authorize. Audited, never trusted: if it claims ALLOW while independent re-evaluation disagrees, proposal construction fails closed."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional note attached to the on-chain vault transaction."
                    }
                },
                "required": ["transaction_base64"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let config: HashMap<String, String> = serde_json::from_str::<serde_json::Value>(&args)
                .ok()
                .and_then(|v| v.get("__config").cloned())
                .and_then(|c| serde_json::from_value(c).ok())
                .unwrap_or_default();

            let rpc_url = config.get("rpc_url").cloned().unwrap_or_default();
            let transport: Option<WakiTransport> = if rpc_url.starts_with("https://") {
                Some(WakiTransport::new(rpc_url))
            } else {
                None
            };

            let started = std::time::Instant::now();
            let out = propose::run(&args, transport.as_ref().map(|t| t as &dyn RpcTransport));

            let (action, outcome, level) = if out.success {
                (
                    PluginAction::Complete,
                    PluginOutcome::Success,
                    LogLevel::Info,
                )
            } else {
                (PluginAction::Fail, PluginOutcome::Failure, LogLevel::Warn)
            };
            log_record(
                level,
                &PluginEvent {
                    function_name: "squads_proposal_build::tool::execute".to_string(),
                    action,
                    outcome: Some(outcome),
                    duration_ms: Some(started.elapsed().as_millis() as u64),
                    attrs: None,
                    message: out
                        .error
                        .clone()
                        .unwrap_or_else(|| "proposal built".to_string()),
                },
            );

            Ok(ToolResult {
                success: out.success,
                output: out.output,
                error: out.error,
            })
        }
    }

    export!(SquadsProposalBuild);
}
