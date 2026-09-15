//! ZeroClaw T2 tool plugin: `solana-keychain-sign`.
//!
//! Multi-backend signing service for Solana versioned transactions. Takes a
//! pre-validated unsigned versioned transaction (base64) produced by
//! `solana-build-tx`, re-fetches a fresh blockhash at sign time (the answer
//! to bounty Trap #1), posts the message bytes to the configured backend
//! (HashiCorp Vault transit in v0; AWS KMS / GCP KMS stubbed), attaches the
//! signature, submits via RPC, and polls for confirmation.
//!
//! ## Custody tier
//!
//! **T2 — signs and submits.** The ZeroClaw process sees only signature
//! bytes; the Ed25519 private key lives exclusively inside the configured
//! backend (Vault transit HSM in v0). All transaction-content validation
//! lives in the `solana-build-tx` plugin via simulation-based policy; this
//! plugin's [`envelope`] module enforces ONLY shape guards (size, instruction
//! count, fee-payer match).
//!
//! ## Build
//!
//! ```text
//! rustup target add wasm32-wasip2
//! cargo build --target wasm32-wasip2 --release
//! ```
//!
//! ## Status (v0 scaffold)
//!
//! This is the **scaffold** (`zeroclaw-solana-bounty-67ip`). The crate
//! layout, manifest, dependency manifest, WIT component shim, and module
//! seams are all in place. Descendant beans own the implementations:
//!
//!   - `rpc.rs` — DONE (`zeroclaw-solana-bounty-4c1h`): waki JSON-RPC client
//!     for `getLatestBlockhash`, `sendTransaction`, `getSignatureStatuses`,
//!     plus the `submit_and_confirm` orchestrator.
//!   - `backends/aws_kms.rs` — DONE (`zeroclaw-solana-bounty-5ev1`): STUB
//!     with shape helpers + `NotImplemented` SignerBackend impl + SigV4 plan.
//!   - `backends/mod.rs` — SignerBackend trait + `SignerError` ship here.
//!   - `backends/vault.rs` — STUB (`zeroclaw-solana-bounty-m4wx` owns the
//!     full waki HTTP impl).
//!   - `backends/gcp_kms.rs` — STUB (`zeroclaw-solana-bounty-88iq` owns the
//!     STUB shape helpers + OAuth2 plan).
//!   - `envelope.rs` — STUB (`zeroclaw-solana-bounty-pptg` owns the three
//!     envelope guards).
//!   - `submit.rs` — STUB (`zeroclaw-solana-bounty-s37c` owns the
//!     fresh-blockhash → sign → submit → poll flow).
//!   - Factory + `SignerBackend` selection — `zeroclaw-solana-bounty-7p6z`.
//!   - Full plugin host tests — `zeroclaw-solana-bounty-ylkw`.

pub mod backends;
pub mod envelope;
pub mod rpc;
pub mod submit;

// ── wasm component shim ─────────────────────────────────────────────────────
//
// The host loads this module only for the `wasm32-wasip2` target. Host tests
// compile against the rlib above and never reach in here, so they pull in no
// `waki`, no `wit-bindgen`, no `wasi:http`.

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    use crate::envelope::EnvelopeConfig;
    use crate::submit::{execute, output_json, SignerConfig, SignerInput};

    struct SolanaKeychainSign;

    const PLUGIN_NAME: &str = "solana-keychain-sign";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana-keychain-sign";

    impl PluginInfo for SolanaKeychainSign {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaKeychainSign {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Sign and submit a Solana versioned transaction via a configured backend \
             (HashiCorp Vault transit in v0; AWS KMS / GCP KMS stubbed). Takes a base64 \
             unsigned tx produced by solana-build-tx, re-fetches a fresh blockhash at \
             sign time, posts the message bytes to the backend for signing, attaches the \
             signature, submits via RPC, and polls for confirmation. The private key \
             never enters the ZeroClaw process."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "instructions_base64": {
                        "type": "string",
                        "description": "Base64-encoded unsigned versioned transaction payload \
                                        produced by solana-build-tx."
                    }
                },
                "required": ["instructions_base64"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            // Parse the inbound JSON envelope. `__config` is host-injected
            // when the manifest declares `config_read` (it does). Missing
            // args / malformed JSON is a hard fail with a structured log.
            let parsed: SignerInput = match serde_json::from_str(&args) {
                Ok(p) => p,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        &format!("invalid arguments: {e}"),
                        None,
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            // Operator config unwrap + factory wiring land with `7p6z`. Until
            // then the scaffold dispatches against `SignerConfig::default()`
            // so the wasm component still builds + loads in the daemon.
            let cfg = SignerConfig {
                envelope: EnvelopeConfig::default(),
                rpc_url: String::new(),
                confirm_timeout_secs: 0,
            };

            match execute(&parsed, &cfg) {
                Ok(out) => {
                    let output = output_json(&out).to_string();
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "signed and submitted",
                        Some(out.slot),
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(reason) => {
                    emit(PluginAction::Reject, PluginOutcome::Failure, &reason, None);
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(reason),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, slot: Option<u64>) {
        let attrs = slot.map(|s| format!("{{\"slot\":{s}}}"));
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_keychain_sign::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaKeychainSign);
}
