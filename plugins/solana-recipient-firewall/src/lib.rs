//! A ZeroClaw T0 WIT tool plugin: `solana_recipient_firewall`.
//!
//! Verifies a Solana recipient address against an operator-pinned address book
//! BEFORE any other plugin builds or signs a transaction. Detects address
//! poisoning (prefix+suffix lookalikes), rejects blocked or invalid addresses,
//! and optionally holds unknown-but-valid addresses for human review.
//!
//! Custody tier: T0 — read-only, no signing, no network, no filesystem, no
//! transaction building. The only permission is `config_read` for the plugin's
//! own jailed config section.
//!
//! The pure firewall core lives in [`firewall`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod firewall;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::firewall::{check_recipient, format_result, FirewallConfig, Verdict};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaRecipientFirewall;

    const PLUGIN_NAME: &str = "solana-recipient-firewall";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_recipient_firewall";

    /// The host merges this plugin's validated config object into the call
    /// arguments under the reserved `__config` key, after deleting any
    /// model-supplied value of that name. It is captured as a raw `Value` so a
    /// config-shaped problem is reported as a config error rather than
    /// collapsing the whole argument parse into "invalid arguments".
    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        candidate: String,
        #[serde(default)]
        claimed_contact: Option<String>,
        #[serde(rename = "__config", default)]
        config: serde_json::Value,
    }

    impl PluginInfo for SolanaRecipientFirewall {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaRecipientFirewall {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Verify a Solana recipient address against the operator's trusted address book. \
             Detects address poisoning (prefix+suffix lookalikes), rejects blocked or invalid \
             addresses, and optionally flags unknown addresses for human review. \
             MUST be called BEFORE any transaction-building tool. \
             Returns ALLOW, HOLD, or REJECT with a detailed reason."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "candidate": {
                        "type": "string",
                        "description": "The Solana recipient address to verify."
                    },
                    "claimed_contact": {
                        "type": "string",
                        "description": "Optional: the label the caller claims this address belongs to (e.g. 'treasury'). If provided, the candidate must match the pinned address for that exact label."
                    }
                },
                "required": ["candidate"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(
                        "execute",
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                        None,
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let cfg = match FirewallConfig::from_json(&parsed.config) {
                Ok(cfg) => cfg,
                Err(e) => {
                    emit(
                        "execute",
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid config",
                        None,
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("config error: {e}")),
                    });
                }
            };

            let result =
                check_recipient(&parsed.candidate, parsed.claimed_contact.as_deref(), &cfg);

            let verdict_str = result.verdict.as_str().to_string();
            let output = format_result(&result);

            let (action, outcome) = match result.verdict {
                Verdict::Allow => (PluginAction::Approve, PluginOutcome::Success),
                Verdict::Hold => (PluginAction::Defer, PluginOutcome::Success),
                Verdict::Reject => (PluginAction::Reject, PluginOutcome::Success),
            };

            emit(
                "execute",
                action,
                outcome,
                &format!("verdict={verdict_str}"),
                None,
            );

            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn emit(
        function_name: &str,
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        _attrs: Option<&str>,
    ) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: function_name.to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaRecipientFirewall);
}
