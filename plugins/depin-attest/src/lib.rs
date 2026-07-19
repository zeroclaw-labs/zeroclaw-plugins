//! A ZeroClaw WIT **tool plugin**: `depin-attest`.
//!
//! Palinurus Track C (DePIN) — attests a physical sensor reading to Solana via
//! the Solana Attestation Service (SAS `create_attestation`) with a durable
//! nonce (the blockhash-expiry fix). T1 default (unsigned — human/Squads
//! multisig signs) + T2 opt-in (scoped session key signs + submits with
//! program allowlist + caps + fail-closed injection test).
//!
//! The pure attestation core lives in [`depin_attest`] with no wasm dependency,
//! so it compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod depin_attest;

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

    struct DepinAttest;

    const PLUGIN_NAME: &str = "depin-attest";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "depin_attest";

    impl PluginInfo for DepinAttest {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for DepinAttest {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Attest a physical sensor reading to Solana as a durable-nonce unsigned \
             transaction (SAS create_attestation, memo fallback). The agent proposes; \
             a human or Squads multisig signs. The attestation PDA is cryptographically \
             bound to the reading. Returns the attestation PDA, tx bytes (base64), and \
             a devnet explorer URL in ~200 tokens."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "sensor_id": {
                        "type": "string",
                        "description": "Identifier of the physical sensor (e.g. 'bme280-1')."
                    },
                    "value": {
                        "type": "number",
                        "description": "The numeric reading."
                    },
                    "unit": {
                        "type": "string",
                        "description": "Unit of the reading (e.g. 'celsius', 'hPa', '%RH')."
                    },
                    "timestamp": {
                        "type": "integer",
                        "description": "Unix seconds when the reading was taken."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional human-readable note appended as a memo instruction."
                    }
                },
                "required": ["sensor_id", "value", "unit", "timestamp"]
            })
            .to_string()
        }

        fn execute(_args: String) -> Result<ToolResult, String> {
            emit(
                PluginAction::Start,
                None,
                "execute received args (slice A stub — not implemented)",
            );
            emit(
                PluginAction::Fail,
                Some(PluginOutcome::Failure),
                "depin-attest not implemented yet (slice A scaffold)",
            );

            // Slice A scaffold: the pure core is empty. Slices B–G implement the
            // real flow (config → nonce → ix → durable-nonce → serialize → shape).
            Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("depin-attest: not implemented (slice A scaffold)".to_string()),
            })
        }
    }

    fn emit(action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "depin_attest::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(DepinAttest);
}