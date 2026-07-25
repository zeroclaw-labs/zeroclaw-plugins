//! A ZeroClaw WIT tool plugin: `kiosk_charge`.
//!
//! Builds a Solana Pay charge URL for the ProofKiosk. Custody tier T1 with the
//! strongest possible posture: this component imports no network capability
//! and holds no secret — the recipient and prices come from the operator's
//! jailed config section, never from the model.
//!
//! The pure charge core lives in [`charge`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod charge;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::charge::{execute_charge, ChargeArgs, ChargeConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct KioskCharge;

    const PLUGIN_NAME: &str = "kiosk-charge";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "kiosk_charge";

    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct ExecuteArgs {
        item_id: Option<String>,
        amount_usdc: Option<String>,
        note: Option<String>,
        #[serde(rename = "__config")]
        config: HashMap<String, String>,
    }

    impl PluginInfo for KioskCharge {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for KioskCharge {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Create a Solana Pay USDC charge for this kiosk. Use when a customer wants to buy \
             an item or pay an amount. Pass item_id (from the operator's price list) or a \
             decimal amount_usdc within the operator cap. Returns a solana: payment URL, a \
             QR-ready payload, and a reference id for payment confirmation. The recipient \
             address is fixed by operator config and cannot be changed. Before creating the \
             charge, tell the customer the item and USDC amount so they can preview what they \
             are about to pay."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "item_id": {
                        "type": "string",
                        "description": "Item id from the kiosk price list, e.g. `cold_drink`."
                    },
                    "amount_usdc": {
                        "type": "string",
                        "description": "Decimal USDC amount (e.g. \"1.5\") when no item_id is given. Bounded by the operator's max_amount_usdc."
                    },
                    "note": {
                        "type": "string",
                        "description": "Optional short note shown in the customer's wallet."
                    }
                },
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
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
            let cfg = match ChargeConfig::from_section(&parsed.config) {
                Ok(c) => c,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "config rejected",
                    );
                    return Ok(fail(e.to_string()));
                }
            };
            let charge_args = ChargeArgs {
                item_id: parsed.item_id,
                amount_usdc: parsed.amount_usdc,
                note: parsed.note,
            };
            // deny_unknown_fields enforcement for the model-facing surface:
            // re-parse the raw args against the strict struct so smuggled keys
            // (recipient, mint, ...) fail closed even though `__config` rides
            // in the same JSON object.
            if let Err(e) = strict_check(&args) {
                emit(
                    PluginAction::Reject,
                    PluginOutcome::Failure,
                    "unknown field rejected",
                );
                return Ok(fail(e));
            }

            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            match execute_charge(&charge_args, &cfg, reference_bytes(now_ms), now_ms) {
                Ok(out) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "charge created",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: out.summary,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Reject,
                        PluginOutcome::Failure,
                        "charge rejected",
                    );
                    Ok(fail(e.to_string()))
                }
            }
        }
    }

    /// Reject any model-supplied key outside the declared schema.
    fn strict_check(raw: &str) -> Result<(), String> {
        const ALLOWED: [&str; 4] = ["item_id", "amount_usdc", "note", "__config"];
        let v: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("invalid arguments: {e}"))?;
        if let Some(obj) = v.as_object() {
            for key in obj.keys() {
                if !ALLOWED.contains(&key.as_str()) {
                    return Err(format!("unknown argument `{key}` rejected (fail closed)"));
                }
            }
        }
        Ok(())
    }

    /// Correlation reference: 32 bytes derived from time + a process counter
    /// via FNV-1a chaining. The reference is a public lookup tag (it appears
    /// in the payment URL), not a secret — uniqueness, not unpredictability,
    /// is the requirement.
    fn reference_bytes(now_ms: u64) -> [u8; 32] {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut out = [0u8; 32];
        for (i, chunk) in out.chunks_mut(8).enumerate() {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in now_ms
                .to_le_bytes()
                .iter()
                .chain(n.to_le_bytes().iter())
                .chain([i as u8].iter())
            {
                h ^= *b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01B3);
            }
            chunk.copy_from_slice(&h.to_le_bytes());
        }
        out
    }

    fn fail(message: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "kiosk_charge::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(KioskCharge);
}
