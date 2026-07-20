//! A ZeroClaw WIT **tool** plugin: `depin-attest`.
//!
//! Turns a ZeroClaw host device (e.g. a Raspberry Pi with a sensor) into a
//! Solana-reporting DePIN node. Given a sensor reading, it fetches the
//! current slot and a recent blockhash from a Solana RPC endpoint, builds a
//! Memo-program instruction committing the reading, and returns an
//! **unsigned** v0 transaction encoded as base64 plus a replay-guard nonce.
//!
//! Custody tier: **T1** — this plugin never holds or uses a private key. It
//! only ever returns unsigned bytes; a human (or an out-of-band approval
//! gate) must sign and submit them.
//!
//! The pure core lives in [`attest`], [`memo`], and [`tx`] with no wasm
//! dependency, so it compiles and tests on the host with a plain
//! `cargo test`; the wasm component reuses the exact same logic through this
//! shim and only adds the wasi:http RPC calls.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod attest;
pub mod memo;
pub mod tx;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde_json::Value;

    use crate::attest::{attestation_hash, build_memo, derive_nonce, hex_encode, AttestArgs, AttestResult};
    use crate::memo::memo_instruction;
    use crate::tx::{base64_encode, serialize, UnsignedTx};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

    struct DepinAttest;

    const PLUGIN_NAME: &str = "depin-attest";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "depin_attest";
    const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

    /// Split the raw JSON args into the typed [`AttestArgs`] and the injected
    /// `__config` map. Deliberately not `#[serde(flatten)]`: flatten's
    /// unknown-field handling interacts poorly with `deny_unknown_fields` on
    /// the inner struct, and this tool's fail-closed guarantee against
    /// prompt-injected extra fields depends on that check being reliable.
    fn split_execute_args(args_json: &str) -> Result<(AttestArgs, HashMap<String, String>), String> {
        let mut obj: Value = serde_json::from_str(args_json).map_err(|e| e.to_string())?;
        let config = obj
            .as_object_mut()
            .and_then(|m| m.remove("__config"))
            .map(|v| serde_json::from_value(v).map_err(|e| e.to_string()))
            .transpose()?
            .unwrap_or_default();
        let attest: AttestArgs = serde_json::from_value(obj).map_err(|e| e.to_string())?;
        Ok((attest, config))
    }

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
            "Read a device sensor reading and build an unsigned Solana Memo transaction \
             attesting it on-chain, with a replay-guard nonce. Custody tier T1: this tool \
             never holds or uses a private key — it returns unsigned transaction bytes for \
             a human or approval gate to sign and submit."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "device_id": {
                        "type": "string",
                        "maxLength": 64,
                        "description": "Identifier of the reporting device, e.g. \"pi-node-001\"."
                    },
                    "sensor_type": {
                        "type": "string",
                        "enum": ["temperature", "humidity", "uptime", "energy_kwh", "custom"]
                    },
                    "value": { "type": "number" },
                    "unit": { "type": "string", "maxLength": 16 }
                },
                "required": ["device_id", "sensor_type", "value", "unit"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let (attest_args, config) = match split_execute_args(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid arguments", None);
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let rpc_url = config.get("rpc_url").map(String::as_str).unwrap_or(DEFAULT_RPC_URL);

            let (slot, blockhash) = match fetch_latest_blockhash(rpc_url) {
                Ok(v) => v,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "rpc fetch failed", None);
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("rpc fetch failed: {e}")),
                    });
                }
            };

            let nonce = derive_nonce(&attest_args.device_id, slot);
            let memo_text = build_memo(&attest_args, slot, &nonce);
            let instr = memo_instruction(&memo_text);
            let tx = UnsignedTx {
                fee_payer: [0u8; 32],
                recent_blockhash: blockhash,
                instruction: instr,
            };
            let tx_b64 = base64_encode(&serialize(&tx));
            let nonce_hex = hex_encode(&nonce);

            let result = AttestResult {
                unsigned_tx_b64: tx_b64,
                attestation_hash: hex_encode(&attestation_hash(&memo_text)),
                memo_payload: memo_text.clone(),
                replay_nonce: nonce_hex.clone(),
                custody_tier: "T1",
                summary: format!(
                    "Attestation built for {} ({}: {:.4} {}) at slot {}. Unsigned — sign with \
                     your wallet and submit to commit on-chain. Nonce: {}...",
                    attest_args.device_id,
                    attest_args.sensor_type,
                    attest_args.value,
                    attest_args.unit,
                    slot,
                    &nonce_hex[..16],
                ),
            };

            let output = match serde_json::to_string(&result) {
                Ok(s) => s,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "serialization failed", None);
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    });
                }
            };

            emit(PluginAction::Complete, PluginOutcome::Success, "built unsigned attestation tx", Some(slot));

            Ok(ToolResult { success: true, output, error: None })
        }
    }

    /// `getLatestBlockhash` — returns `(context.slot, decoded blockhash)`. This
    /// is the only chain state the plugin reads; it never queries balances,
    /// signs, or submits anything.
    fn fetch_latest_blockhash(rpc_url: &str) -> Result<(u64, [u8; 32]), String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "finalized"}]
        });

        let resp = waki::Client::new()
            .post(rpc_url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;

        let val: Value = resp.json().map_err(|e| e.to_string())?;

        let slot = val["result"]["context"]["slot"]
            .as_u64()
            .ok_or("missing result.context.slot")?;
        let blockhash_b58 = val["result"]["value"]["blockhash"]
            .as_str()
            .ok_or("missing result.value.blockhash")?;

        let decoded = base58_decode(blockhash_b58)?;
        let mut out = [0u8; 32];
        if decoded.len() != 32 {
            return Err(format!("unexpected blockhash length: {}", decoded.len()));
        }
        out.copy_from_slice(&decoded);
        Ok((slot, out))
    }

    /// Minimal base58 decoder (Bitcoin alphabet), no external dependency.
    fn base58_decode(input: &str) -> Result<Vec<u8>, String> {
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut bytes = vec![0u8; input.len()];
        let mut len = 0usize;
        for c in input.chars() {
            let mut carry = ALPHABET
                .iter()
                .position(|&b| b == c as u8)
                .ok_or_else(|| format!("invalid base58 char: {c}"))? as u32;
            for byte in bytes.iter_mut().take(len) {
                carry += (*byte as u32) * 58;
                *byte = (carry & 0xff) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                bytes[len] = (carry & 0xff) as u8;
                len += 1;
                carry >>= 8;
            }
        }
        for c in input.chars() {
            if c == '1' {
                bytes[len] = 0;
                len += 1;
            } else {
                break;
            }
        }
        bytes.truncate(len);
        bytes.reverse();
        Ok(bytes)
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, slot: Option<u64>) {
        let attrs = slot.map(|s| format!("{{\"slot\":{s}}}"));
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "depin_attest::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(DepinAttest);
}
