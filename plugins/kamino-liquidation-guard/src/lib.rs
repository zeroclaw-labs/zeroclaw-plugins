//! ZeroClaw T0 tool plugin: `kamino-liquidation-guard`.
//!
//! The pure validation and classification logic lives in [`guard`]. This file
//! is the thin `wasm32-wasip2` shim: it accepts one wallet, calls an
//! operator-configured Solana RPC and the fixed Kamino HTTPS endpoint through
//! `wasi:http`, bounds every response, and returns a compact fail-closed report.

pub mod guard;

/// Manifest/package identity. Cargo metadata is the source of truth.
pub const PLUGIN_PACKAGE_ID: &str = env!("CARGO_PKG_NAME");
/// Immutable release identity. Cargo metadata is the source of truth.
pub const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
/// WIT tool identity exposed to the model. It intentionally matches the
/// package ID for this one-tool component, but remains a distinct interface.
pub const EXPORTED_TOOL_NAME: &str = PLUGIN_PACKAGE_ID;

#[cfg(target_family = "wasm")]
mod component {
    use std::collections::HashMap;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::guard::{
        append_bounded, discover_obligations, evaluate_loans_in_window,
        validate_discovery_transition, validate_mainnet_genesis, validate_public_key, GuardConfig,
        GuardReport, KLEND_PROGRAM_ID, MAX_OBLIGATIONS, OBLIGATION_DATA_SLICE_BYTES,
        OBLIGATION_DISCRIMINATOR_B58,
    };
    use crate::{EXPORTED_TOOL_NAME, PLUGIN_PACKAGE_ID, PLUGIN_VERSION};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    const KAMINO_API_BASE: &str = "https://api.kamino.finance";
    const GENESIS_LIMIT_BYTES: usize = 4_096;
    const RPC_LIMIT_BYTES: usize = 65_536;
    const LOAN_LIMIT_BYTES: usize = 131_072;
    const READ_CHUNK_BYTES: u64 = 16_384;
    const CONNECT_TIMEOUT_SECONDS: u64 = 5;

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        wallet: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct KaminoLiquidationGuard;

    impl PluginInfo for KaminoLiquidationGuard {
        fn plugin_name() -> String {
            PLUGIN_PACKAGE_ID.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for KaminoLiquidationGuard {
        fn name() -> String {
            EXPORTED_TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Enumerate a wallet's known Kamino KLend obligations on Solana and return a compact, \
             fail-closed liquidation-risk status. The tool is T0 read-only: it never builds, \
             signs, or submits transactions. The Kamino API host is fixed; the mainnet RPC, \
             freshness, and health thresholds come only from operator config."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "wallet": {
                        "type": "string",
                        "description": "Solana wallet public key in canonical base58 form.",
                        "minLength": 32,
                        "maxLength": 44
                    }
                },
                "required": ["wallet"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(_) => return Ok(argument_failure("invalid arguments")),
            };
            if !validate_public_key(&parsed.wallet) {
                return Ok(argument_failure(
                    "wallet must be a 32-byte base58 public key",
                ));
            }
            let config = match GuardConfig::from_section(&parsed.config) {
                Ok(value) => value,
                Err(error) => return Ok(argument_failure(error.message)),
            };
            let genesis_body = match post_json_bounded(
                &config.solana_rpc_url,
                br#"{"jsonrpc":"2.0","id":0,"method":"getGenesisHash"}"#,
                GENESIS_LIMIT_BYTES,
            ) {
                Ok(body) => body,
                Err(reason) => return Ok(unknown_result(reason)),
            };
            if let Err(error) = validate_mainnet_genesis(&genesis_body) {
                return Ok(unknown_result(error.message));
            }
            let discovery_request = solana_discovery_request(&parsed.wallet, None);
            let discovery_body = match post_json_bounded(
                &config.solana_rpc_url,
                &discovery_request,
                RPC_LIMIT_BYTES,
            ) {
                Ok(body) => body,
                Err(reason) => return Ok(unknown_result(reason)),
            };
            let discovery = match discover_obligations(&discovery_body, &parsed.wallet) {
                Ok(value) => value,
                Err(error) => return Ok(unknown_result(error.message)),
            };
            if discovery.obligations.len() > MAX_OBLIGATIONS {
                return Ok(unknown_result("obligation count exceeds the safety bound"));
            }

            let mut loan_bodies = Vec::with_capacity(discovery.obligations.len());
            for obligation in &discovery.obligations {
                let url = format!("{KAMINO_API_BASE}/klend/loans/{}", obligation.obligation);
                match get_json_bounded(&url, LOAN_LIMIT_BYTES) {
                    Ok(body) => loan_bodies.push(body),
                    Err(reason) => return Ok(unknown_result(reason)),
                }
            }

            // Re-enumerate after the sequential loan requests. A position
            // opened, closed, or migrated during the assessment must not be
            // silently omitted from a green result.
            let final_discovery_request =
                solana_discovery_request(&parsed.wallet, Some(discovery.solana_slot));
            let final_discovery_body = match post_json_bounded(
                &config.solana_rpc_url,
                &final_discovery_request,
                RPC_LIMIT_BYTES,
            ) {
                Ok(body) => body,
                Err(reason) => return Ok(unknown_result(reason)),
            };
            let final_discovery = match discover_obligations(&final_discovery_body, &parsed.wallet)
            {
                Ok(value) => value,
                Err(error) => return Ok(unknown_result(error.message)),
            };
            if let Err(error) = validate_discovery_transition(&discovery, &final_discovery) {
                return Ok(unknown_result(error.message));
            }
            if final_discovery.obligations.is_empty() {
                return Ok(success_result(GuardReport::no_debt(
                    None,
                    Some(final_discovery.solana_slot),
                )));
            }
            let now_ms = match unix_time_ms() {
                Ok(value) => value,
                Err(reason) => return Ok(unknown_result(reason)),
            };
            match evaluate_loans_in_window(
                &parsed.wallet,
                discovery.solana_slot,
                &final_discovery,
                &loan_bodies,
                now_ms,
                &config,
            ) {
                Ok(report) => Ok(success_result(report)),
                Err(error) => Ok(unknown_result(error.message)),
            }
        }
    }

    fn solana_discovery_request(wallet: &str, min_context_slot: Option<u64>) -> Vec<u8> {
        let mut config = serde_json::json!({
            "commitment": "confirmed",
            "encoding": "base64",
            "withContext": true,
            "filters": [
                {
                    "memcmp": {
                        "offset": 0,
                        "bytes": OBLIGATION_DISCRIMINATOR_B58
                    }
                },
                {
                    "memcmp": {
                        "offset": 64,
                        "bytes": wallet
                    }
                }
            ],
            "dataSlice": {
                "offset": 0,
                "length": OBLIGATION_DATA_SLICE_BYTES
            }
        });
        if let Some(slot) = min_context_slot {
            config["minContextSlot"] = serde_json::json!(slot);
        }
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getProgramAccounts",
            "params": [
                KLEND_PROGRAM_ID,
                config
            ]
        }))
        .expect("fixed Solana discovery request serializes")
    }

    fn get_json_bounded(url: &str, limit: usize) -> Result<Vec<u8>, &'static str> {
        let response = waki::Client::new()
            .get(url)
            .header("Accept", "application/json")
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECONDS))
            .send()
            .map_err(|_| "Kamino request failed")?;
        read_json_response_bounded(response, limit, "Kamino")
    }

    fn post_json_bounded(
        url: &str,
        request_body: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>, &'static str> {
        let response = waki::Client::new()
            .post(url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(request_body)
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECONDS))
            .send()
            .map_err(|_| "Solana RPC request failed")?;
        read_json_response_bounded(response, limit, "Solana RPC")
    }

    fn read_json_response_bounded(
        response: waki::Response,
        limit: usize,
        service: &'static str,
    ) -> Result<Vec<u8>, &'static str> {
        if response.status_code() != 200 {
            return Err(match service {
                "Kamino" => "Kamino returned a non-success status",
                _ => "Solana RPC returned a non-success status",
            });
        }
        if let Some(length) = response.header("content-length") {
            let value = length
                .to_str()
                .map_err(|_| "remote service returned an invalid content length")?;
            let parsed = value
                .parse::<usize>()
                .map_err(|_| "remote service returned an invalid content length")?;
            if parsed > limit {
                return Err("remote response exceeds the safety bound");
            }
        }

        let mut body = Vec::new();
        loop {
            let remaining = limit.saturating_add(1).saturating_sub(body.len());
            if remaining == 0 {
                return Err("remote response exceeds the safety bound");
            }
            let request_len = READ_CHUNK_BYTES.min(remaining as u64);
            let chunk = response
                .chunk(request_len)
                .map_err(|_| "remote response body could not be read")?;
            match chunk {
                None => break,
                Some(bytes) if bytes.is_empty() => {
                    return Err("remote service returned an invalid empty body chunk");
                }
                Some(bytes) => {
                    append_bounded(&mut body, &bytes, limit)
                        .map_err(|_| "remote response exceeds the safety bound")?;
                }
            }
        }
        if body.is_empty() {
            return Err("remote service returned an empty response");
        }
        Ok(body)
    }

    fn unix_time_ms() -> Result<u64, &'static str> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "local clock is before the Unix epoch")?;
        u64::try_from(duration.as_millis())
            .map_err(|_| "local clock is outside the supported range")
    }

    fn argument_failure(message: &str) -> ToolResult {
        emit(
            PluginAction::Fail,
            Some(PluginOutcome::Failure),
            "rejected invalid input or config",
        );
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(message.to_string()),
        }
    }

    fn success_result(report: GuardReport) -> ToolResult {
        let outcome = if report.status == crate::guard::GuardStatus::Unknown {
            None
        } else {
            Some(PluginOutcome::Success)
        };
        emit(
            PluginAction::Complete,
            outcome,
            if report.status == crate::guard::GuardStatus::Unknown {
                "completed with unknown status"
            } else {
                "completed Kamino liquidation assessment"
            },
        );
        ToolResult {
            success: true,
            output: serde_json::to_string(&report).unwrap_or_else(|_| {
                "{\"status\":\"UNKNOWN\",\"reason\":\"serialization failed\",\"obligations\":0}"
                    .to_string()
            }),
            error: None,
        }
    }

    fn unknown_result(reason: &'static str) -> ToolResult {
        success_result(GuardReport::unknown(reason))
    }

    fn emit(action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "kamino_liquidation_guard::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(KaminoLiquidationGuard);
}
