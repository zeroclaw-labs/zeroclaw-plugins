//! Deterministic, read-only risk analysis for SPL Governance V2 proposals.

pub mod analysis;
pub mod config;
pub mod governance;
pub mod instructions;
pub mod output;
pub mod pubkey;
pub mod rpc;

#[cfg(target_family = "wasm")]
mod component {
    use std::{collections::HashMap, time::Duration};

    use crate::{
        analysis::analyze_proposal,
        config::Config,
        pubkey::Pubkey,
        rpc::{Transport, TransportError, TransportResponse},
    };
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

    const PLUGIN_NAME: &str = "realms-proposal-firewall";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "realms_proposal_firewall";
    const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
    const HTTP_CHUNK_BYTES: u64 = 64 * 1024;

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        proposal_address: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct RealmsProposalFirewall;

    impl PluginInfo for RealmsProposalFirewall {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_owned()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_owned()
        }
    }

    impl Tool for RealmsProposalFirewall {
        fn name() -> String {
            TOOL_NAME.to_owned()
        }

        fn description() -> String {
            "Read finalized Solana accounts and deterministically inspect one SPL Governance V2 proposal for treasury outflows, authority changes, governance weakening, program upgrades, and unknown instructions. The tool is read-only and fails closed on incomplete evidence."
                .to_owned()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "proposal_address": {
                        "type": "string",
                        "description": "Base58 address of one SPL Governance V2 proposal account",
                        "minLength": 32,
                        "maxLength": 44
                    }
                },
                "required": ["proposal_address"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            if args.len() > MAX_ARGUMENT_BYTES {
                return failure("arguments exceed the size limit");
            }
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(_) => return failure("invalid arguments"),
            };
            let proposal_address: Pubkey = match parsed.proposal_address.parse() {
                Ok(value) => value,
                Err(_) => return failure("proposal_address is not a valid Solana public key"),
            };
            let config = match Config::from_section(&parsed.config) {
                Ok(value) => value,
                Err(error) => return failure(&format!("invalid operator configuration: {error}")),
            };

            match analyze_proposal(&config, proposal_address, WakiTransport) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "proposal analysis completed",
                        Some(
                            serde_json::json!({
                                "complete": report.complete,
                                "verdict": report.verdict,
                                "finding_count": report.findings.len(),
                            })
                            .to_string(),
                        ),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: report.to_json(),
                        error: None,
                    })
                }
                Err(error) => failure(&error.to_string()),
            }
        }
    }

    struct WakiTransport;

    impl Transport for WakiTransport {
        fn post(
            &self,
            url: &str,
            body: &[u8],
            max_response_bytes: usize,
        ) -> Result<TransportResponse, TransportError> {
            let response = waki::Client::new()
                .post(url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .body(body.to_vec())
                .connect_timeout(Duration::from_secs(10))
                .send()
                .map_err(|_| TransportError::Connection)?;
            let status = response.status_code();
            if status != 200 {
                return Ok(TransportResponse {
                    status,
                    body: Vec::new(),
                });
            }

            let mut response_body = Vec::new();
            loop {
                let remaining = max_response_bytes.saturating_sub(response_body.len());
                let requested = (remaining as u64).saturating_add(1).min(HTTP_CHUNK_BYTES);
                let Some(chunk) = response
                    .chunk(requested)
                    .map_err(|_| TransportError::Other)?
                else {
                    break;
                };
                if chunk.is_empty() {
                    return Err(TransportError::Other);
                }
                if chunk.len() > remaining {
                    return Err(TransportError::ResponseTooLarge);
                }
                response_body.extend_from_slice(&chunk);
            }
            Ok(TransportResponse {
                status,
                body: response_body,
            })
        }
    }

    fn failure(message: &str) -> Result<ToolResult, String> {
        emit(
            PluginAction::Fail,
            PluginOutcome::Failure,
            "proposal analysis failed",
            None,
        );
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(message.to_owned()),
        })
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, attrs: Option<String>) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "realms_proposal_firewall::tool::execute".to_owned(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_owned(),
            },
        );
    }

    export!(RealmsProposalFirewall);
}
