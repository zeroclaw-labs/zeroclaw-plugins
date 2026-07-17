pub mod risk;

use risk::{validate_mint, ACCOUNT_REQUEST_ID, LARGEST_ACCOUNTS_REQUEST_ID};

const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimError {
    InvalidMint,
    RequestSerialization,
    HttpStatus,
    ResponseTooLarge,
    ResponseNotUtf8,
}

#[cfg(target_family = "wasm")]
impl ShimError {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidMint => "INVALID_MINT",
            Self::RequestSerialization => "REQUEST_SERIALIZATION_ERROR",
            Self::HttpStatus => "HTTP_STATUS_ERROR",
            Self::ResponseTooLarge => "RESPONSE_TOO_LARGE",
            Self::ResponseNotUtf8 => "RESPONSE_NOT_UTF8",
        }
    }
}

pub fn rpc_request_bodies(mint: &str) -> Result<[String; 2], ShimError> {
    validate_mint(mint).map_err(|_| ShimError::InvalidMint)?;
    let account = serde_json::json!({
        "jsonrpc": "2.0",
        "id": ACCOUNT_REQUEST_ID,
        "method": "getAccountInfo",
        "params": [mint, {"encoding": "jsonParsed"}],
    });
    let largest = serde_json::json!({
        "jsonrpc": "2.0",
        "id": LARGEST_ACCOUNTS_REQUEST_ID,
        "method": "getTokenLargestAccounts",
        "params": [mint],
    });
    Ok([
        serde_json::to_string(&account).map_err(|_| ShimError::RequestSerialization)?,
        serde_json::to_string(&largest).map_err(|_| ShimError::RequestSerialization)?,
    ])
}

pub fn bounded_response_body(status: u16, body: Vec<u8>) -> Result<String, ShimError> {
    if !(200..300).contains(&status) {
        return Err(ShimError::HttpStatus);
    }
    if body.len() > MAX_RESPONSE_BODY_BYTES {
        return Err(ShimError::ResponseTooLarge);
    }
    String::from_utf8(body).map_err(|_| ShimError::ResponseNotUtf8)
}

pub fn parameters_schema() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {"mint": {"type": "string"}},
        "required": ["mint"],
        "additionalProperties": false,
    })
    .to_string()
}

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::risk::{assess, parse_execute_args, serialize_report, unknown_report, Verdict};
    use crate::{bounded_response_body, parameters_schema, rpc_request_bodies, ShimError};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = "0.1.0";
    const TOOL_NAME: &str = "token_risk_check";

    struct TokenRiskCheck;

    impl PluginInfo for TokenRiskCheck {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for TokenRiskCheck {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Assess Solana mint risk from fixed JSON-RPC evidence.".to_string()
        }

        fn parameters_schema() -> String {
            parameters_schema()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed = match parse_execute_args(&args) {
                Ok(parsed) => parsed,
                Err(error) => return Ok(unknown_result(error.code())),
            };
            let [account_request, largest_request] = match rpc_request_bodies(&parsed.mint) {
                Ok(requests) => requests,
                Err(error) => return Ok(unknown_result(error.code())),
            };
            let account_body = match post_json(&parsed.config.rpc_url, &account_request) {
                Ok(body) => body,
                Err(code) => return Ok(unknown_result(code)),
            };
            let largest_body = match post_json(&parsed.config.rpc_url, &largest_request) {
                Ok(body) => body,
                Err(code) => return Ok(unknown_result(code)),
            };

            match assess(&parsed.mint, &account_body, &largest_body) {
                Ok(report) => {
                    let verdict = verdict_code(report.verdict);
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        verdict,
                        "ASSESSMENT_COMPLETE",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serialize_report(&report),
                        error: None,
                    })
                }
                Err(error) => Ok(unknown_result(error.code())),
            }
        }
    }

    fn post_json(endpoint: &str, request: &str) -> Result<String, &'static str> {
        let response = waki::Client::new()
            .post(endpoint)
            .header("Content-Type", "application/json")
            .body(request.as_bytes().to_vec())
            .send()
            .map_err(|_| "HTTP_TRANSPORT_ERROR")?;
        let status = response.status_code();
        if !(200..300).contains(&status) {
            return Err(ShimError::HttpStatus.code());
        }
        let body = response.body().map_err(|_| "HTTP_BODY_READ_ERROR")?;
        bounded_response_body(status, body).map_err(ShimError::code)
    }

    fn unknown_result(code: &'static str) -> ToolResult {
        emit(PluginAction::Fail, PluginOutcome::Failure, "UNKNOWN", code);
        ToolResult {
            success: false,
            output: serialize_report(&unknown_report(code, code)),
            error: Some(code.to_string()),
        }
    }

    fn verdict_code(verdict: Verdict) -> &'static str {
        match verdict {
            Verdict::Red => "RED",
            Verdict::Amber => "AMBER",
            Verdict::Green => "GREEN",
            Verdict::Unknown => "UNKNOWN",
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, verdict: &str, code: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: Some(format!(r#"{{"verdict":"{verdict}","code":"{code}"}}"#)),
                message: code.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
