//! ZeroClaw `solana_pay_verify` read-only tool component.

pub mod verify;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use serde_json::Value;

    use crate::verify::{
        output, parse_signatures, prepare, signatures_request, transaction_request,
        verify_transaction, VerifyArgs,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const MAX_RPC_RESPONSE_BYTES: usize = 1024 * 1024;

    struct SolanaPayVerify;

    impl PluginInfo for SolanaPayVerify {
        fn plugin_name() -> String {
            "solana-pay-verify".to_string()
        }

        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").to_string()
        }
    }

    impl Tool for SolanaPayVerify {
        fn name() -> String {
            "solana_pay_verify".to_string()
        }

        fn description() -> String {
            "Verify whether a Solana Pay invoice is paid using bounded, read-only RPC calls. \
             A match requires the reference, successful confirmation, recipient balance delta, \
             exact asset, minimum amount, and optional memo to agree. Never signs or moves funds."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "reference": { "type": "string", "description": "Invoice reference public key." },
                    "recipient": { "type": "string", "description": "Expected recipient public key." },
                    "amount": { "type": "string", "description": "Minimum expected plain decimal amount." },
                    "spl_token": { "type": "string", "description": "Expected SPL mint. Omit for SOL." },
                    "memo": { "type": "string", "description": "Optional exact memo to require." }
                },
                "required": ["reference", "recipient", "amount"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            match execute_inner(&args) {
                Ok(result) => {
                    let paid = result.status == "paid";
                    emit(
                        if paid {
                            PluginAction::Complete
                        } else {
                            PluginAction::Query
                        },
                        PluginOutcome::Success,
                        if paid {
                            "invoice settlement verified"
                        } else {
                            "invoice still pending"
                        },
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::to_string(&result)
                            .map_err(|error| format!("serialize output: {error}"))?,
                        error: None,
                    })
                }
                Err(error) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "verification failed closed",
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(error),
                    })
                }
            }
        }
    }

    fn execute_inner(args: &str) -> Result<crate::verify::VerifyOutput, String> {
        let prepared = prepare(
            serde_json::from_str::<VerifyArgs>(args)
                .map_err(|error| format!("invalid arguments: {error}"))?,
        )?;
        let signatures_json = post_json(&prepared.rpc_url, &signatures_request(&prepared))?;
        let signatures = parse_signatures(&signatures_json, prepared.max_signatures)?;
        let scanned = signatures.len();
        for signature in signatures {
            let transaction_json = post_json(
                &prepared.rpc_url,
                &transaction_request(&prepared, &signature),
            )?;
            if let Some(payment) = verify_transaction(&transaction_json, &signature, &prepared)? {
                return Ok(output(&prepared, Some(payment), scanned));
            }
        }
        Ok(output(&prepared, None, scanned))
    }

    fn post_json(url: &str, body: &Value) -> Result<Value, String> {
        let response = waki::Client::new()
            .post(url)
            .json(body)
            .send()
            .map_err(|_| "RPC transport failed (endpoint details suppressed)".to_string())?;
        let status = response.status_code();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk(64 * 1024)
            .map_err(|error| format!("RPC body read failed: {error}"))?
        {
            if chunk.is_empty() {
                break;
            }
            if bytes.len().saturating_add(chunk.len()) > MAX_RPC_RESPONSE_BYTES {
                return Err("RPC response exceeded the 1 MiB safety limit".to_string());
            }
            bytes.extend_from_slice(&chunk);
        }
        if !(200..300).contains(&status) {
            return Err(format!("RPC returned HTTP status {status}"));
        }
        serde_json::from_slice::<Value>(&bytes)
            .map_err(|error| format!("RPC returned invalid JSON: {error}"))
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_pay_verify::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: Some("{\"custody_tier\":\"T0\",\"signs\":false}".to_string()),
                message: message.to_string(),
            },
        );
    }

    export!(SolanaPayVerify);
}
