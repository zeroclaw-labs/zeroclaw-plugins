//! ZeroClaw WIT tool plugin: `payment_watch` (T0).

pub mod watch;

#[cfg(not(target_family = "wasm"))]
pub fn fetch_signatures_host(
    rpc_url: &str,
    reference: &str,
) -> Result<Vec<watch::ObservedSig>, String> {
    if !watch::rpc_url_allowed(rpc_url) {
        return Err("rpc_url_not_allowlisted".into());
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .build()
        .map_err(|e| format!("rpc_client: {e}"))?;
    let resp = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .body(watch::build_get_signatures_body(reference))
        .send()
        .map_err(|e| format!("rpc_http: {e}"))?;
    let status = resp.status();
    let text = resp.text().map_err(|e| format!("rpc_body: {e}"))?;
    if !status.is_success() {
        return Err(format!("rpc_http_status:{status}:{text}"));
    }
    watch::parse_signatures_rpc(&text)
}

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::watch::{
        build_get_signatures_body, detect_prompt_injection, evaluate_signatures,
        parse_signatures_rpc, rpc_url_allowed, ObservedSig, WatchInput, DEFAULT_RPC_URL,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde::Deserialize;
    use std::collections::HashMap;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct PaymentWatch;

    #[derive(Deserialize)]
    struct ExecuteArgs {
        reference: String,
        #[serde(default)]
        expected_amount: Option<String>,
        #[serde(default)]
        recipient: Option<String>,
        #[serde(default)]
        invoice_label: Option<String>,
        #[serde(default = "default_locale")]
        locale: String,
        /// Offline/tests: inject signature rows JSON array.
        #[serde(default)]
        observations_json: Option<String>,
        #[serde(default)]
        rpc_url: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    fn default_locale() -> String {
        "en".into()
    }

    impl PluginInfo for PaymentWatch {
        fn plugin_name() -> String {
            "payment-watch".into()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").into()
        }
    }

    impl Tool for PaymentWatch {
        fn name() -> String {
            "payment_watch".into()
        }
        fn description() -> String {
            "T0: watch a Solana Pay reference pubkey via getSignaturesForAddress. \
             Returns PAID/UNPAID short chat line. Closes the loop with solana-pay-request. \
             Never signs. Fail-closed on prompt injection / bad RPC."
                .into()
        }
        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "reference": { "type": "string", "description": "Solana Pay reference pubkey." },
                    "expected_amount": { "type": "string" },
                    "recipient": { "type": "string" },
                    "invoice_label": { "type": "string" },
                    "locale": { "type": "string", "default": "en" },
                    "rpc_url": { "type": "string" },
                    "observations_json": { "type": "string", "description": "Optional offline ObservedSig[] JSON." }
                },
                "required": ["reference"]
            })
            .to_string()
        }
        fn execute(args: String) -> Result<ToolResult, String> {
            if detect_prompt_injection(&args) {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Refused: adversarial instruction detected (fail-closed).".into()),
                });
            }
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };
            let input = WatchInput {
                reference: parsed.reference.clone(),
                expected_amount: parsed.expected_amount.clone(),
                recipient: parsed.recipient.clone(),
                invoice_label: parsed.invoice_label.clone(),
                locale: parsed.locale.clone(),
            };

            let sigs: Vec<ObservedSig> = if let Some(raw) = &parsed.observations_json {
                serde_json::from_str(raw).map_err(|e| format!("observations_json: {e}"))?
            } else {
                match fetch_sigs_wasm(&parsed) {
                    Ok(s) => s,
                    Err(e) => {
                        log_record(
                            LogLevel::Info,
                            &PluginEvent {
                                function_name: "payment_watch::execute".into(),
                                action: PluginAction::Fail,
                                outcome: Some(PluginOutcome::Failure),
                                duration_ms: None,
                                attrs: None,
                                message: "rpc_fail".into(),
                            },
                        );
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(e),
                        });
                    }
                }
            };

            match evaluate_signatures(&input, &sigs) {
                Ok(report) => {
                    log_record(
                        LogLevel::Info,
                        &PluginEvent {
                            function_name: "payment_watch::execute".into(),
                            action: PluginAction::Complete,
                            outcome: Some(PluginOutcome::Success),
                            duration_ms: None,
                            attrs: None,
                            message: "watched".into(),
                        },
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::to_string(&report).unwrap_or(report.summary),
                        error: None,
                    })
                }
                Err(e) => Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(e),
                }),
            }
        }
    }

    fn fetch_sigs_wasm(parsed: &ExecuteArgs) -> Result<Vec<ObservedSig>, String> {
        let rpc_url = parsed
            .rpc_url
            .clone()
            .or_else(|| parsed.config.get("rpc_url").cloned())
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        if !rpc_url_allowed(&rpc_url) {
            return Err("rpc_url_not_allowlisted".into());
        }
        let body: serde_json::Value =
            serde_json::from_str(&build_get_signatures_body(&parsed.reference))
                .map_err(|e| format!("rpc_body_json: {e}"))?;
        let resp = waki::Client::new()
            .post(&rpc_url)
            .header("Content-Type", "application/json")
            .connect_timeout(std::time::Duration::from_secs(8))
            .json(&body)
            .send()
            .map_err(|e| format!("rpc_http: {e}"))?;
        let status = resp.status_code();
        let text = resp
            .body()
            .map_err(|e| format!("rpc_read: {e}"))
            .and_then(|b| String::from_utf8(b).map_err(|e| format!("rpc_utf8: {e}")))?;
        if status >= 400 {
            return Err(format!("rpc_http_status:{status}:{text}"));
        }
        parse_signatures_rpc(&text)
    }

    export!(PaymentWatch);
}
